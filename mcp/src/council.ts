// Council backends.
//
// embedded: runs the exact governed handler from x402/rfai-council/index.ts (synced into
//           council.generated.ts) in this process. Same policy screen, same signed-grant check,
//           same output check. Needs RFAI_LLM_KEY on this server for model calls. No x402 payment.
// x402:     forwards to the paid Bankr endpoint WITHOUT a payment. It never signs or sends an
//           X-PAYMENT header, so it can only report the price (HTTP 402) or relay what the
//           endpoint says. This server never spends from your wallet.
import councilHandler, {
  inputScreen,
  governanceHeader,
  loadTrustStore,
  ENDPOINT_VERSION,
  POLICY,
  COUNCIL_SOURCE_SHA256,
  MAX_TASK_CHARS,
  MAX_GRANTS,
  MAX_JOB_ID_CHARS,
} from "./council.generated.ts";

export { ENDPOINT_VERSION, POLICY, COUNCIL_SOURCE_SHA256, MAX_TASK_CHARS, MAX_GRANTS, MAX_JOB_ID_CHARS };

export interface CouncilRequest {
  task: string;
  protocol?: string;
  context?: Record<string, unknown>;
}

export type CouncilOutcome =
  | { kind: "ok"; status: number; body: any }
  | { kind: "refused"; status: number; body: any }
  | { kind: "payment_required"; status: 402; payment: PaymentSummary }
  | { kind: "error"; status: number; message: string; body?: any };

export interface PaymentSummary {
  x402Version: number | null;
  options: { scheme?: string; network?: string; amount?: string; asset?: string; payTo?: string; description?: string }[];
}

export interface CouncilBackend {
  readonly name: "embedded" | "x402";
  ask(req: CouncilRequest, signal?: AbortSignal): Promise<CouncilOutcome>;
}

function classify(status: number, body: any): CouncilOutcome {
  if (status === 200 && body && typeof body === "object") return { kind: "ok", status, body };
  if ((status === 403 || status === 422) && body && typeof body === "object") return { kind: "refused", status, body };
  const msg = body && typeof body.error === "string" ? body.error.slice(0, 300) : `council returned HTTP ${status}`;
  return { kind: "error", status, message: msg, body: body && typeof body === "object" ? body : undefined };
}

export class EmbeddedBackend implements CouncilBackend {
  readonly name = "embedded" as const;
  async ask(req: CouncilRequest): Promise<CouncilOutcome> {
    const r = await councilHandler(
      new Request("http://embedded.invalid/rfai-council", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      }),
    );
    let body: any = null;
    try {
      body = await r.json();
    } catch {
      body = null;
    }
    return classify(r.status, body);
  }
}

const MAX_UPSTREAM_BYTES = 256 * 1024;

async function readCapped(r: Response): Promise<string> {
  const reader = r.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_UPSTREAM_BYTES) {
      await reader.cancel();
      throw new Error("upstream response too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function str(x: unknown, max = 200): string | undefined {
  return typeof x === "string" ? x.slice(0, max) : typeof x === "number" ? String(x) : undefined;
}

export function summarisePayment(headerValue: string | null, body: any): PaymentSummary {
  let doc: any = body;
  if (headerValue) {
    try {
      doc = JSON.parse(Buffer.from(headerValue, "base64").toString("utf8"));
    } catch {
      /* fall back to the body */
    }
  }
  const accepts = Array.isArray(doc?.accepts) ? doc.accepts.slice(0, 5) : [];
  return {
    x402Version: typeof doc?.x402Version === "number" ? doc.x402Version : null,
    options: accepts.map((a: any) => ({
      scheme: str(a?.scheme),
      network: str(a?.network),
      amount: str(a?.maxAmountRequired ?? a?.amount),
      asset: str(a?.extra?.name ?? a?.asset),
      payTo: str(a?.payTo),
      description: str(a?.description),
    })),
  };
}

export class X402QuoteBackend implements CouncilBackend {
  readonly name = "x402" as const;
  private url: string;
  private fetchImpl: typeof fetch;
  private timeoutMs: number;
  constructor(url: string, fetchImpl: typeof fetch = fetch, timeoutMs = 45_000) {
    this.url = url;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async ask(req: CouncilRequest, signal?: AbortSignal): Promise<CouncilOutcome> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    let r: Response;
    try {
      r = await this.fetchImpl(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(req),
        redirect: "error",
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
    } catch (e) {
      const name = (e as Error)?.name;
      return { kind: "error", status: 504, message: name === "TimeoutError" || name === "AbortError" ? "the paid council endpoint did not answer in time" : "could not reach the paid council endpoint" };
    }
    let text = "";
    try {
      text = await readCapped(r);
    } catch {
      return { kind: "error", status: 502, message: "the paid council endpoint sent an oversized reply" };
    }
    let body: any = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    if (r.status === 402) {
      return { kind: "payment_required", status: 402, payment: summarisePayment(r.headers.get("payment-required"), body) };
    }
    if (body === null && r.status === 200) return { kind: "error", status: 502, message: "the paid council endpoint sent a reply that is not JSON" };
    return classify(r.status, body);
  }
}

/** Free, local, no model call: what the governance input screen decides for this request. */
export async function screenOnly(req: CouncilRequest) {
  const trust = await loadTrustStore(process.env.RFAI_TRUSTED_SIGNERS);
  const screen = await inputScreen(req.task.trim(), (req.context ?? {}) as any, trust, Math.floor(Date.now() / 1000));
  return {
    ...(await governanceHeader()),
    input: { ...screen.result },
    audit: screen.audit,
    trust_store: trust.status,
  };
}

export function modelKeyConfigured(): boolean {
  return !!process.env.RFAI_LLM_KEY;
}
