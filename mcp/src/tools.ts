// The MCP tools. Three tools:
//   council_info   (council:read) what this server runs and what it is missing. No network.
//   council_screen (council:read) the governance input screen only. Free, local, no model call.
//   council_ask    (council:run)  the full governed council through the configured backend.
// The OAuth identity is used for access and rate limits only. Nothing from it is passed to the
// council: the context the caller sends is passed as-is, and caller-claimed flags stay claims.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  COUNCIL_SOURCE_SHA256,
  ENDPOINT_VERSION,
  MAX_GRANTS,
  MAX_JOB_ID_CHARS,
  MAX_TASK_CHARS,
  POLICY,
  modelKeyConfigured,
  screenOnly,
  type CouncilBackend,
  type CouncilOutcome,
} from "./council.ts";
import { SCOPE_READ, SCOPE_RUN } from "./oauth.ts";

export const SERVER_VERSION = "1.0.0";

const contextSchema = z
  .object({
    job_id: z.string().max(MAX_JOB_ID_CHARS).optional().describe("Job ID that signed grants are scoped to."),
    domain: z.string().max(64).optional().describe("Declared domain. A high-impact domain only adds strictness."),
    capabilities: z.array(z.string().max(64)).max(16).optional().describe("Declared capabilities, e.g. human_review."),
    flags: z
      .array(z.string().max(64))
      .max(16)
      .optional()
      .describe("Claimed flags. Recorded and ignored unless a valid signed grant carries them."),
    grants: z
      .array(z.record(z.string(), z.unknown()))
      .max(MAX_GRANTS)
      .optional()
      .describe("Signed permission grants (Ed25519) from a trusted signer configured on the server."),
  })
  .strict();

const askShape = {
  task: z.string().trim().min(1).max(MAX_TASK_CHARS).describe("The question or task for the council."),
  protocol: z.enum(["plan", "execute"]).default("plan").describe("plan (default) or execute."),
  context: contextSchema.optional(),
};

export class RunLimiter {
  private runs = new Map<string, number[]>();
  private active = 0;
  private perHour: number;
  private maxConcurrent: number;
  constructor(perHour: number, maxConcurrent: number) {
    this.perHour = perHour;
    this.maxConcurrent = maxConcurrent;
  }
  tryStart(key: string, now = Date.now()): "ok" | "rate" | "busy" {
    const list = (this.runs.get(key) ?? []).filter((t) => now - t < 3600_000);
    if (list.length >= this.perHour) {
      this.runs.set(key, list);
      return "rate";
    }
    if (this.active >= this.maxConcurrent) return "busy";
    list.push(now);
    this.runs.set(key, list);
    this.active += 1;
    return "ok";
  }
  finish() {
    this.active = Math.max(0, this.active - 1);
  }
}

function textResult(text: string, structured?: Record<string, unknown>, isError = false): CallToolResult {
  const out: CallToolResult = { content: [{ type: "text", text }] };
  if (structured) out.structuredContent = structured;
  if (isError) out.isError = true;
  return out;
}

function govSummary(gov: any): string {
  const input = gov?.input;
  if (!input) return "";
  const codes = Array.isArray(input.reason_codes) && input.reason_codes.length ? input.reason_codes.join(", ") : "none";
  const ignored = gov?.audit?.ignored_claimed_flags;
  let s = `Governance input screen: ${input.decision} (risk ${input.risk}; reasons: ${codes}).`;
  if (Array.isArray(ignored) && ignored.length) s += ` Claimed flags ignored without a valid signed grant: ${ignored.join(", ")}.`;
  return s;
}

export function outcomeToResult(o: CouncilOutcome): CallToolResult {
  switch (o.kind) {
    case "ok": {
      const b = o.body;
      const text = typeof b.final_text === "string" ? b.final_text : JSON.stringify(b).slice(0, 4000);
      const avg = b.trace?.average_critic_score;
      const score = typeof avg === "number" ? `\n\nAverage critic score: ${avg}/10.` : "";
      const out = b.governance?.output?.decision ? ` Output check: ${b.governance.output.decision}.` : "";
      return textResult(`${text}${score}\n${govSummary(b.governance)}${out}`.trim(), b);
    }
    case "refused":
      return textResult(`${o.body.error ?? "Refused by the RFAI governance screen."}\n${govSummary(o.body.governance)}`.trim(), o.body, true);
    case "payment_required": {
      const opts = o.payment.options
        .map((p) => `${p.amount ?? "?"} (${p.asset ?? "unknown asset"}) on ${p.network ?? "unknown network"}${p.payTo ? ` to ${p.payTo}` : ""}`)
        .join("; ");
      return textResult(
        `The paid council endpoint requires an x402 payment: ${opts || "no payment options listed"}. Not paid: this MCP server never pays from your wallet. Use the embedded backend with your own model key, or pay the endpoint directly with an x402 client.`,
        { payment_required: o.payment },
        true,
      );
    }
    default: {
      let hint = "";
      if (/gateway not configured/i.test(o.message)) hint = " The server has no model key: set RFAI_LLM_KEY on the MCP server.";
      else if (/credit|insufficient|402/i.test(o.message)) hint = " The model gateway may be out of credits.";
      return textResult(`The council could not finish: ${o.message}.${hint}`, o.body ? { error: o.message, ...o.body } : { error: o.message }, true);
    }
  }
}

export interface ToolDeps {
  backend: CouncilBackend;
  limiter: RunLimiter;
  x402Url: string;
}

export function createMcpServer(deps: ToolDeps): McpServer {
  const server = new McpServer(
    { name: "rfai-council", version: SERVER_VERSION },
    {
      instructions:
        "Tools for the owner's RFAI council. council_screen is free and runs only the governance screen. council_ask runs the full governed council and may use model credits. Signing in never grants governance exceptions: only grants signed by a trusted signer configured on the server can, and none may be configured.",
    },
  );

  server.registerTool(
    "council_info",
    {
      title: "RFAI council info",
      description: "What this server runs: council version, governance policy and hash, backend, and whether a model key and trusted signers are configured. Free, no model call.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
    },
    async () => {
      const screen = await screenOnly({ task: "info" });
      const info = {
        server_version: SERVER_VERSION,
        council_endpoint_version: ENDPOINT_VERSION,
        council_source_sha256: COUNCIL_SOURCE_SHA256,
        policy_id: POLICY.policy_id,
        policy_version: POLICY.version,
        policy_sha256: (screen as any).policy_sha256,
        backend: deps.backend.name,
        model_key_configured: deps.backend.name === "embedded" ? modelKeyConfigured() : null,
        trusted_signers: screen.trust_store,
        paid_endpoint: deps.x402Url,
        pays_x402_automatically: false,
      };
      const lines = [
        `RFAI council ${ENDPOINT_VERSION} behind MCP server ${SERVER_VERSION}, policy ${info.policy_id} v${info.policy_version}.`,
        deps.backend.name === "embedded"
          ? `Backend: embedded governed council. Model key ${info.model_key_configured ? "is" : "is NOT"} configured.`
          : `Backend: the paid x402 endpoint, quote only. This server never pays.`,
        `Trusted signers: ${info.trusted_signers}.`,
      ];
      return textResult(lines.join("\n"), info);
    },
  );

  server.registerTool(
    "council_screen",
    {
      title: "Screen a request with RFAI governance",
      description:
        "Run only the RFAI governance input screen on a task: allow, review or deny, with reasons and the audit trail. Free and local: no model call, nothing is charged. Claimed flags are reported and ignored unless a valid signed grant carries them.",
      inputSchema: askShape,
      annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
    },
    async ({ task, context }) => {
      const r = await screenOnly({ task, context });
      return textResult(govSummary(r), r);
    },
  );

  server.registerTool(
    "council_ask",
    {
      title: "Ask the RFAI council",
      description:
        "Send a task to the governed RFAI council (architect, critic, integrator). The governance screen runs first; refused or withheld requests stop before any model call. Allowed requests use model credits. Requires the council:run scope.",
      inputSchema: askShape,
      annotations: { readOnlyHint: false, openWorldHint: true, destructiveHint: false, idempotentHint: false },
    },
    async ({ task, protocol, context }, extra) => {
      const scopes = extra.authInfo?.scopes ?? [];
      if (!scopes.includes(SCOPE_RUN)) {
        return textResult("This sign-in does not include the council:run permission.", undefined, true);
      }
      const key = extra.authInfo?.clientId ?? "unknown";
      const gate = deps.limiter.tryStart(key);
      if (gate === "rate") return textResult("Run limit reached for this hour. Try again later.", undefined, true);
      if (gate === "busy") return textResult("The council is busy with other runs. Try again in a minute.", undefined, true);
      try {
        return outcomeToResult(await deps.backend.ask({ task, protocol, context }, extra.signal));
      } catch {
        return textResult("The council could not finish because of an internal error.", undefined, true);
      } finally {
        deps.limiter.finish();
      }
    },
  );

  return server;
}

export { SCOPE_READ };
