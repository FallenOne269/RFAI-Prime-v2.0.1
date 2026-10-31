import { createServer } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import type { Server } from "node:http";
import { loadConfig } from "../src/config.ts";
import { createApp, type AppOptions } from "../src/app.ts";
import { hashPasscodeSync } from "../src/crypto.ts";

export const PASS = "correct horse battery staple";
export const PASS_HASH = hashPasscodeSync(PASS, 1 << 14);
export const SECRET_HEX = randomBytes(32).toString("hex");
export const REDIRECT = "http://127.0.0.1:9/callback";

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as any).port;
      s.close(() => resolve(p));
    });
  });
}

export interface Started {
  base: string;
  resource: string;
  logs: string[];
  close: () => Promise<void>;
  ctx: ReturnType<typeof createApp>;
}

export async function start(env: Record<string, string> = {}, opts: AppOptions = {}): Promise<Started> {
  const port = await freePort();
  const base = `http://localhost:${port}`;
  const config = loadConfig({
    RFAI_MCP_PUBLIC_URL: base,
    RFAI_MCP_SECRET: SECRET_HEX,
    RFAI_MCP_OWNER_PASSCODE_HASH: PASS_HASH,
    RFAI_MCP_TRUST_PROXY_HOPS: "0",
    ...env,
  });
  const logs: string[] = [];
  const ctx = createApp(config, { log: (l) => logs.push(l), ...opts });
  const server: Server = await new Promise((resolve) => {
    const s = ctx.app.listen(port, "127.0.0.1", () => resolve(s));
  });
  return {
    base,
    resource: `${base}/mcp`,
    logs,
    ctx,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export async function register(base: string, meta: Record<string, unknown> = {}) {
  const r = await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Test client", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], ...meta }),
  });
  return { status: r.status, body: (await r.json()) as any };
}

export interface AuthzOpts {
  scope?: string;
  resource?: string;
  state?: string;
  passcode?: string;
  action?: "approve" | "deny";
  challenge?: string;
  redirect?: string;
  ip?: string;
}

export async function openConsent(base: string, clientId: string, o: AuthzOpts = {}) {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: o.redirect ?? REDIRECT,
    code_challenge: o.challenge ?? pkce().challenge,
    code_challenge_method: "S256",
    state: o.state ?? "st-123",
  });
  if (o.scope !== undefined) q.set("scope", o.scope);
  if (o.resource !== undefined) q.set("resource", o.resource);
  const r = await fetch(`${base}/authorize?${q}`, { redirect: "manual" });
  const html = await r.text();
  const m = html.match(/name="request" value="([^"]+)"/);
  return { status: r.status, html, headers: r.headers, location: r.headers.get("location"), request: m ? m[1].replace(/&amp;/g, "&") : null };
}

export async function submitConsent(base: string, request: string, passcode: string, action = "approve") {
  const r = await fetch(`${base}/oauth/consent`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request, passcode, action }),
  });
  const location = r.headers.get("location");
  const url = location ? new URL(location) : null;
  return { status: r.status, text: await r.text(), location, code: url?.searchParams.get("code") ?? null, url };
}

export async function getCode(base: string, clientId: string, o: AuthzOpts = {}) {
  const c = await openConsent(base, clientId, o);
  if (!c.request) throw new Error(`no consent form (status ${c.status}, location ${c.location})`);
  return submitConsent(base, c.request, o.passcode ?? PASS, o.action ?? "approve");
}

export async function token(base: string, params: Record<string, string>, headers: Record<string, string> = {}) {
  const r = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(params),
  });
  return { status: r.status, body: (await r.json()) as any };
}

/** Full owner sign-in for a fresh public client; returns tokens. */
export async function signIn(base: string, scope?: string) {
  const reg = await register(base);
  const p = pkce();
  const c = await getCode(base, reg.body.client_id, { challenge: p.challenge, scope });
  const t = await token(base, { grant_type: "authorization_code", code: c.code!, code_verifier: p.verifier, client_id: reg.body.client_id, redirect_uri: REDIRECT });
  if (t.status !== 200) throw new Error(`token exchange failed: ${JSON.stringify(t.body)}`);
  return { clientId: reg.body.client_id as string, ...t.body } as { clientId: string; access_token: string; refresh_token: string; scope: string };
}

let rpcId = 1;
export async function rpc(resource: string, accessToken: string | null, method: string, params: unknown = {}, extraHeaders: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": "2025-06-18",
    ...extraHeaders,
  };
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  const r = await fetch(resource, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }) });
  const text = await r.text();
  let body: any = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: r.status, body, headers: r.headers };
}

// ---- mock model gateway (same reply shapes as x402 tests) ----------------------
export const gateway = { calls: 0, mode: "ok" as "ok" | "fail" };
const realFetch = globalThis.fetch;
export function installGatewayMock() {
  globalThis.fetch = (async (url: any, init: any) => {
    const u = String(url instanceof Request ? url.url : url);
    if (!u.startsWith("https://llm.bankr.bot/")) return realFetch(url, init);
    gateway.calls++;
    if (gateway.mode === "fail") return new Response('{"error":"upstream secret detail"}', { status: 500 });
    const body = JSON.parse(init.body);
    const p: string = body.messages[0].content;
    let text = "Final answer.";
    if (p.includes("Architect in")) text = '{"summary":"S","approach":"A","concerns":["c1"]}\n---DRAFT---\nDraft answer.';
    else if (p.includes("Critic in")) text = '{"perspective":"x","score":9,"feedback":"good","suggestions":["s"]}';
    return Response.json({ content: [{ type: "text", text }] });
  }) as any;
}
export function removeGatewayMock() {
  globalThis.fetch = realFetch;
}
