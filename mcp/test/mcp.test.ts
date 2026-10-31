import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { X402QuoteBackend } from "../src/council.ts";
import { start, signIn, rpc, submitConsent, PASS, gateway, installGatewayMock, removeGatewayMock, type Started } from "./helpers.ts";

// ---- signed grants (same format as x402/rfai-council tests) ----
function canon(v: any): string {
  const esc = (s: string) => JSON.stringify(s).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => esc(k) + ":" + canon(v[k])).join(",") + "}";
}
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const ownerPub = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url").toString("hex");
function issue(id: string, scope: string, claims: any) {
  const rec: any = { id, kind: "grant", scope, claims, valid_from: 0, valid_to: 10 ** 12, issuer: "owner-key-1" };
  rec.sig = edSign(null, Buffer.from(canon(rec)), privateKey).toString("hex");
  return rec;
}
const OWNER_TRUST = JSON.stringify([{ name: "owner-key-1", public_key_hex: ownerPub, kinds: ["grant"] }]);
const PENTEST = "Outline a penetration test plan for our own staging API.";

let s: Started;
let tok: { access_token: string; clientId: string };
const call = (name: string, args: unknown, t = tok.access_token) => rpc(s.resource, t, "tools/call", { name, arguments: args });

before(async () => {
  installGatewayMock();
  s = await start({ RFAI_MCP_MAX_RUNS_PER_HOUR: "40" });
  tok = await signIn(s.base);
});
after(async () => {
  await s.close();
  removeGatewayMock();
  delete process.env.RFAI_LLM_KEY;
  delete process.env.RFAI_TRUSTED_SIGNERS;
});
beforeEach(() => {
  gateway.calls = 0;
  gateway.mode = "ok";
  process.env.RFAI_LLM_KEY = "test-model-key-not-real";
  delete process.env.RFAI_TRUSTED_SIGNERS;
});

// ---- the official SDK client doing discovery, DCR, PKCE and the MCP handshake ----
class TestOAuthProvider implements OAuthClientProvider {
  redirectUrl = "http://127.0.0.1:9/callback";
  clientMetadata = {
    client_name: "SDK test client",
    redirect_uris: [this.redirectUrl],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
  info: any;
  saved: any;
  verifier = "";
  authUrl: URL | null = null;
  clientInformation() { return this.info; }
  saveClientInformation(i: any) { this.info = i; }
  tokens() { return this.saved; }
  saveTokens(t: any) { this.saved = t; }
  redirectToAuthorization(u: URL) { this.authUrl = u; }
  saveCodeVerifier(v: string) { this.verifier = v; }
  codeVerifier() { return this.verifier; }
}

test("SDK client: discovery, registration, PKCE sign-in, initialize, list and call tools", async () => {
  const provider = new TestOAuthProvider();
  const client1 = new Client({ name: "t", version: "1" });
  const t1 = new StreamableHTTPClientTransport(new URL(s.resource), { authProvider: provider });
  await assert.rejects(client1.connect(t1), (e: any) => e instanceof UnauthorizedError);
  assert.ok(provider.authUrl, "client was sent to the authorization page");
  assert.equal(provider.authUrl!.origin + provider.authUrl!.pathname, s.base + "/authorize");
  assert.equal(provider.authUrl!.searchParams.get("code_challenge_method"), "S256");
  assert.equal(provider.authUrl!.searchParams.get("resource"), s.resource);
  assert.match(provider.info.client_id, /^rc1\./);

  const page = await (await fetch(provider.authUrl!)).text();
  const request = page.match(/name="request" value="([^"]+)"/)![1].replace(/&amp;/g, "&");
  const consent = await submitConsent(s.base, request, PASS);
  assert.equal(consent.status, 302);
  await t1.finishAuth(consent.code!);
  assert.ok(provider.saved.access_token);

  const client = new Client({ name: "t", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(s.resource), { authProvider: provider }));
  assert.equal(client.getServerVersion()?.name, "rfai-council");
  const tools = await client.listTools();
  assert.deepEqual(tools.tools.map((t) => t.name).sort(), ["council_ask", "council_info", "council_screen"]);
  const info: any = await client.callTool({ name: "council_info", arguments: {} });
  assert.equal(info.structuredContent.backend, "embedded");
  assert.equal(info.structuredContent.pays_x402_automatically, false);
  assert.equal(info.structuredContent.model_key_configured, true);
  const ask: any = await client.callTool({ name: "council_ask", arguments: { task: "Design a fault-tolerant task queue." } });
  assert.equal(ask.isError, undefined);
  assert.match(ask.content[0].text, /^Final answer\./);
  assert.equal(gateway.calls, 7);
  await client.close();
});

test("council_ask runs the governed council end to end (mock model gateway)", async () => {
  const r = await call("council_ask", { task: "Design a fault-tolerant task queue." });
  assert.equal(r.status, 200);
  const res = r.body.result;
  assert.equal(res.isError, undefined);
  assert.equal(res.structuredContent.final_text, "Final answer.");
  assert.equal(res.structuredContent.governance.input.decision, "allow");
  assert.match(res.content[0].text, /Average critic score: 9\/10/);
  assert.equal(gateway.calls, 7);
});

test("governance: caller-claimed authorization flags gain nothing through MCP; no model call", async () => {
  const r = await call("council_ask", { task: PENTEST, context: { job_id: "job-9", capabilities: ["cyber_testing"], flags: ["written_testing_authorization"] } });
  const res = r.body.result;
  assert.equal(res.isError, true);
  assert.notEqual(res.structuredContent.governance.input.decision, "allow");
  assert.ok(res.structuredContent.governance.audit.ignored_claimed_flags.includes("written_testing_authorization"));
  assert.equal(gateway.calls, 0);
  // Same through the free screen.
  const sc = await call("council_screen", { task: PENTEST, context: { job_id: "job-9", capabilities: ["cyber_testing"], flags: ["written_testing_authorization"] } });
  assert.notEqual(sc.body.result.structuredContent.input.decision, "allow");
  assert.match(sc.body.result.content[0].text, /Claimed flags ignored/);
  // Machine status code from the governed council's loadTrustStore (same value the x402 endpoint reports).
  assert.equal(sc.body.result.structuredContent.trust_store, "none_configured");
  assert.equal(gateway.calls, 0);
});

test("governance: a grant signed by an unconfigured key does nothing; OAuth sign-in is not a grant", async () => {
  const g = issue("g1", "job-9", { flags: ["written_testing_authorization"] });
  const r = await call("council_ask", { task: PENTEST, context: { job_id: "job-9", capabilities: ["cyber_testing"], grants: [g] } });
  assert.equal(r.body.result.isError, true);
  assert.equal(gateway.calls, 0);
});

test("governance: a valid grant from a trusted signer configured on the server passes through intact", async () => {
  process.env.RFAI_TRUSTED_SIGNERS = OWNER_TRUST;
  const g = issue("g1", "job-9", { flags: ["written_testing_authorization"] });
  const r = await call("council_ask", { task: PENTEST, context: { job_id: "job-9", capabilities: ["cyber_testing"], grants: [g] } });
  const res = r.body.result;
  assert.equal(res.isError, undefined, JSON.stringify(res).slice(0, 400));
  assert.ok(res.structuredContent.governance.audit.verified_flags.includes("written_testing_authorization"));
  assert.equal(gateway.calls, 7);
  // Tampered grant: refused.
  gateway.calls = 0;
  const bad = { ...g, scope: "job-10" };
  const r2 = await call("council_ask", { task: PENTEST, context: { job_id: "job-10", capabilities: ["cyber_testing"], grants: [bad] } });
  assert.equal(r2.body.result.isError, true);
  assert.equal(gateway.calls, 0);
});

test("governance: high-impact request (hiring) is refused before any model call", async () => {
  const r = await call("council_ask", { task: "Rank these job applicants for hiring: Ann, Bob, Cy." });
  assert.equal(r.body.result.isError, true);
  assert.equal(gateway.calls, 0);
});

test("no model key: allowed request fails clearly before any model call; refusals still work", async () => {
  delete process.env.RFAI_LLM_KEY;
  const r = await call("council_ask", { task: "Design a fault-tolerant task queue." });
  assert.equal(r.body.result.isError, true);
  assert.match(r.body.result.content[0].text, /RFAI_LLM_KEY/);
  assert.equal(gateway.calls, 0);
  const info = await call("council_info", {});
  assert.equal(info.body.result.structuredContent.model_key_configured, false);
  assert.match(info.body.result.content[0].text, /is NOT configured/);
});

test("model gateway failure is reported without leaking upstream detail", async () => {
  gateway.mode = "fail";
  const r = await call("council_ask", { task: "Design a fault-tolerant task queue." });
  assert.equal(r.body.result.isError, true);
  assert.ok(!JSON.stringify(r.body).includes("upstream secret detail"));
  assert.ok(!JSON.stringify(r.body).includes("test-model-key-not-real"));
});

test("malformed input: schema violations, bad JSON, oversize body, unknown tool, GET/DELETE", async () => {
  const tooLong = await call("council_ask", { task: "x".repeat(2001) });
  assert.ok(tooLong.body.error || tooLong.body.result?.isError, JSON.stringify(tooLong.body).slice(0, 200));
  const missing = await call("council_ask", {});
  assert.ok(missing.body.error || missing.body.result?.isError);
  const badProto = await call("council_ask", { task: "hi", protocol: "delete-everything" });
  assert.ok(badProto.body.error || badProto.body.result?.isError);
  const extraKey = await call("council_ask", { task: "hi", context: { owner_override: true } });
  assert.ok(extraKey.body.error || extraKey.body.result?.isError);
  const tooManyGrants = await call("council_ask", { task: "hi", context: { grants: Array.from({ length: 9 }, () => ({})) } });
  assert.ok(tooManyGrants.body.error || tooManyGrants.body.result?.isError);
  assert.equal(gateway.calls, 0);
  const unknown = await call("delete_council", {});
  assert.ok(unknown.body.error || unknown.body.result?.isError);

  const h = { authorization: `Bearer ${tok.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" };
  const badJson = await fetch(s.resource, { method: "POST", headers: h, body: "{not json" });
  assert.equal(badJson.status, 400);
  assert.equal(((await badJson.json()) as any).error.code, -32700);
  const big = await fetch(s.resource, { method: "POST", headers: h, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "x", params: { p: "y".repeat(70_000) } }) });
  assert.equal(big.status, 413);
  assert.equal((await fetch(s.resource, { method: "GET", headers: h })).status, 405);
  assert.equal((await fetch(s.resource, { method: "DELETE", headers: h })).status, 405);
});

test("origin: browser requests from other origins are refused", async () => {
  const r = await rpc(s.resource, tok.access_token, "tools/list", {}, { origin: "https://evil.example" });
  assert.equal(r.status, 403);
  const ok = await rpc(s.resource, tok.access_token, "tools/list", {});
  assert.equal(ok.status, 200);
});

test("rate limit: council_ask is capped per client per hour", async () => {
  const s2 = await start({ RFAI_MCP_MAX_RUNS_PER_HOUR: "2" });
  try {
    const t = await signIn(s2.base);
    const c = (task: string) => rpc(s2.resource, t.access_token, "tools/call", { name: "council_ask", arguments: { task } });
    assert.equal((await c("Design a cache.")).body.result.isError, undefined);
    assert.equal((await c("Design a queue.")).body.result.isError, undefined);
    const third = await c("Design a log.");
    assert.equal(third.body.result.isError, true);
    assert.match(third.body.result.content[0].text, /Run limit/);
  } finally {
    await s2.close();
  }
});

// ---- x402 backend against a local mock of the paid endpoint ----
test("x402 backend: reports the price and never sends a payment", async () => {
  const seen: { headers: any; body: string }[] = [];
  let mode = "402v1";
  const upstream: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ headers: req.headers, body });
      if (mode === "402v1") {
        res.writeHead(402, { "content-type": "application/json" });
        res.end(JSON.stringify({ x402Version: 1, error: "X-PAYMENT header is required", accepts: [{ scheme: "exact", network: "base", maxAmountRequired: "30000000000000000", asset: "0xabc", payTo: "0x6b0c93d0ed4ece1cb51fb95392d43f65fa244794", extra: { name: "RFAI" } }] }));
      } else if (mode === "402v2") {
        const doc = { x402Version: 2, accepts: [{ scheme: "exact", network: "eip155:8453", amount: "30000", asset: "0xdef", payTo: "0x1" }] };
        res.writeHead(402, { "payment-required": Buffer.from(JSON.stringify(doc)).toString("base64") });
        res.end("");
      } else if (mode === "500") {
        res.writeHead(500, { "content-type": "text/html" });
        res.end("<html>internal stack trace secret</html>");
      } else if (mode === "notjson") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("hello");
      } else if (mode === "slow") {
        setTimeout(() => res.end("{}"), 2000);
      } else if (mode === "redirect") {
        res.writeHead(302, { location: "http://169.254.169.254/" });
        res.end();
      }
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(upstream.address() as any).port}/rfai-council`;
  const s2 = await start({ RFAI_MCP_BACKEND: "x402" }, { backend: new X402QuoteBackend(url, fetch, 500) });
  try {
    const t = await signIn(s2.base);
    const c = () => rpc(s2.resource, t.access_token, "tools/call", { name: "council_ask", arguments: { task: "Design a cache.", context: { job_id: "j1" } } });
    const r1 = (await c()).body.result;
    assert.equal(r1.isError, true);
    assert.match(r1.content[0].text, /requires an x402 payment: 30000000000000000 \(RFAI\) on base/);
    assert.match(r1.content[0].text, /Not paid/);
    assert.equal(r1.structuredContent.payment_required.x402Version, 1);
    mode = "402v2";
    const r2 = (await c()).body.result;
    assert.match(r2.content[0].text, /30000 \(0xdef\) on eip155:8453/);
    for (const sReq of seen) {
      assert.equal(sReq.headers["x-payment"], undefined);
      assert.equal(sReq.headers["payment-signature"], undefined);
      assert.equal(sReq.headers.authorization, undefined, "the OAuth token is never forwarded upstream");
      assert.deepEqual(JSON.parse(sReq.body), { task: "Design a cache.", protocol: "plan", context: { job_id: "j1" } });
    }
    mode = "500";
    const r3 = (await c()).body.result;
    assert.equal(r3.isError, true);
    assert.ok(!JSON.stringify(r3).includes("stack trace secret"));
    mode = "notjson";
    assert.match((await c()).body.result.content[0].text, /not JSON/);
    mode = "slow";
    assert.match((await c()).body.result.content[0].text, /did not answer in time/);
    mode = "redirect";
    const r6 = (await c()).body.result;
    assert.equal(r6.isError, true);
    assert.match(r6.content[0].text, /could not reach/);
    const info = (await rpc(s2.resource, t.access_token, "tools/call", { name: "council_info", arguments: {} })).body.result;
    assert.equal(info.structuredContent.backend, "x402");
    assert.equal(info.structuredContent.model_key_configured, null);
  } finally {
    await s2.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});
