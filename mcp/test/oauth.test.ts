import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { SignJWT } from "jose";
import { deriveKey } from "../src/crypto.ts";
import { start, register, pkce, openConsent, submitConsent, getCode, token, signIn, rpc, PASS, REDIRECT, SECRET_HEX, type Started } from "./helpers.ts";

let s: Started;
before(async () => {
  s = await start();
});
after(async () => {
  await s.close();
});

test("discovery: protected resource metadata at path and root", async () => {
  for (const p of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]) {
    const r = await fetch(s.base + p);
    assert.equal(r.status, 200);
    const j: any = await r.json();
    assert.equal(j.resource, s.resource);
    assert.deepEqual(j.authorization_servers, [s.base]);
    assert.deepEqual(j.scopes_supported, ["council:read", "council:run"]);
  }
});

test("discovery: authorization server metadata", async () => {
  const j: any = await (await fetch(s.base + "/.well-known/oauth-authorization-server")).json();
  assert.equal(j.issuer, s.base);
  assert.equal(j.authorization_endpoint, s.base + "/authorize");
  assert.equal(j.token_endpoint, s.base + "/token");
  assert.equal(j.registration_endpoint, s.base + "/register");
  assert.deepEqual(j.code_challenge_methods_supported, ["S256"]);
  assert.equal(j.client_id_metadata_document_supported, true);
  assert.equal(j.authorization_response_iss_parameter_supported, true);
});

test("mcp: no token -> 401 with resource_metadata and scope challenge", async () => {
  const r = await rpc(s.resource, null, "initialize", {});
  assert.equal(r.status, 401);
  const h = r.headers.get("www-authenticate")!;
  assert.match(h, /^Bearer /);
  assert.match(h, new RegExp(`resource_metadata="${s.base}/.well-known/oauth-protected-resource/mcp"`));
  assert.match(h, /scope="council:read council:run"/);
});

test("mcp: garbage, wrong-key, wrong-audience, expired, alg=none and wrong-typ tokens are rejected", async () => {
  const key = deriveKey(Buffer.from(SECRET_HEX, "hex"), "access-token");
  const now = Math.floor(Date.now() / 1000);
  const mk = (o: { aud?: string; exp?: number; k?: Uint8Array; typ?: string; ep?: string; iss?: string }) =>
    new SignJWT({ client_id: "x", scope: "council:read council:run", ep: o.ep ?? "1" })
      .setProtectedHeader({ alg: "HS256", typ: o.typ ?? "at+jwt" })
      .setIssuer(o.iss ?? s.base)
      .setAudience(o.aud ?? s.resource)
      .setIssuedAt(now - 10)
      .setExpirationTime(o.exp ?? now + 600)
      .setJti("j" + Math.random())
      .sign(o.k ?? key);
  // Sanity: a correctly forged-with-the-real-key token is accepted (proves the negatives below are meaningful).
  const good = await mk({});
  assert.equal((await rpc(s.resource, good, "tools/list")).status, 200);
  const bad = [
    "not-a-token",
    await mk({ k: new Uint8Array(32).fill(7) }),
    await mk({ aud: "https://other.example/mcp" }),
    await mk({ exp: now - 5 }),
    await mk({ typ: "rt+jwt" }),
    await mk({ ep: "0" }),
    await mk({ iss: "https://evil.example" }),
    Buffer.from('{"alg":"none","typ":"at+jwt"}').toString("base64url") + "." + Buffer.from(JSON.stringify({ aud: s.resource, iss: s.base, scope: "council:read council:run", exp: now + 600 })).toString("base64url") + ".",
  ];
  for (const t of bad) {
    const r = await rpc(s.resource, t, "tools/list");
    assert.equal(r.status, 401, `token should be rejected: ${t.slice(0, 20)}`);
    assert.match(r.headers.get("www-authenticate")!, /error="invalid_token"/);
  }
  // Refresh-token key cannot mint access tokens.
  const rkey = deriveKey(Buffer.from(SECRET_HEX, "hex"), "refresh-token");
  assert.equal((await rpc(s.resource, await mk({ k: rkey }), "tools/list")).status, 401);
});

test("registration: valid public and confidential clients; bad metadata refused", async () => {
  const pub = await register(s.base);
  assert.equal(pub.status, 201);
  assert.match(pub.body.client_id, /^rc1\./);
  assert.equal(pub.body.client_secret, undefined);
  const conf = await register(s.base, { token_endpoint_auth_method: "client_secret_basic" });
  assert.equal(conf.status, 201);
  assert.ok(conf.body.client_secret && conf.body.client_secret.length >= 40);
  for (const bad of [
    { redirect_uris: ["http://evil.example/cb"] },
    { redirect_uris: ["javascript:alert(1)"] },
    { redirect_uris: ["https://ok.example/cb#frag"] },
    { redirect_uris: [] },
    { grant_types: ["client_credentials"] },
    { token_endpoint_auth_method: "private_key_jwt" },
    { scope: "admin" },
  ]) {
    const r = await register(s.base, bad);
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
  // Private-use reverse-domain scheme is allowed (native apps).
  assert.equal((await register(s.base, { redirect_uris: ["com.example.app:/oauth"] })).status, 201);
});

test("authorize: tampered client_id and unregistered redirect are refused without redirecting", async () => {
  const reg = await register(s.base);
  const id: string = reg.body.client_id;
  const tampered = id.slice(0, -3) + (id.endsWith("AAA") ? "BBB" : "AAA");
  const a = await openConsent(s.base, tampered);
  assert.equal(a.status, 400);
  assert.equal(a.location, null);
  const b = await openConsent(s.base, id, { redirect: "https://evil.example/cb" });
  assert.equal(b.status, 400);
  assert.equal(b.location, null);
});

test("authorize: missing PKCE, unknown scope and foreign resource are refused", async () => {
  const reg = await register(s.base);
  const q = new URLSearchParams({ response_type: "code", client_id: reg.body.client_id, redirect_uri: REDIRECT, state: "x" });
  const r = await fetch(`${s.base}/authorize?${q}`, { redirect: "manual" });
  assert.equal(r.status, 302);
  assert.equal(new URL(r.headers.get("location")!).searchParams.get("error"), "invalid_request");
  const sc = await openConsent(s.base, reg.body.client_id, { scope: "council:admin" });
  assert.equal(new URL(sc.location!).searchParams.get("error"), "invalid_scope");
  const rs = await openConsent(s.base, reg.body.client_id, { resource: "https://other.example/mcp" });
  assert.equal(new URL(rs.location!).searchParams.get("error"), "invalid_target");
  const ok = await openConsent(s.base, reg.body.client_id, { resource: s.resource });
  assert.equal(ok.status, 200);
  assert.ok(ok.request);
});

test("consent page: shows client and destination, cannot be framed, not cached", async () => {
  const reg = await register(s.base, { client_name: "<b>Sesame</b>" });
  const c = await openConsent(s.base, reg.body.client_id);
  assert.equal(c.status, 200);
  assert.ok(c.html.includes("&lt;b&gt;Sesame&lt;/b&gt;"), "client name is escaped");
  assert.ok(c.html.includes("http://127.0.0.1:9"));
  assert.equal(c.headers.get("x-frame-options"), "DENY");
  assert.match(c.headers.get("content-security-policy")!, /frame-ancestors 'none'/);
  assert.equal(c.headers.get("cache-control"), "no-store");
});

test("consent: deny returns access_denied with state and iss; no code", async () => {
  const reg = await register(s.base);
  const r = await getCode(s.base, reg.body.client_id, { action: "deny", passcode: "" });
  assert.equal(r.status, 302);
  assert.equal(r.url!.searchParams.get("error"), "access_denied");
  assert.equal(r.url!.searchParams.get("state"), "st-123");
  assert.equal(r.url!.searchParams.get("iss"), s.base);
  assert.equal(r.code, null);
});

test("consent: forged or altered request blob is refused", async () => {
  const reg = await register(s.base);
  const c = await openConsent(s.base, reg.body.client_id, { scope: "council:read" });
  const [body, mac] = c.request!.split(".");
  const obj = JSON.parse(Buffer.from(body, "base64url").toString());
  obj.sc = ["council:read", "council:run"];
  const altered = Buffer.from(JSON.stringify(obj)).toString("base64url") + "." + mac;
  const r = await submitConsent(s.base, altered, PASS);
  assert.equal(r.status, 400);
  assert.equal(r.code, null);
});

test("full flow: code -> tokens -> MCP; code is single use and bound to PKCE, client and redirect", async () => {
  const reg = await register(s.base);
  const p = pkce();
  const c = await getCode(s.base, reg.body.client_id, { challenge: p.challenge });
  assert.equal(c.status, 302);
  assert.equal(c.url!.searchParams.get("iss"), s.base);
  assert.equal(c.url!.searchParams.get("state"), "st-123");
  assert.ok(c.code);
  const t = await token(s.base, { grant_type: "authorization_code", code: c.code!, code_verifier: p.verifier, client_id: reg.body.client_id, redirect_uri: REDIRECT, resource: s.resource });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  assert.equal(t.body.token_type, "Bearer");
  assert.equal(t.body.scope, "council:read council:run");
  assert.ok(t.body.refresh_token);
  const again = await token(s.base, { grant_type: "authorization_code", code: c.code!, code_verifier: p.verifier, client_id: reg.body.client_id });
  assert.equal(again.status, 400);
  assert.equal(again.body.error, "invalid_grant");
  assert.equal((await rpc(s.resource, t.body.access_token, "tools/list")).status, 200);

  // Wrong verifier: refused, and the code is burned (a correct retry also fails).
  const p2 = pkce();
  const c2 = await getCode(s.base, reg.body.client_id, { challenge: p2.challenge });
  const w = await token(s.base, { grant_type: "authorization_code", code: c2.code!, code_verifier: pkce().verifier, client_id: reg.body.client_id });
  assert.equal(w.body.error, "invalid_grant");
  const retry = await token(s.base, { grant_type: "authorization_code", code: c2.code!, code_verifier: p2.verifier, client_id: reg.body.client_id });
  assert.equal(retry.body.error, "invalid_grant");

  // Another client cannot redeem the code.
  const other = await register(s.base);
  const p3 = pkce();
  const c3 = await getCode(s.base, reg.body.client_id, { challenge: p3.challenge });
  const x = await token(s.base, { grant_type: "authorization_code", code: c3.code!, code_verifier: p3.verifier, client_id: other.body.client_id });
  assert.equal(x.body.error, "invalid_grant");

  // Redirect URI mismatch and foreign resource at the token endpoint.
  const reg2 = await register(s.base, { redirect_uris: [REDIRECT, "http://127.0.0.1:9/other"] });
  const p4 = pkce();
  const c4 = await getCode(s.base, reg2.body.client_id, { challenge: p4.challenge });
  const m = await token(s.base, { grant_type: "authorization_code", code: c4.code!, code_verifier: p4.verifier, client_id: reg2.body.client_id, redirect_uri: "http://127.0.0.1:9/other" });
  assert.equal(m.body.error, "invalid_grant");
  const p5 = pkce();
  const c5 = await getCode(s.base, reg2.body.client_id, { challenge: p5.challenge });
  const rt = await token(s.base, { grant_type: "authorization_code", code: c5.code!, code_verifier: p5.verifier, client_id: reg2.body.client_id, resource: "https://other.example/mcp" });
  assert.equal(rt.status, 400);
});

test("confidential client: secret required (post and basic); wrong secret refused", async () => {
  const reg = await register(s.base, { token_endpoint_auth_method: "client_secret_basic" });
  const { client_id, client_secret } = reg.body;
  const run = async (params: Record<string, string>, headers: Record<string, string> = {}) => {
    const p = pkce();
    const c = await getCode(s.base, client_id, { challenge: p.challenge });
    return token(s.base, { grant_type: "authorization_code", code: c.code!, code_verifier: p.verifier, ...params }, headers);
  };
  const basic = "Basic " + Buffer.from(`${encodeURIComponent(client_id)}:${encodeURIComponent(client_secret)}`).toString("base64");
  assert.equal((await run({}, { authorization: basic })).status, 200);
  assert.equal((await run({ client_id, client_secret })).status, 200);
  const wrong = await run({ client_id, client_secret: "x".repeat(43) });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error, "invalid_client");
  const none = await run({ client_id });
  assert.equal(none.body.error, "invalid_client");
});

test("refresh: rotates, refuses reuse, other clients and scope widening; read-only token cannot run", async () => {
  const t = await signIn(s.base, "council:read");
  assert.equal(t.scope, "council:read");
  const r1 = await token(s.base, { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.body.refresh_token, t.refresh_token);
  const reuse = await token(s.base, { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId });
  assert.equal(reuse.body.error, "invalid_grant");
  const other = await register(s.base);
  const stolen = await token(s.base, { grant_type: "refresh_token", refresh_token: r1.body.refresh_token, client_id: other.body.client_id });
  assert.equal(stolen.body.error, "invalid_grant");
  const widen = await token(s.base, { grant_type: "refresh_token", refresh_token: r1.body.refresh_token, client_id: t.clientId, scope: "council:read council:run" });
  assert.equal(widen.body.error, "invalid_scope");
  // An access token is not a refresh token.
  const swap = await token(s.base, { grant_type: "refresh_token", refresh_token: t.access_token, client_id: t.clientId });
  assert.equal(swap.body.error, "invalid_grant");

  const call = await rpc(s.resource, t.access_token, "tools/call", { name: "council_ask", arguments: { task: "hello" } });
  assert.equal(call.status, 403);
  assert.match(call.headers.get("www-authenticate")!, /error="insufficient_scope"/);
  assert.match(call.headers.get("www-authenticate")!, /scope="council:read council:run"/);
  // But the free screen works with council:read.
  const scr = await rpc(s.resource, t.access_token, "tools/call", { name: "council_screen", arguments: { task: "Design a cache." } });
  assert.equal(scr.status, 200);
  assert.equal(scr.body.result.isError, undefined);
});

test("revocation: revoked access token stops working", async () => {
  const t = await signIn(s.base);
  assert.equal((await rpc(s.resource, t.access_token, "tools/list")).status, 200);
  const r = await fetch(`${s.base}/revoke`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: t.access_token, client_id: t.clientId }),
  });
  assert.equal(r.status, 200);
  assert.equal((await rpc(s.resource, t.access_token, "tools/list")).status, 401);
});

test("tokens survive a restart with the same secret; a new token epoch revokes everything", async () => {
  const t = await signIn(s.base);
  const port = new URL(s.base).port;
  await s.close();
  // Same secret and URL: DCR client IDs and tokens still valid without any database.
  s = await startOnPort(port, {});
  assert.equal((await rpc(s.resource, t.access_token, "tools/list")).status, 200);
  const r = await token(s.base, { grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId });
  assert.equal(r.status, 200);
  await s.close();
  s = await startOnPort(port, { RFAI_MCP_TOKEN_EPOCH: "2" });
  assert.equal((await rpc(s.resource, r.body.access_token, "tools/list")).status, 401);
  const r2 = await token(s.base, { grant_type: "refresh_token", refresh_token: r.body.refresh_token, client_id: t.clientId });
  assert.equal(r2.body.error, "invalid_grant");
});

// Restart helper that keeps the same port (issuer and audience depend on it).
import { loadConfig } from "../src/config.ts";
import { createApp } from "../src/app.ts";
import { PASS_HASH } from "./helpers.ts";
async function startOnPort(port: string, env: Record<string, string>): Promise<Started> {
  const base = `http://localhost:${port}`;
  const config = loadConfig({ RFAI_MCP_PUBLIC_URL: base, RFAI_MCP_SECRET: SECRET_HEX, RFAI_MCP_OWNER_PASSCODE_HASH: PASS_HASH, RFAI_MCP_TRUST_PROXY_HOPS: "0", ...env });
  const logs: string[] = [];
  const ctx = createApp(config, { log: (l) => logs.push(l) });
  const server = await new Promise<any>((resolve) => {
    const sv = ctx.app.listen(Number(port), "127.0.0.1", () => resolve(sv));
  });
  return { base, resource: `${base}/mcp`, logs, ctx, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

test("passcode: wrong passcode refused; repeated failures pause sign-in even for the right passcode", async () => {
  const s2 = await start();
  try {
    const reg = await register(s2.base);
    const c = await openConsent(s2.base, reg.body.client_id);
    const w = await submitConsent(s2.base, c.request!, "wrong passcode");
    assert.equal(w.status, 401);
    assert.equal(w.code, null);
    assert.ok(w.text.includes("not right"));
    for (let i = 0; i < 4; i++) await submitConsent(s2.base, c.request!, "wrong again");
    const locked = await submitConsent(s2.base, c.request!, PASS);
    assert.equal(locked.status, 429);
    assert.equal(locked.code, null);
  } finally {
    await s2.close();
  }
});

test("logs never contain tokens, codes, passcodes or query strings", async () => {
  const t = await signIn(s.base);
  await rpc(s.resource, t.access_token, "tools/list");
  const all = s.logs.join("\n");
  assert.ok(all.length > 0);
  assert.ok(!all.includes(t.access_token.slice(0, 30)));
  assert.ok(!all.includes(t.refresh_token.slice(0, 30)));
  assert.ok(!all.includes(PASS));
  assert.ok(!all.includes("code="));
  assert.ok(!all.includes("?"));
});
