// OAuth 2.1 authorization server for the RFAI MCP server (one owner, same origin as /mcp).
//
// - Clients register by Dynamic Client Registration (RFC 7591) or Client ID Metadata Documents.
//   DCR client IDs are signed records of the client's metadata, so registrations survive restarts
//   without a database. Confidential client secrets are derived from the client ID with a separate
//   key and never stored.
// - The owner signs in on the consent page with a passcode. Only its scrypt hash is configured.
//   Failed attempts are rate limited globally (one owner) and per address.
// - PKCE S256 is required (enforced by the SDK's authorize schema and token handler).
// - Authorization codes are single use, bound to client, redirect URI, PKCE challenge, scopes and
//   resource, and expire after two minutes.
// - Access tokens are short-lived HS256 JWTs with audience = the /mcp resource URL. Refresh tokens
//   use a different key, rotate on every use, and a reused refresh token is refused.
// - OAuth identity grants access to the MCP tools only. It never becomes a governance permission:
//   nothing from the token is passed into the council's policy screen.
import type { Response, Request, RequestHandler } from "express";
import { SignJWT, jwtVerify, errors as joseErrors } from "jose";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  InvalidGrantError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
  InvalidClientMetadataError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Config } from "./config.ts";
import { deriveKey, hmac, randomToken, signBlob, verifyBlob, verifyPasscode } from "./crypto.ts";
import { MetadataDocumentClients, type MetadataFetcher } from "./cimd.ts";
import { validateRedirectUri } from "./redirects.ts";
import { createHash } from "node:crypto";

export const SCOPE_READ = "council:read";
export const SCOPE_RUN = "council:run";
export const SUPPORTED_SCOPES = [SCOPE_READ, SCOPE_RUN];
const CODE_TTL_MS = 120_000;
const CONSENT_TTL_MS = 10 * 60_000;

export function sameResource(a: URL | string, b: URL | string): boolean {
  const norm = (x: URL | string) => {
    const u = new URL(String(x));
    u.hash = "";
    return u.href.replace(/\/$/, "");
  };
  try {
    return norm(a) === norm(b);
  } catch {
    return false;
  }
}

/** Requested scopes, normalised. Empty means both. council:run implies council:read. */
export function normaliseScopes(requested: string[]): string[] {
  const req = requested.filter(Boolean);
  if (req.length === 0) return [...SUPPORTED_SCOPES];
  for (const s of req) if (!SUPPORTED_SCOPES.includes(s)) throw new InvalidScopeError(`unsupported scope: ${s.slice(0, 40)}`);
  const set = new Set(req);
  if (set.has(SCOPE_RUN)) set.add(SCOPE_READ);
  return SUPPORTED_SCOPES.filter((s) => set.has(s));
}

// ---- clients --------------------------------------------------------------

interface ClientRecord {
  v: 1;
  r: string[];
  n?: string;
  a: "none" | "client_secret_post" | "client_secret_basic";
  g: string[];
  t: number;
  j: string; // random, so every registration is a distinct client
}

export class ClientsStore implements OAuthRegisteredClientsStore {
  private idKey: Buffer;
  private secretKey: Buffer;
  private docs: MetadataDocumentClients | null;

  constructor(secret: Buffer, allowMetadataDocuments: boolean, fetcher?: MetadataFetcher) {
    this.idKey = deriveKey(secret, "client-id");
    this.secretKey = deriveKey(secret, "client-secret");
    this.docs = allowMetadataDocuments ? new MetadataDocumentClients(fetcher) : null;
  }

  private secretFor(clientId: string): string {
    return hmac(this.secretKey, clientId).toString("base64url");
  }

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    if (typeof clientId !== "string" || clientId.length > 4096) return undefined;
    if (clientId.startsWith("rc1.")) {
      const rec = verifyBlob<ClientRecord>(this.idKey, clientId.slice(4));
      if (!rec || rec.v !== 1 || !Array.isArray(rec.r)) return undefined;
      const info: OAuthClientInformationFull = {
        client_id: clientId,
        client_id_issued_at: rec.t,
        redirect_uris: rec.r,
        token_endpoint_auth_method: rec.a,
        grant_types: rec.g,
        response_types: ["code"],
        client_name: rec.n,
      } as OAuthClientInformationFull;
      if (rec.a !== "none") {
        info.client_secret = this.secretFor(clientId);
        info.client_secret_expires_at = 0;
      }
      return info;
    }
    if (this.docs && clientId.startsWith("https://")) return this.docs.get(clientId);
    return undefined;
  }

  async registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): Promise<OAuthClientInformationFull> {
    const uris = client.redirect_uris ?? [];
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 5) throw new InvalidClientMetadataError("redirect_uris must list 1 to 5 URIs");
    for (const u of uris) if (!validateRedirectUri(String(u))) throw new InvalidClientMetadataError("redirect_uri not allowed: use https, loopback http, or a reverse-domain private-use scheme");
    const method = (client.token_endpoint_auth_method ?? "client_secret_basic") as ClientRecord["a"];
    if (!["none", "client_secret_post", "client_secret_basic"].includes(method)) throw new InvalidClientMetadataError("unsupported token_endpoint_auth_method");
    const grants = client.grant_types ?? ["authorization_code", "refresh_token"];
    if (!grants.every((g) => g === "authorization_code" || g === "refresh_token")) throw new InvalidClientMetadataError("unsupported grant_types");
    if (client.response_types && !client.response_types.every((t) => t === "code")) throw new InvalidClientMetadataError("unsupported response_types");
    if (client.scope) normaliseScopes(client.scope.split(" ")); // throws on unknown scope
    const rec: ClientRecord = {
      v: 1,
      r: uris.map(String),
      n: typeof client.client_name === "string" ? client.client_name.slice(0, 100) : undefined,
      a: method,
      g: grants,
      t: Math.floor(Date.now() / 1000),
      j: randomToken(9),
    };
    const clientId = "rc1." + signBlob(this.idKey, rec);
    const out: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_id_issued_at: rec.t,
      redirect_uris: rec.r,
      token_endpoint_auth_method: method,
      grant_types: grants,
      response_types: ["code"],
      client_name: rec.n,
    } as OAuthClientInformationFull;
    delete (out as any).scope; // scopes are granted at consent, not registration
    if (method === "none") {
      delete out.client_secret;
      delete out.client_secret_expires_at;
    } else {
      out.client_secret = this.secretFor(clientId);
      out.client_secret_expires_at = 0;
    }
    return out;
  }
}

// ---- sign-in rate limiting -------------------------------------------------

export class SignInLimiter {
  private global: number[] = [];
  private perIp = new Map<string, number[]>();
  private globalMax: number;
  private ipMax: number;
  private windowMs: number;
  constructor(globalMax = 10, ipMax = 5, windowMs = 15 * 60_000) {
    this.globalMax = globalMax;
    this.ipMax = ipMax;
    this.windowMs = windowMs;
  }
  private prune(list: number[], now: number) {
    while (list.length && now - list[0] > this.windowMs) list.shift();
  }
  blocked(ip: string, now = Date.now()): boolean {
    this.prune(this.global, now);
    const l = this.perIp.get(ip) ?? [];
    this.prune(l, now);
    return this.global.length >= this.globalMax || l.length >= this.ipMax;
  }
  fail(ip: string, now = Date.now()) {
    this.global.push(now);
    const l = this.perIp.get(ip) ?? [];
    l.push(now);
    if (this.perIp.size > 10_000) this.perIp.clear();
    this.perIp.set(ip, l);
  }
}

// ---- provider ---------------------------------------------------------------

interface CodeRecord {
  clientId: string;
  challenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
  challenged: number;
}

interface ConsentRequest {
  c: string; // client_id
  ru: string;
  cc: string;
  sc: string[];
  rs: string;
  st?: string;
  exp: number;
}

export class RfaiOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: ClientsStore;
  private accessKey: Uint8Array;
  private refreshKey: Uint8Array;
  private consentKey: Buffer;
  private codes = new Map<string, CodeRecord>();
  private revoked = new Map<string, number>(); // jti -> expiry (ms)
  readonly limiter = new SignInLimiter();
  private config: Config;

  constructor(config: Config, fetcher?: MetadataFetcher) {
    this.config = config;
    this.clientsStore = new ClientsStore(config.secret, config.allowClientIdMetadataDocuments, fetcher);
    this.accessKey = deriveKey(config.secret, "access-token");
    this.refreshKey = deriveKey(config.secret, "refresh-token");
    this.consentKey = deriveKey(config.secret, "consent");
  }

  private get issuer() {
    return this.config.issuer.href.replace(/\/$/, "");
  }

  private sweep() {
    const now = Date.now();
    for (const [k, v] of this.codes) if (v.expiresAt < now) this.codes.delete(k);
    for (const [k, v] of this.revoked) if (v < now) this.revoked.delete(k);
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const scopes = normaliseScopes(params.scopes ?? []);
    if (params.resource && !sameResource(params.resource, this.config.resource)) {
      throw new InvalidTargetError("resource must be this server's MCP endpoint");
    }
    const req: ConsentRequest = {
      c: client.client_id,
      ru: params.redirectUri,
      cc: params.codeChallenge,
      sc: scopes,
      rs: this.config.resource.href,
      st: params.state,
      exp: Date.now() + CONSENT_TTL_MS,
    };
    renderConsent(res, 200, {
      request: signBlob(this.consentKey, req),
      clientName: client.client_name || "Unnamed app",
      redirectHost: describeRedirect(params.redirectUri),
      scopes,
    });
  }

  /** POST /oauth/consent: the owner approves or denies with the passcode. */
  consentHandler(): RequestHandler {
    return async (req: Request, res: Response) => {
      res.setHeader("Cache-Control", "no-store");
      const body = (req.body ?? {}) as Record<string, unknown>;
      const blob = typeof body.request === "string" ? body.request : "";
      const cr = verifyBlob<ConsentRequest>(this.consentKey, blob);
      if (!cr || typeof cr.exp !== "number" || cr.exp < Date.now()) {
        renderMessage(res, 400, "This sign-in request has expired or is invalid. Start again from the app.");
        return;
      }
      const client = await this.clientsStore.getClient(cr.c);
      if (!client || !client.redirect_uris.includes(cr.ru)) {
        renderMessage(res, 400, "This app is no longer registered. Start again from the app.");
        return;
      }
      const redirect = new URL(cr.ru);
      if (cr.st) redirect.searchParams.set("state", cr.st);
      redirect.searchParams.set("iss", this.issuer);

      if (body.action === "deny") {
        redirect.searchParams.set("error", "access_denied");
        redirect.searchParams.set("error_description", "The owner denied access");
        res.redirect(302, redirect.href);
        return;
      }

      const ip = req.ip || "unknown";
      const view = { request: blob, clientName: client.client_name || "Unnamed app", redirectHost: describeRedirect(cr.ru), scopes: cr.sc };
      if (this.limiter.blocked(ip)) {
        renderConsent(res, 429, { ...view, error: "Too many wrong passcodes. Sign-in is paused for 15 minutes." });
        return;
      }
      const ok = await verifyPasscode(this.config.passcode, typeof body.passcode === "string" ? body.passcode : "");
      if (!ok) {
        this.limiter.fail(ip);
        renderConsent(res, 401, { ...view, error: "That passcode is not right." });
        return;
      }

      this.sweep();
      const code = randomToken(32);
      this.codes.set(sha256(code), {
        clientId: cr.c,
        challenge: cr.cc,
        redirectUri: cr.ru,
        scopes: cr.sc,
        resource: cr.rs,
        expiresAt: Date.now() + CODE_TTL_MS,
        challenged: 0,
      });
      redirect.searchParams.set("code", code);
      res.redirect(302, redirect.href);
    };
  }

  private lookupCode(client: OAuthClientInformationFull, code: string): CodeRecord {
    const key = sha256(String(code));
    const rec = this.codes.get(key);
    if (!rec || rec.expiresAt < Date.now() || rec.clientId !== client.client_id) {
      if (rec && rec.clientId !== client.client_id) this.codes.delete(key);
      throw new InvalidGrantError("invalid or expired authorization code");
    }
    return rec;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const rec = this.lookupCode(client, code);
    rec.challenged += 1;
    if (rec.challenged > 1) {
      // A second attempt means the first exchange failed PKCE or was replayed: burn the code.
      this.codes.delete(sha256(String(code)));
      throw new InvalidGrantError("invalid or expired authorization code");
    }
    return rec.challenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const rec = this.lookupCode(client, code);
    this.codes.delete(sha256(String(code)));
    if (redirectUri !== undefined && redirectUri !== rec.redirectUri) throw new InvalidGrantError("redirect_uri does not match the authorization request");
    if (resource && !sameResource(resource, rec.resource)) throw new InvalidTargetError("resource does not match the authorization request");
    return this.issueTokens(client.client_id, rec.scopes);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    let payload: any;
    try {
      ({ payload } = await jwtVerify(refreshToken, this.refreshKey, {
        algorithms: ["HS256"],
        issuer: this.issuer,
        audience: this.issuer,
        typ: "rt+jwt",
      }));
    } catch {
      throw new InvalidGrantError("invalid refresh token");
    }
    if (payload.client_id !== client.client_id || payload.ep !== this.config.tokenEpoch || typeof payload.jti !== "string") {
      throw new InvalidGrantError("invalid refresh token");
    }
    if (this.revoked.has(payload.jti)) throw new InvalidGrantError("refresh token already used or revoked");
    if (resource && !sameResource(resource, this.config.resource)) throw new InvalidTargetError("resource must be this server's MCP endpoint");
    const granted: string[] = String(payload.scope ?? "").split(" ").filter(Boolean);
    let next = granted;
    if (scopes && scopes.length) {
      for (const s of scopes) if (!granted.includes(s)) throw new InvalidScopeError("cannot widen scope on refresh");
      next = normaliseScopes(scopes);
    }
    this.revoked.set(payload.jti, (payload.exp ?? 0) * 1000);
    return this.issueTokens(client.client_id, next);
  }

  private async issueTokens(clientId: string, scopes: string[]): Promise<OAuthTokens> {
    const now = Math.floor(Date.now() / 1000);
    const scope = scopes.join(" ");
    const access = await new SignJWT({ client_id: clientId, scope, ep: this.config.tokenEpoch })
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
      .setIssuer(this.issuer)
      .setAudience(this.config.resource.href)
      .setSubject("owner")
      .setIssuedAt(now)
      .setExpirationTime(now + this.config.accessTtlSeconds)
      .setJti(randomToken(16))
      .sign(this.accessKey);
    const refresh = await new SignJWT({ client_id: clientId, scope, ep: this.config.tokenEpoch })
      .setProtectedHeader({ alg: "HS256", typ: "rt+jwt" })
      .setIssuer(this.issuer)
      .setAudience(this.issuer)
      .setSubject("owner")
      .setIssuedAt(now)
      .setExpirationTime(now + this.config.refreshTtlSeconds)
      .setJti(randomToken(16))
      .sign(this.refreshKey);
    return { access_token: access, token_type: "Bearer", expires_in: this.config.accessTtlSeconds, refresh_token: refresh, scope };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    let payload: any;
    try {
      ({ payload } = await jwtVerify(token, this.accessKey, {
        algorithms: ["HS256"],
        issuer: this.issuer,
        audience: this.config.resource.href,
        typ: "at+jwt",
      }));
    } catch (e) {
      throw new InvalidTokenError(e instanceof joseErrors.JWTExpired ? "token expired" : "invalid token");
    }
    if (payload.ep !== this.config.tokenEpoch || typeof payload.jti !== "string" || this.revoked.has(payload.jti)) {
      throw new InvalidTokenError("invalid token");
    }
    return {
      token,
      clientId: String(payload.client_id),
      scopes: String(payload.scope ?? "").split(" ").filter(Boolean),
      expiresAt: payload.exp,
      resource: new URL(this.config.resource.href),
      extra: { jti: payload.jti },
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    // RFC 7009: respond 200 whatever the token is; revoke only the caller's own tokens.
    for (const [key, typ] of [
      [this.accessKey, "at+jwt"],
      [this.refreshKey, "rt+jwt"],
    ] as const) {
      try {
        const { payload } = await jwtVerify(request.token, key, { algorithms: ["HS256"], issuer: this.issuer, typ });
        if (payload.client_id === client.client_id && typeof payload.jti === "string") {
          this.revoked.set(payload.jti, (payload.exp ?? 0) * 1000);
        }
        return;
      } catch {
        /* try the other key */
      }
    }
  }
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("base64url");
}

function describeRedirect(uri: string): string {
  try {
    const u = new URL(uri);
    return u.host ? `${u.protocol}//${u.host}` : `${u.protocol}${u.pathname}`;
  } catch {
    return "unknown";
  }
}

// ---- pages ------------------------------------------------------------------

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function pageHeaders(res: Response) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
}

const STYLE = `body{font-family:system-ui,sans-serif;max-width:28rem;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.3rem}.box{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}
input[type=password]{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}
button{padding:.6rem 1rem;font-size:1rem;margin:.5rem .5rem 0 0}.err{color:#a00}.muted{color:#555;font-size:.9rem}`;

const SCOPE_TEXT: Record<string, string> = {
  [SCOPE_READ]: "Read council information and run the free governance screen",
  [SCOPE_RUN]: "Ask the RFAI council questions (uses your model credits)",
};

function renderConsent(
  res: Response,
  status: number,
  v: { request: string; clientName: string; redirectHost: string; scopes: string[]; error?: string },
) {
  pageHeaders(res);
  res.status(status).send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to RFAI Council</title><style>${STYLE}</style></head><body>
<h1>Connect ${esc(v.clientName)} to your RFAI Council</h1>
<div class="box"><p>It will be allowed to:</p><ul>${v.scopes.map((s) => `<li>${esc(SCOPE_TEXT[s] ?? s)}</li>`).join("")}</ul>
<p class="muted">After you approve, you go back to ${esc(v.redirectHost)}. Signing in does not let the app change governance rules or grant itself exceptions.</p></div>
${v.error ? `<p class="err">${esc(v.error)}</p>` : ""}
<form method="post" action="/oauth/consent">
<input type="hidden" name="request" value="${esc(v.request)}">
<label for="passcode">Owner passcode</label>
<input id="passcode" name="passcode" type="password" autocomplete="current-password" autofocus>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny" formnovalidate>Deny</button>
</form></body></html>`);
}

function renderMessage(res: Response, status: number, message: string) {
  pageHeaders(res);
  res.status(status).send(`<!doctype html><html><head><meta charset="utf-8"><title>RFAI Council</title><style>${STYLE}</style></head><body><p>${esc(message)}</p></body></html>`);
}
