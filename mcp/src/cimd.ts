// OAuth Client ID Metadata Documents (the MCP 2025-11-25 registration path where client_id is
// an https URL that serves the client's metadata). Fetching a URL chosen by the caller is an
// SSRF risk, so the fetch is locked down: https only, public IP addresses only (checked at
// connect time, so DNS rebinding cannot swap in a private address), no redirects, short
// timeout, small size cap, cached.
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import https from "node:https";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { validateRedirectUri } from "./redirects.ts";

const MAX_BYTES = 16 * 1024;
const TIMEOUT_MS = 5000;
const CACHE_MS = 10 * 60 * 1000;

export function isPublicAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    if (a === 169 && b === 254) return false; // link-local, cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false; // 192.0.0.0/24 and 192.0.2.0/24
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
    if (a === 198 && b === 51) return false;
    if (a === 203 && b === 0) return false;
    if (a >= 224) return false; // multicast, reserved, broadcast
    return true;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === "::" || s === "::1") return false;
    if (s.startsWith("::ffff:")) return isPublicAddress(s.slice(7));
    if (/^f[cd]/.test(s)) return false; // unique local
    if (/^fe[89ab]/.test(s)) return false; // link-local
    if (s.startsWith("ff")) return false; // multicast
    if (s.startsWith("2001:db8")) return false; // documentation
    if (s.startsWith("64:ff9b")) return false; // NAT64 can reach IPv4 private space
    return true;
  }
  return false;
}

export function checkMetadataUrl(clientId: string): URL | null {
  let u: URL;
  try {
    u = new URL(clientId);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.hash) return null;
  if (u.pathname === "/" || u.pathname === "") return null;
  if (u.port && u.port !== "443") return null;
  if (isIP(u.hostname.replace(/^\[|\]$/g, ""))) return null; // hostnames only
  if (clientId.length > 512) return null;
  return u;
}

export type MetadataFetcher = (url: URL) => Promise<string>;

const guardedLookup: typeof dnsLookup = ((hostname: string, options: any, cb: any) => {
  dnsLookup(hostname, { ...options, all: true }, (err, addrs: any) => {
    if (err) return cb(err);
    const list = (addrs as { address: string; family: number }[]).filter((a) => isPublicAddress(a.address));
    if (!list.length) return cb(Object.assign(new Error("address not allowed"), { code: "EADDRNOTALLOWED" }));
    if (options?.all) cb(null, list);
    else cb(null, list[0].address, list[0].family);
  });
}) as any;

export const defaultFetcher: MetadataFetcher = (url) =>
  new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { lookup: guardedLookup, timeout: TIMEOUT_MS, headers: { accept: "application/json" } },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`status ${res.statusCode}`));
          return;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > MAX_BYTES) {
            req.destroy(new Error("too large"));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });

/** Validates a fetched metadata document. Returns client info or null. */
export function parseMetadataDocument(clientId: string, text: string): OAuthClientInformationFull | null {
  let doc: any;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object" || doc.client_id !== clientId) return null;
  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0 || doc.redirect_uris.length > 5) return null;
  if (!doc.redirect_uris.every((u: unknown) => typeof u === "string" && validateRedirectUri(u))) return null;
  // Metadata-document clients cannot hold a shared secret; only public clients are accepted.
  const method = doc.token_endpoint_auth_method ?? "none";
  if (method !== "none") return null;
  const grants = doc.grant_types ?? ["authorization_code"];
  if (!Array.isArray(grants) || !grants.every((g: unknown) => g === "authorization_code" || g === "refresh_token")) return null;
  const name = typeof doc.client_name === "string" ? doc.client_name.slice(0, 100) : undefined;
  return {
    client_id: clientId,
    redirect_uris: doc.redirect_uris,
    token_endpoint_auth_method: "none",
    grant_types: grants,
    response_types: ["code"],
    client_name: name,
  } as OAuthClientInformationFull;
}

export class MetadataDocumentClients {
  private cache = new Map<string, { at: number; info: OAuthClientInformationFull | null }>();
  private fetcher: MetadataFetcher;
  constructor(fetcher: MetadataFetcher = defaultFetcher) {
    this.fetcher = fetcher;
  }

  async get(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const url = checkMetadataUrl(clientId);
    if (!url) return undefined;
    const hit = this.cache.get(clientId);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.info ?? undefined;
    let info: OAuthClientInformationFull | null = null;
    try {
      info = parseMetadataDocument(clientId, await this.fetcher(url));
    } catch {
      info = null;
    }
    if (this.cache.size > 200) this.cache.clear();
    this.cache.set(clientId, { at: Date.now(), info });
    return info ?? undefined;
  }
}
