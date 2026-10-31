// Configuration from environment variables. Fails closed: the server will not start without
// an HTTPS public URL, a strong signing secret and an owner passcode hash.
// Error messages name the variable and the problem, never the value.
import { parsePasscodeHash, type PasscodeHash } from "./crypto.ts";

export type Backend = "embedded" | "x402";

export interface Config {
  /** Origin the server is reached at, e.g. https://rfai-mcp.example.com (also the OAuth issuer). */
  issuer: URL;
  /** The MCP endpoint and OAuth resource identifier: <issuer>/mcp. */
  resource: URL;
  secret: Buffer;
  passcode: PasscodeHash;
  backend: Backend;
  x402Url: string;
  tokenEpoch: string;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  maxRunsPerHour: number;
  maxConcurrentRuns: number;
  allowedOrigins: string[];
  allowClientIdMetadataDocuments: boolean;
  port: number;
  trustProxy: number;
}

export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) {
    super(`Invalid configuration:\n- ${problems.join("\n- ")}`);
    this.problems = problems;
  }
}

export const DEFAULT_X402_URL =
  "https://x402.bankr.bot/0x6b0c93d0ed4ece1cb51fb95392d43f65fa244794/rfai-council";

function decodeSecret(raw: string): Buffer | null {
  const s = raw.trim();
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return Buffer.from(s, "hex");
  if (/^[A-Za-z0-9_\-+/=]+$/.test(s)) return Buffer.from(s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), "base64url");
  return null;
}

function intVar(env: Record<string, string | undefined>, name: string, def: number, min: number, max: number, problems: string[]): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    problems.push(`${name} must be a whole number from ${min} to ${max}`);
    return def;
  }
  return n;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const problems: string[] = [];

  let issuer: URL | null = null;
  const rawUrl = env.RFAI_MCP_PUBLIC_URL?.trim();
  if (!rawUrl) problems.push("RFAI_MCP_PUBLIC_URL is required (the https:// origin the server is reached at)");
  else {
    try {
      const u = new URL(rawUrl);
      const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol !== "https:" && !(local && u.protocol === "http:")) problems.push("RFAI_MCP_PUBLIC_URL must use https:// (http is allowed only for localhost)");
      else if (u.search || u.hash || u.username || u.password) problems.push("RFAI_MCP_PUBLIC_URL must not contain a query, fragment or credentials");
      else if (u.pathname !== "/" && u.pathname !== "") problems.push("RFAI_MCP_PUBLIC_URL must be an origin with no path");
      else issuer = new URL(u.origin);
    } catch {
      problems.push("RFAI_MCP_PUBLIC_URL is not a valid URL");
    }
  }

  let secret: Buffer | null = null;
  if (!env.RFAI_MCP_SECRET?.trim()) problems.push("RFAI_MCP_SECRET is required (at least 32 random bytes, hex or base64url)");
  else {
    secret = decodeSecret(env.RFAI_MCP_SECRET);
    if (!secret || secret.length < 32) {
      problems.push("RFAI_MCP_SECRET must decode to at least 32 bytes (hex or base64url)");
      secret = null;
    }
  }

  const passcode = parsePasscodeHash(env.RFAI_MCP_OWNER_PASSCODE_HASH);
  if (!env.RFAI_MCP_OWNER_PASSCODE_HASH?.trim()) problems.push("RFAI_MCP_OWNER_PASSCODE_HASH is required (make one with: node scripts/hash-passcode.mjs)");
  else if (!passcode) problems.push("RFAI_MCP_OWNER_PASSCODE_HASH is malformed or too weak (expected scrypt$N$r$p$salt$hash from scripts/hash-passcode.mjs)");

  const backendRaw = (env.RFAI_MCP_BACKEND ?? "embedded").trim();
  let backend: Backend = "embedded";
  if (backendRaw === "embedded" || backendRaw === "x402") backend = backendRaw;
  else problems.push("RFAI_MCP_BACKEND must be 'embedded' or 'x402'");

  const x402Url = (env.RFAI_X402_URL ?? DEFAULT_X402_URL).trim();
  try {
    if (new URL(x402Url).protocol !== "https:") problems.push("RFAI_X402_URL must use https://");
  } catch {
    problems.push("RFAI_X402_URL is not a valid URL");
  }

  const tokenEpoch = (env.RFAI_MCP_TOKEN_EPOCH ?? "1").trim();
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(tokenEpoch)) problems.push("RFAI_MCP_TOKEN_EPOCH must be 1-32 letters, digits, dot, dash or underscore");

  const accessTtlSeconds = intVar(env, "RFAI_MCP_ACCESS_TTL_SECONDS", 3600, 60, 86400, problems);
  const refreshTtlSeconds = intVar(env, "RFAI_MCP_REFRESH_TTL_SECONDS", 30 * 86400, 3600, 90 * 86400, problems);
  const maxRunsPerHour = intVar(env, "RFAI_MCP_MAX_RUNS_PER_HOUR", 20, 1, 1000, problems);
  const maxConcurrentRuns = intVar(env, "RFAI_MCP_MAX_CONCURRENT_RUNS", 2, 1, 16, problems);
  const port = intVar(env, "PORT", 8080, 1, 65535, problems);
  const trustProxy = intVar(env, "RFAI_MCP_TRUST_PROXY_HOPS", 1, 0, 5, problems);

  const allowedOrigins = (env.RFAI_MCP_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const o of allowedOrigins) {
    try {
      if (new URL(o).origin !== o) problems.push("RFAI_MCP_ALLOWED_ORIGINS entries must be bare origins like https://app.example.com");
    } catch {
      problems.push("RFAI_MCP_ALLOWED_ORIGINS has an entry that is not a URL");
    }
  }

  const cimd = (env.RFAI_MCP_ALLOW_CLIENT_METADATA_URLS ?? "true").trim().toLowerCase();
  if (!["true", "false"].includes(cimd)) problems.push("RFAI_MCP_ALLOW_CLIENT_METADATA_URLS must be true or false");

  if (problems.length || !issuer || !secret || !passcode) throw new ConfigError(problems);

  return {
    issuer,
    resource: new URL("/mcp", issuer),
    secret,
    passcode,
    backend,
    x402Url,
    tokenEpoch,
    accessTtlSeconds,
    refreshTtlSeconds,
    maxRunsPerHour,
    maxConcurrentRuns,
    allowedOrigins,
    allowClientIdMetadataDocuments: cimd === "true",
    port,
    trustProxy,
  };
}
