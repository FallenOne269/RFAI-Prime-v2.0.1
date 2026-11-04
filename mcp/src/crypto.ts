// Small crypto helpers: key derivation, signed blobs, passcode hashing. Node built-ins only.
import { createHmac, hkdfSync, randomBytes, scrypt, scryptSync, timingSafeEqual } from "node:crypto";

/** Derive an independent 32-byte key per purpose from the server secret (HKDF-SHA256). */
export function deriveKey(secret: Buffer, label: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.from("rfai-mcp/v1"), Buffer.from(label), 32));
}

export function hmac(key: Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

export function safeEqual(a: Buffer | string, b: Buffer | string): boolean {
  const x = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const y = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

/** base64url(JSON) + "." + base64url(HMAC). Integrity only: the payload is readable. */
export function signBlob(key: Buffer, payload: unknown): string {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${hmac(key, body).toString("base64url")}`;
}

export function verifyBlob<T = any>(key: Buffer, blob: string, maxLen = 8192): T | null {
  if (typeof blob !== "string" || blob.length > maxLen) return null;
  const dot = blob.indexOf(".");
  if (dot <= 0 || dot !== blob.lastIndexOf(".")) return null;
  const body = blob.slice(0, dot);
  const mac = blob.slice(dot + 1);
  if (!safeEqual(hmac(key, body).toString("base64url"), mac)) return null;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

// ---- owner passcode (scrypt) ----------------------------------------------

export interface PasscodeHash {
  N: number;
  r: number;
  p: number;
  salt: Buffer;
  hash: Buffer;
}

/** Format: scrypt$N$r$p$<salt b64url>$<hash b64url>. Returns null when malformed or too weak. */
export function parsePasscodeHash(s: string | undefined): PasscodeHash | null {
  if (!s) return null;
  const parts = s.trim().split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return null;
  const [N, r, p] = parts.slice(1, 4).map((x) => Number(x));
  if (![N, r, p].every((x) => Number.isInteger(x) && x > 0)) return null;
  if (N < 1 << 14 || N > 1 << 20 || (N & (N - 1)) !== 0 || r < 8 || r > 32 || p > 4) return null;
  const salt = Buffer.from(parts[4], "base64url");
  const hash = Buffer.from(parts[5], "base64url");
  if (salt.length < 16 || hash.length < 32) return null;
  return { N, r, p, salt, hash };
}

export function verifyPasscode(h: PasscodeHash, candidate: string): Promise<boolean> {
  return new Promise((resolve) => {
    if (typeof candidate !== "string" || candidate.length === 0 || candidate.length > 1024) {
      resolve(false);
      return;
    }
    scrypt(candidate, h.salt, h.hash.length, { N: h.N, r: h.r, p: h.p, maxmem: 256 * h.N * h.r }, (err, out) => {
      resolve(!err && timingSafeEqual(out, h.hash));
    });
  });
}

export function hashPasscodeSync(pass: string, N = 1 << 15): string {
  // Used by tests; the CLI in scripts/hash-passcode.mjs is what operators run.
  const salt = randomBytes(16);
  const out = scryptSync(pass, salt, 32, { N, r: 8, p: 1, maxmem: 256 * N * 8 });
  return `scrypt$${N}$8$1$${salt.toString("base64url")}$${out.toString("base64url")}`;
}
