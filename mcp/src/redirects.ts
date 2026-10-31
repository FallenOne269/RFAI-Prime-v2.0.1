// Redirect URI rules for registered clients.
// Allowed: https URLs; http only on loopback (RFC 8252 native apps); private-use schemes in
// reverse-domain form such as com.example.app:/callback (RFC 8252 section 7.1).
// Rejected: fragments, credentials, javascript:, data:, file: and other non-reverse-domain schemes.
export function validateRedirectUri(raw: string): boolean {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 512) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === "https:") return !!u.hostname;
  if (u.protocol === "http:") return u.hostname === "127.0.0.1" || u.hostname === "[::1]" || u.hostname === "localhost";
  const scheme = u.protocol.slice(0, -1);
  return /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/.test(scheme);
}
