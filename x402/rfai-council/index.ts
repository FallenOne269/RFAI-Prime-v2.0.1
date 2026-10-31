/**
 * rfai-council — RFAI-PRIME council as a paid x402 endpoint, with the governance screen.
 *
 * Version: v2.1-governed-x402.1 (signed grants). Council ported from
 * FallenOne269/RFAI-Prime-v2.0.1 src/rfai_prime_runtime.py; governance ported from the
 * local v2.1 SafetyGuard (policies/discovery_default_v1.json, v1.0.0) and the Oct 28
 * v2.2 signed-grant check (Ed25519, public keys only).
 *
 * Pipeline: input screen -> Architect -> 5 parallel Critics -> Integrator -> output screen.
 *
 * Governance rules on this endpoint:
 *   - Authority comes only from signed grants. A caller's own flags (for example
 *     "written_testing_authorization" or "personal_data_authorized") are recorded and ignored.
 *   - Grants verify only against public keys in RFAI_TRUSTED_SIGNERS. When that is unset or
 *     unreadable, nothing verifies and every request gets the strict default policy.
 *   - The domain counts from a signed grant; otherwise a keyword screen guesses it from the
 *     task, and a caller-declared high-impact domain is honoured because it only adds strictness.
 *   - This endpoint is production with no human reviewer. Anything the policy would send to
 *     review is withheld, not answered; anything denied is refused before any model call.
 *   - The output screen covers everything returned (final text, draft, plan, critic text).
 *
 * Models are called through the Bankr LLM Gateway (Anthropic /v1/messages format). The only
 * model secret is RFAI_LLM_KEY, read from process.env and never returned, logged, or echoed.
 *
 * Every refusal and failure returns a 4xx/5xx, so x402 Cloud does not settle the payment.
 */

const ENDPOINT_VERSION = "v2.1-governed-x402.1";
const GATEWAY_URL = "https://llm.bankr.bot/v1/messages";

const DEFAULT_ARCHITECT_MODEL = "claude-haiku-4.5";
const DEFAULT_CRITIC_MODEL = "claude-haiku-4.5";
const DEFAULT_INTEGRATOR_MODEL = "claude-haiku-4.5";

const CRITIC_PERSPECTIVES = [
  "correctness",
  "completeness",
  "security",
  "performance",
  "clarity",
] as const;

const MAX_TASK_CHARS = 2000;
const MAX_GRANTS = 8;
const MAX_JOB_ID_CHARS = 128;
const MAX_LIST_ITEMS = 16;
const EARLY_EXIT_SCORE = 8.0; // same threshold as the Python runtime

// Time budget inside the 30 s platform limit.
const ARCHITECT_TIMEOUT_MS = 11000;
const CRITIC_TIMEOUT_MS = 7000;
const INTEGRATOR_TIMEOUT_MS = 10000;

type Protocol = "plan" | "execute";

interface ArchitectPlan {
  summary: string;
  approach: string;
  concerns: string[];
}

interface CriticFeedback {
  perspective: string;
  score: number;
  feedback: string;
  suggestions: string[];
}

class UpstreamError extends Error {}

// ---------------------------------------------------------------------------
// Policy: a faithful copy of policies/discovery_default_v1.json (v1.0.0). Every field is
// written out, so policySha256() matches the Python Policy.sha256 of the same file.
// ---------------------------------------------------------------------------

type Decision = "allow" | "review" | "deny";
type Risk = "none" | "low" | "medium" | "high" | "critical";

interface Rule {
  id: string;
  description: string;
  stage: "input" | "output" | "both";
  decision: "review" | "deny";
  risk: Risk;
  reason_code: string;
  patterns: string[];
  capabilities: string[];
  domains: string[];
  unless_flags: string[];
  when_flags: string[];
  required_approvals: string[];
}

const SECRET_PATTERNS = [
  "-----BEGIN [A-Z ]*PRIVATE KEY-----",
  "\\bAKIA[0-9A-Z]{16}\\b",
  "\\b(sk|rk)-[A-Za-z0-9_-]{16,}",
  "\\b(ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}",
  "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}",
];

const HIGH_IMPACT_DOMAINS = [
  "employment",
  "education",
  "credit",
  "essential_services",
  "justice",
  "biometrics",
  "migration",
  "health",
  "safety",
];

function rule(r: Partial<Rule> & Pick<Rule, "id" | "description" | "decision" | "reason_code">): Rule {
  return {
    stage: "input",
    risk: "medium",
    patterns: [],
    capabilities: [],
    domains: [],
    unless_flags: [],
    when_flags: [],
    required_approvals: [],
    ...r,
  };
}

const POLICY = {
  policy_id: "rfai-discovery-default",
  version: "1.0.0",
  description:
    "Default screen for supervised RFAI Discovery work. A keyword and declared-capability screen, not a classifier. Tailor per client; any change is a new version.",
  rules: [
    rule({
      id: "IN-SECRET",
      description: "Credential or private key in the task; it must not be sent to a model provider",
      stage: "input",
      decision: "deny",
      risk: "high",
      reason_code: "SECRET_IN_INPUT",
      patterns: SECRET_PATTERNS,
    }),
    rule({
      id: "OUT-SECRET",
      description: "Credential or private key in the model output",
      stage: "output",
      decision: "deny",
      risk: "high",
      reason_code: "SECRET_IN_OUTPUT",
      patterns: SECRET_PATTERNS,
    }),
    rule({
      id: "IN-PERSONAL-DATA",
      description:
        "Personal data in the task (email, US SSN or phone number); default is synthetic or de-identified data",
      stage: "input",
      decision: "review",
      risk: "medium",
      reason_code: "PERSONAL_DATA",
      patterns: [
        "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
        "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        "(?<!\\w)\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}(?!\\w)",
      ],
      unless_flags: ["personal_data_authorized"],
      required_approvals: ["privacy_owner"],
    }),
    rule({
      id: "IN-INJECTION",
      description: "Possible prompt injection in the task",
      stage: "input",
      decision: "review",
      risk: "medium",
      reason_code: "PROMPT_INJECTION_SUSPECTED",
      patterns: [
        "ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)",
        "disregard (the |your )?(system|previous) (prompt|instructions)",
        "(reveal|print|show) (me )?(your|the) (system prompt|hidden instructions)",
        "you are now (in )?(developer|dan|jailbreak) mode",
      ],
      required_approvals: ["security_reviewer"],
    }),
    rule({
      id: "IN-HIGH-IMPACT",
      description: "High-impact use domain; needs domain expertise and a named risk owner",
      stage: "input",
      decision: "review",
      risk: "high",
      reason_code: "HIGH_IMPACT_DOMAIN",
      domains: HIGH_IMPACT_DOMAINS,
      required_approvals: ["domain_expert", "risk_owner"],
    }),
    rule({
      id: "IN-HIGH-IMPACT-UNREVIEWED",
      description: "High-impact domain requested for unreviewed production use; excluded by default",
      stage: "input",
      decision: "deny",
      risk: "critical",
      reason_code: "HIGH_IMPACT_UNREVIEWED_PRODUCTION",
      domains: HIGH_IMPACT_DOMAINS,
      when_flags: ["unreviewed_production"],
    }),
    rule({
      id: "IN-HARMFUL-TESTING",
      description: "Jailbreak, cyber or dual-use testing without written testing authorization",
      stage: "input",
      decision: "deny",
      risk: "critical",
      reason_code: "UNAUTHORIZED_HARMFUL_TESTING",
      capabilities: ["jailbreak_testing", "cyber_testing", "dual_use_testing"],
      unless_flags: ["written_testing_authorization"],
    }),
    rule({
      id: "IN-HARMFUL-REQUEST",
      description: "Request for weapons or mass-harm instructions",
      stage: "input",
      decision: "deny",
      risk: "critical",
      reason_code: "HARMFUL_CAPABILITY_REQUEST",
      patterns: [
        "\\b(synthesi[sz]e|make|produce|weaponi[sz]e)\\b.{0,40}\\b(sarin|vx|nerve agent|ricin|anthrax|pipe bomb|explosive device)\\b",
        "\\bwrite (working )?(ransomware|a keylogger|malware)\\b",
      ],
    }),
    rule({
      id: "OUT-ASSURANCE-CLAIM",
      description: "Output makes a guarantee or certification claim that the work cannot substantiate",
      stage: "output",
      decision: "review",
      risk: "medium",
      reason_code: "UNSUPPORTED_ASSURANCE_CLAIM",
      patterns: [
        "\\bguarantee[sd]?\\b.{0,40}\\b(safe|secure|correct|accurate|compliant|unbiased)\\b",
        "\\b(certified|fully) compliant\\b",
        "\\b(NIST|ISO|SOC ?2|HIPAA|GDPR|FedRAMP|AI Act)[- ](compliant|certified)\\b",
      ],
      required_approvals: ["reviewer"],
    }),
  ] as Rule[],
};

const COMPILED: Record<string, RegExp[]> = Object.fromEntries(
  POLICY.rules.map((r) => [r.id, r.patterns.map((p) => new RegExp(p, "i"))]),
);

const DECISION_ORDER: Record<Decision, number> = { allow: 0, review: 1, deny: 2 };
const RISK_ORDER: Record<Risk, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

interface GuardResult {
  decision: Decision;
  risk: Risk;
  reason_codes: string[];
  matched_rules: string[];
  required_approvals: string[];
}

function union(a: string[], b: string[]): string[] {
  const out = [...a];
  for (const x of b) if (!out.includes(x)) out.push(x);
  return out;
}

/** Combine two results; never less strict than either. */
function escalate(prev: GuardResult, next: GuardResult): GuardResult {
  return {
    decision: DECISION_ORDER[prev.decision] >= DECISION_ORDER[next.decision] ? prev.decision : next.decision,
    risk: RISK_ORDER[prev.risk] >= RISK_ORDER[next.risk] ? prev.risk : next.risk,
    reason_codes: union(prev.reason_codes, next.reason_codes),
    matched_rules: union(prev.matched_rules, next.matched_rules),
    required_approvals: union(prev.required_approvals, next.required_approvals),
  };
}

function emptyResult(): GuardResult {
  return { decision: "allow", risk: "none", reason_codes: [], matched_rules: [], required_approvals: [] };
}

/** Same semantics as SafetyGuard.evaluate in safety_guard.py. */
function evaluatePolicy(
  text: string,
  stage: "input" | "output",
  capabilities: Set<string>,
  domain: string | null,
  flags: Set<string>,
): GuardResult {
  let result = emptyResult();
  for (const r of POLICY.rules) {
    if (r.stage !== stage && r.stage !== "both") continue;
    if (r.when_flags.length && !r.when_flags.every((f) => flags.has(f))) continue;
    if (r.unless_flags.length && r.unless_flags.every((f) => flags.has(f))) continue;
    let hit = COMPILED[r.id].some((re) => re.test(text || ""));
    if (!hit && r.capabilities.some((c) => capabilities.has(c))) hit = true;
    if (!hit && domain && r.domains.includes(domain)) hit = true;
    if (!hit) continue;
    result = escalate(result, {
      decision: r.decision,
      risk: r.risk,
      reason_codes: [r.reason_code],
      matched_rules: [r.id],
      required_approvals: r.required_approvals,
    });
  }
  return result;
}

// ---------------------------------------------------------------------------
// Canonical JSON (byte-identical to Python json.dumps(sort_keys=True,
// separators=(",", ":")) with the default ensure_ascii=True) and hashing.
// ---------------------------------------------------------------------------

function asciiEscape(s: string): string {
  return s.replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

function canonJson(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    if (!Number.isInteger(v)) throw new Error("non-integer number");
    return String(v);
  }
  if (typeof v === "string") return asciiEscape(JSON.stringify(v));
  if (Array.isArray(v)) return "[" + v.map(canonJson).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    return "{" + keys.map((k) => asciiEscape(JSON.stringify(k)) + ":" + canonJson(o[k])).join(",") + "}";
  }
  throw new Error("unsupported value");
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(s: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

let policyHashCache: string | null = null;
export async function policySha256(): Promise<string> {
  if (!policyHashCache) policyHashCache = await sha256Hex(canonJson(POLICY));
  return policyHashCache;
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> | null {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------------------------------------------------------------------------
// Trust store and signed grants (port of oct28 v22/signing.py and v22/grants.py).
// ---------------------------------------------------------------------------

const KINDS = ["amendment", "identity", "grant"];

interface TrustEntry {
  key: CryptoKey | null; // null when the runtime cannot import Ed25519: verification then fails closed
  kinds: Set<string>;
}

interface TrustStore {
  entries: Map<string, TrustEntry>;
  status: "none_configured" | "configured" | "invalid_config";
}

/**
 * RFAI_TRUSTED_SIGNERS: JSON list of {"name", "public_key_hex" (32-byte raw Ed25519), "kinds"}.
 * Unset -> empty store. Anything malformed -> empty store (fail closed), never a partial one.
 */
export async function loadTrustStore(raw: string | undefined): Promise<TrustStore> {
  const entries = new Map<string, TrustEntry>();
  if (!raw || !raw.trim()) return { entries, status: "none_configured" };
  try {
    const list = JSON.parse(raw);
    if (!Array.isArray(list) || list.length === 0) throw new Error("not a list");
    for (const s of list) {
      if (!s || typeof s.name !== "string" || !s.name) throw new Error("bad name");
      const pub = hexToBytes(s.public_key_hex);
      if (!pub || pub.length !== 32) throw new Error("bad key");
      if (!Array.isArray(s.kinds) || !s.kinds.length || s.kinds.some((k: unknown) => !KINDS.includes(k as string))) {
        throw new Error("bad kinds");
      }
      let key: CryptoKey | null = null;
      try {
        key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
      } catch {
        key = null;
      }
      entries.set(s.name, { key, kinds: new Set(s.kinds) });
    }
    return { entries, status: "configured" };
  } catch {
    return { entries: new Map(), status: "invalid_config" };
  }
}

interface GrantLog {
  id: string | null;
  ok: boolean;
  why: string;
}

async function verifyRecord(
  trust: TrustStore,
  rec: any,
  kind: string,
  scope: string,
  now: number,
): Promise<[boolean, string]> {
  try {
    if (!rec || typeof rec !== "object" || Array.isArray(rec) || !rec.sig) return [false, "unsigned"];
    const ent = trust.entries.get(rec.issuer);
    if (!ent) return [false, "untrusted issuer"];
    const sig = hexToBytes(String(rec.sig));
    if (!sig || sig.length !== 64 || !ent.key) return [false, "bad signature"];
    const body: Record<string, unknown> = {};
    for (const k of Object.keys(rec)) if (k !== "sig") body[k] = rec[k];
    const msg = new TextEncoder().encode(canonJson(body));
    let good = false;
    try {
      good = await crypto.subtle.verify({ name: "Ed25519" }, ent.key, sig, msg);
    } catch {
      good = false;
    }
    if (!good) return [false, "bad signature"];
    if (rec.kind !== kind) return [false, "wrong kind"];
    if (!ent.kinds.has(kind)) return [false, "issuer not allowed to sign this kind"];
    if (rec.scope !== scope) return [false, "wrong scope"];
    const from = Number(rec.valid_from);
    const to = Number(rec.valid_to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || !(from <= now && now <= to)) {
      return [false, "not in force at this time"];
    }
    if (!rec.claims || typeof rec.claims !== "object" || Array.isArray(rec.claims)) return [false, "no claims"];
    return [true, "ok"];
  } catch {
    return [false, "malformed"];
  }
}

/** Verified grants for this scope, minus any revoked by another verified grant. */
async function validGrants(
  trust: TrustStore,
  records: any[],
  scope: string,
  now: number,
): Promise<{ valid: any[]; log: GrantLog[] }> {
  const log: GrantLog[] = [];
  const ok: any[] = [];
  for (const r of records) {
    const [good, why] = await verifyRecord(trust, r, "grant", scope, now);
    log.push({ id: r && typeof r.id === "string" ? r.id.slice(0, 80) : null, ok: good, why });
    if (good) ok.push(r);
  }
  const revoked = new Set<string>();
  for (const r of ok) {
    if (Array.isArray(r.revokes)) for (const x of r.revokes) if (typeof x === "string") revoked.add(x);
  }
  const valid: any[] = [];
  for (const r of ok) {
    if (revoked.has(r.id)) log.push({ id: r.id, ok: false, why: "revoked" });
    else if (Array.isArray(r.revokes) && r.revokes.length && Object.keys(r.claims).length === 0) continue;
    else valid.push(r);
  }
  return { valid, log };
}

// Keyword guess of a high-impact domain, mapped onto the policy's domain names.
const HIGH_IMPACT_HINTS: [string, RegExp][] = [
  ["employment", /\b(hire|hiring|job applicants?|candidates?|resumes?|CVs?|promotion|fire|layoffs?)\b/i],
  ["credit", /\b(loan|credit score|creditworth\w*|mortgage|lend(?:ing)?)\b/i],
  ["essential_services", /\b(tenant|rental application|eviction|landlord)\b/i],
  ["health", /\b(diagnos\w+|patients?|treatment plan|prescri\w+)\b/i],
  ["justice", /\b(sentenc\w+|parole|bail|custody|asylum)\b/i],
  ["education", /\b(admissions?|grade the students|expel\w*)\b/i],
];

function guessDomain(text: string): string | null {
  for (const [d, re] of HIGH_IMPACT_HINTS) if (re.test(text || "")) return d;
  return null;
}

function stringList(v: unknown, max = MAX_LIST_ITEMS): string[] {
  return Array.isArray(v)
    ? v.filter((x) => typeof x === "string").slice(0, max).map((x) => (x as string).slice(0, 64))
    : [];
}

interface Screen {
  result: GuardResult;
  audit: Record<string, unknown>;
  domain: string | null;
  flags: Set<string>;
  capabilities: Set<string>;
}

async function inputScreen(task: string, callerContext: any, trust: TrustStore, now: number): Promise<Screen> {
  const jobId = typeof callerContext?.job_id === "string" ? callerContext.job_id.slice(0, MAX_JOB_ID_CHARS) : "";
  const claimedFlags = stringList(callerContext?.flags);
  const claimedDomain = typeof callerContext?.domain === "string" ? callerContext.domain.slice(0, 64) : null;
  const capabilities = new Set(stringList(callerContext?.capabilities));
  const rawGrants = Array.isArray(callerContext?.grants) ? callerContext.grants.slice(0, MAX_GRANTS) : [];

  const { valid, log } = jobId
    ? await validGrants(trust, rawGrants, jobId, now)
    : { valid: [] as any[], log: rawGrants.map(() => ({ id: null, ok: false, why: "no job_id to scope the grant" })) };

  const flags = new Set<string>();
  const domains = new Set<string>();
  for (const g of valid) {
    for (const f of stringList(g.claims.flags)) flags.add(f);
    if (typeof g.claims.domain === "string") domains.add(g.claims.domain);
  }

  const audit: Record<string, unknown> = {
    trust_store: trust.status,
    trusted_signers: trust.entries.size,
    job_id: jobId || null,
    grants_received: rawGrants.length,
    grant_log: log,
    verified_flags: [...flags].sort(),
    claimed_flags: claimedFlags,
    ignored_claimed_flags: claimedFlags.filter((f) => !flags.has(f)),
    claimed_domain: claimedDomain,
    declared_capabilities: [...capabilities].sort(),
  };

  let domain: string | null = null;
  let conflict = false;
  if (domains.size > 1) {
    conflict = true;
    audit.domain_conflict = [...domains].sort();
  } else if (domains.size === 1) {
    domain = [...domains][0];
    audit.domain_source = "signed grant";
  } else if (claimedDomain && HIGH_IMPACT_DOMAINS.includes(claimedDomain)) {
    domain = claimedDomain; // a declared high-impact domain only adds strictness
    audit.domain_source = "declared high-impact (adds strictness only)";
  } else {
    domain = guessDomain(task);
    audit.domain_source = domain ? "keyword guess" : "none";
  }
  // A guessed or declared high-impact domain still counts even if a grant names a milder one.
  const guessed = guessDomain(task);
  if (!conflict && guessed && domain !== guessed && audit.domain_source === "signed grant" &&
      !HIGH_IMPACT_DOMAINS.includes(domain ?? "")) {
    audit.domain_override = { granted: domain, guessed };
    domain = guessed;
  }
  audit.domain = conflict ? "conflict" : domain;

  // Live endpoint = production. Unless a verified grant says a human review is in place,
  // the policy's own unreviewed-production rule applies.
  const policyFlags = new Set(flags);
  if (!flags.has("human_review_in_place")) policyFlags.add("unreviewed_production");
  else policyFlags.delete("unreviewed_production");

  let result = evaluatePolicy(task, "input", capabilities, conflict ? null : domain, policyFlags);
  if (conflict) {
    result = escalate(result, {
      decision: "review",
      risk: "high",
      reason_codes: ["GRANT_DOMAIN_CONFLICT"],
      matched_rules: ["V22-DOMAIN-CONFLICT"],
      required_approvals: ["risk_owner"],
    });
  }
  return { result, audit, domain, flags: policyFlags, capabilities };
}

// ---------------------------------------------------------------------------
// Council (unchanged prompts and parsing from v2.0.1 port).
// ---------------------------------------------------------------------------

function env(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.trim() ? v.trim() : fallback;
}

async function callModel(
  model: string,
  prompt: string,
  maxTokens: number,
  timeoutMs: number,
): Promise<string> {
  const key = process.env.RFAI_LLM_KEY;
  if (!key) throw new UpstreamError("model gateway not configured");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(GATEWAY_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": key,
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!res.ok) {
      // Do not forward upstream bodies: they could carry account details.
      throw new UpstreamError(`model gateway returned ${res.status}`);
    }
    const data: any = await res.json();
    const parts: any[] = Array.isArray(data?.content) ? data.content : [];
    const text = parts
      .filter((p) => p && p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("");
    if (!text.trim()) throw new UpstreamError("model returned no text");
    return text;
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if ((err as any)?.name === "AbortError") {
      throw new UpstreamError("model call timed out");
    }
    throw new UpstreamError("model call failed");
  } finally {
    clearTimeout(timer);
  }
}

/** Pull the first {...} block out of a model reply and parse it. */
function extractJson(text: string): any | null {
  const cleaned = text.replace(/```(?:json)?/gi, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return null;
  }
}

function asStringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, 10) : [];
}

async function architect(
  task: string,
  protocol: Protocol,
  model: string,
): Promise<{ plan: ArchitectPlan; draft: string }> {
  const prompt =
    `You are the Architect in the RFAI-PRIME council.\n` +
    `Protocol: ${protocol}\n` +
    `Task: ${task}\n\n` +
    "Respond with a JSON object matching:\n" +
    '{"summary": "...", "approach": "...", "concerns": ["..."]}\n' +
    "Then output a line containing only ---DRAFT--- followed by your full draft response. " +
    "Keep the draft under 450 words.";
  const text = await callModel(model, prompt, 900, ARCHITECT_TIMEOUT_MS);
  let planPart = text;
  let draft = text;
  const idx = text.indexOf("---DRAFT---");
  if (idx !== -1) {
    planPart = text.slice(0, idx);
    draft = text.slice(idx + "---DRAFT---".length);
  }
  const parsed = extractJson(planPart);
  const plan: ArchitectPlan =
    parsed && typeof parsed.summary === "string"
      ? {
          summary: parsed.summary,
          approach: typeof parsed.approach === "string" ? parsed.approach : "",
          concerns: asStringList(parsed.concerns),
        }
      : { summary: task.slice(0, 200), approach: planPart.trim().slice(0, 1000), concerns: [] };
  return { plan, draft: draft.trim() };
}

async function critic(
  task: string,
  draft: string,
  perspective: string,
  model: string,
): Promise<CriticFeedback> {
  const title = perspective.charAt(0).toUpperCase() + perspective.slice(1);
  const prompt =
    `You are the ${title} Critic in the RFAI-PRIME council.\n` +
    `Task: ${task}\n\n` +
    `Draft response:\n${draft}\n\n` +
    `Evaluate strictly from a ${perspective} perspective. ` +
    "Respond with only a JSON object, feedback under 60 words:\n" +
    `{"perspective": "${perspective}", "score": <1-10>, ` +
    '"feedback": "...", "suggestions": ["..."]}';
  try {
    const text = await callModel(model, prompt, 300, CRITIC_TIMEOUT_MS);
    const parsed = extractJson(text);
    const score = Number(parsed?.score);
    if (parsed && Number.isFinite(score)) {
      return {
        perspective,
        score: Math.min(10, Math.max(1, Math.round(score))),
        feedback: typeof parsed.feedback === "string" ? parsed.feedback : "",
        suggestions: asStringList(parsed.suggestions),
      };
    }
    // Same fallback as the Python runtime: neutral score, raw text as feedback.
    return { perspective, score: 5, feedback: text.trim().slice(0, 800), suggestions: [] };
  } catch {
    return { perspective, score: 5, feedback: "critic unavailable", suggestions: [] };
  }
}

async function integrator(
  task: string,
  draft: string,
  feedbacks: CriticFeedback[],
  model: string,
): Promise<string> {
  const block = feedbacks
    .map(
      (f) =>
        `- [${f.perspective.toUpperCase()}] score=${f.score}: ${f.feedback}\n` +
        `  suggestions: ${JSON.stringify(f.suggestions)}`,
    )
    .join("\n");
  const prompt =
    `You are the Integrator in the RFAI-PRIME council.\n` +
    `Task: ${task}\n\n` +
    `Architect draft:\n${draft}\n\n` +
    `Council feedback:\n${block}\n\n` +
    "Produce the final, polished response that incorporates all valid feedback. " +
    "Keep it under 600 words.";
  return (await callModel(model, prompt, 1100, INTEGRATOR_TIMEOUT_MS)).trim();
}

function bad(message: string, status = 400, extra: Record<string, unknown> = {}): Response {
  return Response.json({ error: message, ...extra }, { status });
}

async function governanceHeader(): Promise<Record<string, unknown>> {
  return {
    endpoint_version: ENDPOINT_VERSION,
    policy_id: POLICY.policy_id,
    policy_version: POLICY.version,
    policy_sha256: await policySha256(),
  };
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return bad("POST a JSON body: {\"task\": \"...\", \"protocol\": \"plan\" | \"execute\"}", 405);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return bad("Body must be JSON.");
  }

  const task = typeof body?.task === "string" ? body.task.trim() : "";
  if (!task) return bad("Field 'task' is required.");
  if (task.length > MAX_TASK_CHARS) {
    return bad(`Field 'task' must be at most ${MAX_TASK_CHARS} characters.`);
  }
  const protocol: Protocol = body?.protocol === "execute" ? "execute" : "plan";
  const callerContext = body?.context && typeof body.context === "object" && !Array.isArray(body.context) ? body.context : {};

  const now = Math.floor(Date.now() / 1000);
  const trust = await loadTrustStore(process.env.RFAI_TRUSTED_SIGNERS);
  const header = await governanceHeader();

  // 1. Input screen. Deny and review both stop before any model call.
  const screen = await inputScreen(task, callerContext, trust, now);
  const inputGov = {
    ...header,
    input: { ...screen.result },
    audit: screen.audit,
  };
  if (screen.result.decision === "deny") {
    return bad("Refused by the RFAI governance screen. You were not charged.", 403, { governance: inputGov });
  }
  if (screen.result.decision === "review") {
    return bad(
      "Withheld: the RFAI governance screen requires human review for this request, and this endpoint has no reviewer. You were not charged.",
      422,
      { governance: inputGov },
    );
  }

  const models = {
    architect: env("RFAI_ARCHITECT_MODEL", DEFAULT_ARCHITECT_MODEL),
    critic: env("RFAI_CRITIC_MODEL", DEFAULT_CRITIC_MODEL),
    integrator: env("RFAI_INTEGRATOR_MODEL", DEFAULT_INTEGRATOR_MODEL),
  };

  const started = Date.now();
  try {
    // 2. Council.
    const { plan, draft } = await architect(task, protocol, models.architect);
    const feedbacks = await Promise.all(
      CRITIC_PERSPECTIVES.map((p) => critic(task, draft, p, models.critic)),
    );
    const avg = feedbacks.reduce((s, f) => s + f.score, 0) / feedbacks.length;
    const live = feedbacks.filter((f) => f.feedback !== "critic unavailable").length;
    if (live === 0) throw new UpstreamError("no critic responded");

    const finalText = await integrator(task, draft, feedbacks, models.integrator);

    const trace = {
      task,
      protocol,
      architect_plan: plan,
      critic_feedbacks: feedbacks,
      average_critic_score: Math.round(avg * 100) / 100,
      passed_early_exit_threshold: avg >= EARLY_EXIT_SCORE,
      revisions: 0,
      models,
      elapsed_ms: Date.now() - started,
    };

    // 3. Output screen over everything that would be returned except the caller's own task.
    const outText = [
      finalText,
      draft,
      plan.summary,
      plan.approach,
      ...plan.concerns,
      ...feedbacks.flatMap((f) => [f.feedback, ...f.suggestions]),
    ].join("\n");
    const out = evaluatePolicy(outText, "output", new Set(), null, screen.flags);
    if (out.decision !== "allow") {
      return bad(
        "Withheld: the council's output did not pass the RFAI governance screen. You were not charged.",
        422,
        {
          governance: {
            ...inputGov,
            output: { ...out, withheld_sha256: await sha256Hex(outText), withheld_chars: outText.length },
          },
        },
      );
    }

    return Response.json({
      final_text: finalText,
      trace,
      governance: { ...inputGov, output: { ...out } },
    });
  } catch (err) {
    const msg = err instanceof UpstreamError ? err.message : "council failed";
    // 5xx: x402 Cloud does not settle payment, so the caller is not charged.
    return bad(`RFAI council could not finish: ${msg}. You were not charged.`, 502, { governance: inputGov });
  }
}
