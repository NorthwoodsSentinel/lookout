// Lookout — identity-lensed search through your daemon profile
// Brave Search API → Claude re-ranking → daemon-filtered results
// v0.2 adds /discover — find values-aligned humans on GitHub

interface Env {
  BRAVE_SEARCH_KEY: string;
  ANTHROPIC_API_KEY: string;
  LOOKOUT_API_KEY: string;
  GITHUB_TOKEN: string;
  ENVIRONMENT: string;
  // v0.3 — scheduled discover state + notifications
  LOOKOUT_KV: KVNamespace;
  NOTIFY_EMAIL_TO?: string;        // optional — destination address
  NOTIFY_EMAIL_FROM?: string;      // optional — must be a verified address on your CF zone
  MYCELIA_API_BASE?: string;       // optional — fleet event distribution
  MYCELIA_KEY_LOOKOUT?: string;    // optional — bearer for the Mycelia POST
  // v0.4 — daemon-fed lens + ntfy alerts
  DAEMON_URL?: string;             // optional — personal-daemon MCP endpoint; enables the live lens
  DAEMON?: Fetcher;                // optional — service binding to the daemon worker (required when
                                   // both live on workers.dev: worker→worker fetch of *.workers.dev is blocked)
  NTFY_TOPIC?: string;             // optional — ntfy.sh topic for severity-routed alerts
  // v0.5.1 — identity layer before the values layer (self-recognition)
  SELF_GITHUB_LOGINS?: string;     // optional — comma-separated operator logins/orgs; default "NorthwoodsSentinel"
}

// ── Identity layer (v0.5.1, extended v0.6) ───────────────────
// The operator is the positive control for the values lens, never a candidate.
// Deterministic check, runs BEFORE any LLM sees a login (CoE 2026-07-29:
// "identity recognition should not depend on an LLM"). Prevents self-alerts
// and self-addressed intros; operator-owned anchors still surface their
// OUTSIDE contributors. v0.6 adds the known-contact set: people who graduated
// out of discovery because a relationship already exists.
import { parseSelfLogins, isSelfLogin, classify, shouldAlert, calibrationDrift, GRADUATING_OUTCOMES } from "./identity";
import type { ScoreTriple, Classification } from "./identity";

function isSelf(login: string, env: Env): boolean {
  return isSelfLogin(login, parseSelfLogins(env.SELF_GITHUB_LOGINS));
}

const KNOWN_CONTACTS_KEY = "contacts:known";

async function getKnownContacts(kv: KVNamespace): Promise<Set<string>> {
  try {
    const raw = await kv.get(KNOWN_CONTACTS_KEY);
    if (!raw) return new Set();
    const obj = JSON.parse(raw) as Record<string, { since: string; source: string }>;
    return new Set(Object.keys(obj).map((k) => k.toLowerCase()));
  } catch { return new Set(); }
}

async function addKnownContact(kv: KVNamespace, login: string, source: string): Promise<void> {
  let obj: Record<string, { since: string; source: string }> = {};
  try { obj = JSON.parse((await kv.get(KNOWN_CONTACTS_KEY)) ?? "{}"); } catch { /* fresh */ }
  const key = login.toLowerCase();
  if (!obj[key]) obj[key] = { since: new Date().toISOString(), source };
  await kv.put(KNOWN_CONTACTS_KEY, JSON.stringify(obj));
}

// ── Auth ──────────────────────────────────────────────────────

function requireAuth(request: Request, env: Env): Response | null {
  const headerKey = request.headers.get('Authorization')?.replace('Bearer ', '');
  const paramKey = new URL(request.url).searchParams.get('key');
  const key = headerKey || paramKey;

  if (!env.LOOKOUT_API_KEY || !key || key !== env.LOOKOUT_API_KEY) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS },
    });
  }
  return null;
}

// "Knowledge without mileage equals bullshit" — Henry Rollins
const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; script-src 'unsafe-inline'; connect-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'private, no-store',
};

// ── IP-based Rate Limiting ──────────────────────────────────
// search: 10 req/min/IP — cheap, frequent
// discover: 2 req/min/IP — expensive (many GitHub calls + a big Claude call)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const discoverRateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 10) return false;
  entry.count++;
  return true;
}

function checkDiscoverRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = discoverRateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    discoverRateLimitMap.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 2) return false;
  entry.count++;
  return true;
}

// Periodic cleanup — drop expired entries to prevent memory leak
function cleanupRateLimits() {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetAt) rateLimitMap.delete(ip);
  }
  for (const [ip, entry] of discoverRateLimitMap) {
    if (now > entry.resetAt) discoverRateLimitMap.delete(ip);
  }
}

function secureHtmlResponse(body: string, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(body, { ...init, headers });
}

function secureJsonResponse(data: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'application/json');
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(JSON.stringify(data), { ...init, headers });
}

// ── Daemon Profile (inline for MVP) ────────────────────────────

// ── EDIT THIS ── Your daemon profile controls how results are filtered.
// See: https://danielmiessler.com/blog/launching-daemon-personal-api
const DAEMON_PROFILE = `Name: Rob Chuvala
Role: Cybersecurity consultant, 20 years. COE strategy, AI integration, mid-market focus.
Expertise: Security operations, threat intelligence, vendor evaluation, AI infrastructure, personal AI systems.
Preferences: Practical over theoretical. Code over slides. Primary sources over summaries.
Already knows: SIEM/SOAR, endpoint security, network security, cloud security fundamentals, AI/ML basics.
Skip: Marketing content, vendor press releases, beginner tutorials, listicles, AI hype pieces.
Prefer: GitHub repos, research papers, Hacker News, security conference talks, RFC documents, practitioner blogs.`;

// ── v0.4: Lens Snapshot — the declared, versioned distillation of the daemon ──
// The daemon serves get_all only (its no-summarizer doctrine refuses slices).
// So the lens is built ONCE DAILY as a declared transformation: fetched raw,
// distilled by one Claude call into fixed layers, content-hashed, and the
// resulting lens_version is stamped on every result it ever scores.
// Fallback ladder: fresh KV lens → stale KV lens (flagged) → legacy inline
// profile below (flagged "legacy-fallback"). Search never dies with the daemon.

interface LensSnapshot {
  version: string;        // sha256[0..12] of layer content + build date
  fetched_at: string;     // ISO — when daemon get_all was pulled
  source_bytes: number;   // size of raw daemon context distilled
  identity: string;
  current_missions: string;
  preferences: string;
  known_domains: string;
  exclusions: string;
  // v0.5 — values lens (for /discover), distilled from the same daemon pull
  values_signals: string;       // what to look FOR in people
  values_anti_signals: string;  // what to penalize
  connection_intent: string;    // why they're looking — what the community is FOR
  provenance: string;     // daemon URL + distillation model
}

const LENS_KV_KEY = "lens:snapshot";
const LENS_FRESH_MS = 26 * 60 * 60 * 1000; // fresh if under ~26h (daily cron + slack)

async function sha256Short(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}

async function fetchDaemonAll(env: Env): Promise<string | null> {
  try {
    const init: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_all", arguments: {} } }),
    };
    // Service binding when available (mandatory on workers.dev↔workers.dev); public URL otherwise
    const res = env.DAEMON
      ? await env.DAEMON.fetch(env.DAEMON_URL ?? "https://daemon/", init)
      : await fetch(env.DAEMON_URL!, init);
    if (!res.ok) return null;
    const data = (await res.json()) as { result?: { content?: Array<{ type: string; text: string }> } };
    const text = data.result?.content?.map((c) => c.text).join("\n") ?? "";
    return text.length > 200 ? text : null; // refuse to build a lens from an error stub
  } catch {
    return null;
  }
}

async function distillLens(raw: string, apiKey: string): Promise<Omit<LensSnapshot, "version" | "fetched_at" | "source_bytes" | "provenance"> | null> {
  const prompt = `Distill this person's full daemon context into a search lens and a values lens. Output ONLY valid JSON with exactly these eight string fields, each a compact plain-text block under 120 words, using the subject's own words wherever possible. Do not add interpretation or new facts. If the context genuinely lacks material for a field, write "none stated".

{"identity": "who they are, role, background", "current_missions": "what they are actively building and pursuing NOW", "preferences": "format and source preferences for information", "known_domains": "what they already know deeply (results below this level are noise)", "exclusions": "everything the context marks as skip, avoid, banned, or unwanted", "values_signals": "what this person values in OTHER PEOPLE and their work — the qualities of someone they would want to build community with", "values_anti_signals": "qualities, postures, and language in other people that this person would walk away from", "connection_intent": "WHY they are looking for people — what the community or collaboration is for"}

DAEMON CONTEXT:
${raw}`;
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 1200, messages: [{ role: "user", content: prompt }] }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { content: Array<{ type: string; text: string }> };
    const text = (data.content?.[0]?.text ?? "").replace(/```json?\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(text) as Record<string, string>;
    const need = ["identity", "current_missions", "preferences", "known_domains", "exclusions"];
    if (!need.every((k) => typeof parsed[k] === "string" && parsed[k].length > 0)) return null;
    const opt = (k: string) => (typeof parsed[k] === "string" && parsed[k].length > 0 ? parsed[k] : "none stated");
    return {
      identity: parsed.identity,
      current_missions: parsed.current_missions,
      preferences: parsed.preferences,
      known_domains: parsed.known_domains,
      exclusions: parsed.exclusions,
      values_signals: opt("values_signals"),
      values_anti_signals: opt("values_anti_signals"),
      connection_intent: opt("connection_intent"),
    };
  } catch {
    return null;
  }
}

async function refreshLens(env: Env): Promise<LensSnapshot | null> {
  const r = await refreshLensDetailed(env);
  return r.lens;
}

async function refreshLensDetailed(env: Env): Promise<{ lens: LensSnapshot | null; fail?: string }> {
  if (!env.DAEMON_URL && !env.DAEMON) return { lens: null, fail: "DAEMON_URL unset" };
  const raw = await fetchDaemonAll(env);
  if (!raw) return { lens: null, fail: "daemon fetch failed or returned <200 bytes" };
  const layers = await distillLens(raw, env.ANTHROPIC_API_KEY);
  if (!layers) return { lens: null, fail: `distillation failed (raw ${raw.length}b fetched ok)` };
  const lens = await buildLensFromLayers(env, raw, layers);
  return { lens };
}

async function buildLensFromLayers(env: Env, raw: string, layers: Omit<LensSnapshot, "version" | "fetched_at" | "source_bytes" | "provenance">): Promise<LensSnapshot> {
  const now = new Date().toISOString();
  const lens: LensSnapshot = {
    ...layers,
    version: `${await sha256Short(JSON.stringify(layers))}-${now.slice(0, 10)}`,
    fetched_at: now,
    source_bytes: raw.length,
    provenance: `${env.DAEMON_URL} get_all → claude-sonnet-4-6 distillation`,
  };
  await env.LOOKOUT_KV.put(LENS_KV_KEY, JSON.stringify(lens));
  return lens;
}

interface ActiveLens { text: string; version: string; state: "fresh" | "stale" | "legacy-fallback" }

async function getLens(env: Env): Promise<ActiveLens> {
  try {
    const raw = await env.LOOKOUT_KV.get(LENS_KV_KEY);
    if (raw) {
      const lens = JSON.parse(raw) as LensSnapshot;
      const age = Date.now() - Date.parse(lens.fetched_at);
      const text = [
        `IDENTITY: ${lens.identity}`,
        `CURRENT MISSIONS (weight these heavily — this is what matters NOW): ${lens.current_missions}`,
        `PREFERENCES: ${lens.preferences}`,
        `ALREADY KNOWS DEEPLY (results at or below this level are noise): ${lens.known_domains}`,
        `EXCLUDE (hard skips): ${lens.exclusions}`,
      ].join("\n");
      return { text, version: lens.version, state: age < LENS_FRESH_MS ? "fresh" : "stale" };
    }
  } catch { /* fall through to legacy */ }
  return { text: DAEMON_PROFILE, version: "legacy-2026-03", state: "legacy-fallback" };
}

// ── v0.5: Values lens — the /discover judge, daemon-fed with the same contract ──
// The SIGNALS come from the daemon distillation; the output contract and the
// operational anti-signal floor stay code-owned. Fallback: legacy inline profile.

interface ActiveValuesLens { text: string; version: string; state: "fresh" | "stale" | "legacy-fallback" }

async function getValuesLens(env: Env): Promise<ActiveValuesLens> {
  try {
    const raw = await env.LOOKOUT_KV.get(LENS_KV_KEY);
    if (raw) {
      const lens = JSON.parse(raw) as LensSnapshot;
      if (lens.values_signals && lens.values_signals !== "none stated") {
        const age = Date.now() - Date.parse(lens.fetched_at);
        const anti = lens.values_anti_signals !== "none stated" ? lens.values_anti_signals : "Vendor-pitch posture, platform evangelism, output-free self-promotion";
        const intent = lens.connection_intent !== "none stated" ? `WHY THEY ARE LOOKING (what the community is for):\n${lens.connection_intent}\n\n` : "";
        const text = `${intent}VALUES SIGNALS (positive — score high if present):\n${lens.values_signals}\n\nANTI-SIGNALS (negative — penalize):\n${anti}\n\nOperational anti-signal floor (always applies): marketing language ("comprehensive", "utilize", "leverage", "robust", "seamless", "next-generation"), "Founder & CEO" puffery with no substantive output, single-repo accounts with no prior work, follower count without corresponding output.`;
        return { text, version: lens.version, state: age < LENS_FRESH_MS ? "fresh" : "stale" };
      }
    }
  } catch { /* fall through to legacy */ }
  return { text: VALUES_PROFILE, version: "legacy-2026-03", state: "legacy-fallback" };
}

// ── v0.4: ntfy notification (fleet alert surface; SessionStart relay reads the same topic) ──

async function notifyNtfy(env: Env, title: string, body: string, urgent: boolean): Promise<void> {
  if (!env.NTFY_TOPIC) return;
  await fetch(`https://ntfy.sh/${env.NTFY_TOPIC}`, {
    method: "POST",
    headers: { "Title": title.replace(/[^\x20-\x7E]/g, ""), "Priority": urgent ? "urgent" : "default", "Tags": "telescope" },
    body,
  }).catch(() => {});
}

// ── Values Profile (for /discover — human values-alignment filter) ──
const VALUES_PROFILE = `Rob is looking for values-aligned humans on GitHub to connect with.

VALUES SIGNALS (positive — score high if present):
- Substrate-first / sovereignty / anti-extraction posture
- Self-hosted, BYO, no-telemetry, no-surveillance language in repos and READMEs
- Personal infrastructure builders, not platform-AI consumers
- Working independents: musicians, mechanics, architects, writers, security practitioners
- Cooperative shape over corporate (mutual aid, open methodology, give-the-methodology-away)
- Edge / Cloudflare / Workers / Durable Objects / R2 / D1 fluency
- Memory and provenance as first-class concerns (loam-shaped, not RAG-as-marketing)
- Long-form personal essays in repos; README-as-manifesto register
- Open methodology, anti-platform, anti-engagement-farming
- Local-first / ATproto / IndieWeb / personal-AI / model-context-protocol contributors

ANTI-SIGNALS (negative — penalize):
- "Founder & CEO" puffery in bio with no substantive output
- "AI evangelist" or content-creator-to-passive-consumer framing
- Marketing language in README ("comprehensive", "transform", "unlock", "next-generation", "robust", "enterprise-grade", "seamless")
- Single-repo accounts with no substantive prior work
- Heavy follower-count without corresponding output
- Vendor-pitch-disguised-as-content patterns

FOR EACH CANDIDATE produce:
- values_score: 1-10 (10 = strongest match)
- values_notes: 2-3 sentences explaining the specific signals that landed (or anti-signals if low)
- suggested_intro: one short paragraph Rob could send (his voice: direct, no flourish, names what caught his eye, avoids banned words)
- reach_via: ordered list of contact paths visible from the GitHub profile (github / blog / twitter / email if public)

Only return candidates with values_score >= 6. Order by values_score descending.`;

// ── Types ──────────────────────────────────────────────────────

interface BraveResult {
  title: string;
  url: string;
  description: string;
}

interface BraveSearchResponse {
  web?: {
    results: BraveResult[];
  };
}

interface DaemonResult {
  title: string;
  url: string;
  snippet: string;
  daemon_score: number;
  daemon_note: string;
}

interface SearchResponse {
  query: string;
  results: DaemonResult[];
  daemon: string;
  lens_version?: string;   // v0.4 — which lens scored these results
  lens_state?: string;     // fresh | stale | legacy-fallback
  ts: string;
  error?: string;
}

// Discover types
interface DiscoverRequest {
  mode?: "adjacency";
  anchors?: string[];
  count?: number;
  per_anchor?: number;
}

interface Candidate {
  login: string;
  name: string | null;
  bio: string | null;
  location: string | null;
  html_url: string;
  blog: string | null;
  twitter_username: string | null;
  email: string | null;
  public_repos: number;
  followers: number;
  top_repos: Array<{ name: string; description: string | null; stars: number; topics: string[]; language: string | null }>;
  contributed_to: string[];
  source_kind?: "github" | "rss";   // v0.4 — rss candidates are authors/domains, not GH users
}

interface DiscoverResult {
  login: string;
  name: string | null;
  bio: string | null;
  html_url: string;
  values_score: number;                        // = public_values_alignment (kept for stored rows/readers)
  public_values_alignment?: number;            // v0.6 — canonical alignment score, 10 = strongest non-self match
  connection_actionability?: number | null;    // v0.6 — path-to-conversation score
  confidence: "low" | "medium" | "high";      // v0.4 — dossier-richness signal (= evidence_confidence)
  requires_human_review: true;                 // v0.4 — always true; intros are drafts
  source_kind: "github" | "rss";               // v0.4 — which anchor pipeline produced this
  values_notes: string;
  suggested_intro: string;
  reach_via: string[];
  contributed_to: string[];
}

interface DiscoverResponse {
  mode: string;
  total_candidates: number;
  results: DiscoverResult[];
  daemon: string;
  values_lens_version?: string;   // v0.5 — which values lens judged these candidates
  values_lens_state?: string;     // fresh | stale | legacy-fallback
  ts: string;
  error?: string;
}

// ── Brave Search ───────────────────────────────────────────────

async function braveSearch(query: string, count: number, apiKey: string): Promise<BraveResult[]> {
  const params = new URLSearchParams({ q: query, count: String(count) });
  const res = await fetch(`https://api.search.brave.com/res/v1/web/search?${params}`, {
    headers: {
      "Accept": "application/json",
      "Accept-Encoding": "gzip",
      "X-Subscription-Token": apiKey,
    },
  });

  if (!res.ok) {
    throw new Error(`Brave API ${res.status}: ${await res.text()}`);
  }

  const data = (await res.json()) as BraveSearchResponse;
  return data.web?.results ?? [];
}

// ── Claude Re-ranking ──────────────────────────────────────────

async function daemonRerank(
  query: string,
  results: BraveResult[],
  apiKey: string,
  lensText: string,
): Promise<DaemonResult[]> {
  const resultsBlock = results
    .map((r, i) => `[${i + 1}] ${r.title}\n    URL: ${r.url}\n    ${r.description}`)
    .join("\n\n");

  const prompt = `You are a daemon — a personalized search filter for a specific human. Your job is to re-rank search results based on how useful they are to THIS person, not to a generic user.

DAEMON PROFILE:
${lensText}

SEARCH QUERY: "${query}"

RAW SEARCH RESULTS:
${resultsBlock}

INSTRUCTIONS:
1. Score each result 1-10 for relevance to this specific person (not generic relevance)
2. Filter out anything below their expertise level or that is marketing fluff
3. Annotate each result with a one-line "why this matters to you" note
4. Re-order by daemon-adjusted relevance
5. Return the top 5

Return ONLY valid JSON — no markdown fences, no explanation. Use this exact format:
[
  {
    "index": 1,
    "daemon_score": 9,
    "daemon_note": "One line explaining why this matters to this person specifically"
  }
]

Where "index" is the original result number (1-based). Only include results worth showing (score >= 4). Order by daemon_score descending.`;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    throw new Error(`Claude API ${res.status}: ${await res.text()}`);
  }

  const data = (await res.json()) as {
    content: Array<{ type: string; text: string }>;
  };

  const text = data.content?.[0]?.text ?? "[]";

  // Parse Claude's JSON response
  let ranked: Array<{ index: number; daemon_score: number; daemon_note: string }>;
  try {
    ranked = JSON.parse(text);
  } catch {
    // If Claude wraps in markdown fences, strip them
    const cleaned = text.replace(/```json?\n?/g, "").replace(/```\n?/g, "").trim();
    ranked = JSON.parse(cleaned);
  }

  // Map back to full results
  return ranked
    .filter((r) => r.index >= 1 && r.index <= results.length)
    .map((r) => {
      const orig = results[r.index - 1];
      return {
        title: orig.title,
        url: orig.url,
        snippet: orig.description,
        daemon_score: r.daemon_score,
        daemon_note: r.daemon_note,
      };
    });
}

// ── GitHub API ─────────────────────────────────────────────────

const GH_BASE = "https://api.github.com";

function ghHeaders(token: string): Record<string, string> {
  return {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Authorization": `Bearer ${token}`,
    "User-Agent": "lookout-discover/0.2",
  };
}

interface GhContributor {
  login: string;
  type: string;
  contributions: number;
}

interface GhUser {
  login: string;
  name: string | null;
  bio: string | null;
  location: string | null;
  html_url: string;
  blog: string | null;
  twitter_username: string | null;
  email: string | null;
  public_repos: number;
  followers: number;
  type: string;
}

interface GhRepo {
  name: string;
  description: string | null;
  stargazers_count: number;
  topics: string[];
  language: string | null;
  fork: boolean;
}

// Validate "owner/repo" format to prevent SSRF-style path injection
function isValidRepoSlug(slug: string): boolean {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug) && slug.length <= 100;
}

function isValidLogin(login: string): boolean {
  return /^[A-Za-z0-9-]+$/.test(login) && login.length <= 39;
}

async function fetchContributors(repo: string, token: string, perPage = 30): Promise<string[]> {
  if (!isValidRepoSlug(repo)) return [];
  const res = await fetch(`${GH_BASE}/repos/${encodeURIComponent(repo.split("/")[0])}/${encodeURIComponent(repo.split("/")[1])}/contributors?per_page=${perPage}`, {
    headers: ghHeaders(token),
  });
  if (!res.ok) return [];
  const data = (await res.json()) as GhContributor[];
  return data
    .filter((c) => c.type === "User" && !c.login.includes("[bot]") && c.login !== "github-actions" && isValidLogin(c.login))
    .map((c) => c.login);
}

async function fetchUser(login: string, token: string): Promise<GhUser | null> {
  if (!isValidLogin(login)) return null;
  const res = await fetch(`${GH_BASE}/users/${encodeURIComponent(login)}`, { headers: ghHeaders(token) });
  if (!res.ok) return null;
  return (await res.json()) as GhUser;
}

async function fetchTopRepos(login: string, token: string, count = 5): Promise<GhRepo[]> {
  if (!isValidLogin(login)) return [];
  const res = await fetch(
    `${GH_BASE}/users/${encodeURIComponent(login)}/repos?type=owner&sort=updated&per_page=${count * 3}`,
    { headers: ghHeaders(token) },
  );
  if (!res.ok) return [];
  const all = (await res.json()) as GhRepo[];
  return all
    .filter((r) => !r.fork)
    .sort((a, b) => b.stargazers_count - a.stargazers_count)
    .slice(0, count);
}

async function buildCandidate(
  login: string,
  anchorRepo: string,
  token: string,
): Promise<Candidate | null> {
  const user = await fetchUser(login, token);
  if (!user || user.type !== "User") return null;

  const repos = await fetchTopRepos(login, token, 5);

  return {
    login: user.login,
    name: user.name,
    bio: user.bio,
    location: user.location,
    html_url: user.html_url,
    blog: user.blog,
    twitter_username: user.twitter_username,
    email: user.email,
    public_repos: user.public_repos,
    followers: user.followers,
    top_repos: repos.map((r) => ({
      name: r.name,
      description: r.description,
      stars: r.stargazers_count,
      topics: r.topics,
      language: r.language,
    })),
    contributed_to: [anchorRepo],
  };
}

function dossier(c: Candidate): string {
  const topRepoLines = c.top_repos
    .map((r) => {
      const topics = r.topics.length > 0 ? ` [${r.topics.slice(0, 5).join(", ")}]` : "";
      const lang = r.language ? ` (${r.language})` : "";
      const desc = r.description ? ` — ${r.description.slice(0, 100)}` : "";
      return `  - ${r.name} ★${r.stars}${lang}${topics}${desc}`;
    })
    .join("\n");

  const contacts: string[] = [];
  if (c.email) contacts.push(`email:${c.email}`);
  if (c.blog) contacts.push(`blog:${c.blog}`);
  if (c.twitter_username) contacts.push(`twitter:@${c.twitter_username}`);

  return [
    `@${c.login}${c.name ? ` (${c.name})` : ""}`,
    `  url: ${c.html_url}`,
    c.bio ? `  bio: ${c.bio}` : null,
    c.location ? `  location: ${c.location}` : null,
    `  public_repos: ${c.public_repos}, followers: ${c.followers}`,
    `  showed up in: ${c.contributed_to.join(", ")}`,
    contacts.length > 0 ? `  contacts: ${contacts.join(" | ")}` : null,
    topRepoLines ? `  top repos:\n${topRepoLines}` : null,
  ]
    .filter((l) => l !== null)
    .join("\n");
}

// ── Values Re-ranking via Claude ───────────────────────────────

async function valuesRerank(
  candidates: Candidate[],
  apiKey: string,
  valuesText: string,
  opts: { calibration?: boolean } = {},
): Promise<DiscoverResult[]> {
  if (candidates.length === 0) return [];

  const block = candidates.map((c, i) => `[${i + 1}]\n${dossier(c)}`).join("\n\n");

  // Calibration mode scores the OPERATOR's own profile as the lens's positive
  // control — the self-identity backstop is swapped out, never both active.
  const identityRule = opts.calibration
    ? `CALIBRATION RUN (special mode):
- The candidate below IS the operator this lens was distilled from. Score it honestly against the lens like any profile — this measures the LENS, not the person. Do not inflate. suggested_intro may be an empty string.`
    : `SELF-IDENTITY RULE (hard rule, backstop — the code filters these before you see them):
- If a candidate appears to BE Rob or a Rob-owned org (NorthwoodsSentinel, robert-chuvala, or a profile whose repos/urls are the operator's own infrastructure), do NOT score it and do NOT draft an intro. Omit it from results entirely. The operator is the calibration reference for this lens, not a discovery candidate.`;

  const prompt = `You are a values-alignment filter for Rob Chuvala. Your job is to read GitHub candidate profiles and rank them by how strongly their PUBLIC, OBSERVABLE work matches Rob's values.

${valuesText}

${identityRule}

SCORE SEMANTICS (defined scale — do not improvise):
- public_values_alignment (1-10): how strongly the candidate's observable public output matches the values lens. 10 = the strongest observable NON-SELF match — multiple concrete, independent signals with no anti-signals. 9 = very strong match, multiple concrete signals. 8 = strong match with some missing context. This score measures visible evidence, not the person behind it.
- evidence_confidence (low|medium|high): how much public surface there was to read. low = thin (few repos, empty bio) — a low-confidence score is a guess and will not alert.
- connection_actionability (1-10): is there a real path to a real conversation — visible contact routes, recent activity, signs they engage with strangers.

PRIVACY GUARDRAILS (hard rules):
- Base every claim ONLY on the candidate's public output shown in the dossier. Never infer protected or sensitive attributes (health, politics, religion, finances, relationships).
- values_notes must cite the observable signal (repo, bio phrase, topic), not a character judgment.
- suggested_intro is a DRAFT for human review — never imply it was or will be sent automatically.
- Set "confidence" to low if the dossier is thin (few repos, empty bio), medium for moderate signal, high only for rich public output.

CANDIDATES:
${block}

Return ONLY valid JSON — no markdown fences, no preamble. Use this exact format:
[
  {
    "index": 1,
    "public_values_alignment": 9,
    "evidence_confidence": "high",
    "connection_actionability": 7,
    "values_notes": "2-3 sentences citing the specific observable signals",
    "suggested_intro": "one short paragraph Rob could send",
    "reach_via": ["github", "blog:https://...", "email:..."]
  }
]

Where "index" is the 1-based candidate number. Only include candidates with public_values_alignment >= 6. Order by public_values_alignment descending. Cap at 15 results.`;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    throw new Error(`Claude API ${res.status}: ${await res.text()}`);
  }

  const data = (await res.json()) as { content: Array<{ type: string; text: string }> };
  const text = data.content?.[0]?.text ?? "[]";

  let ranked: Array<{
    index: number;
    public_values_alignment?: number;
    evidence_confidence?: string;
    connection_actionability?: number;
    values_score?: number;          // pre-v0.6 field name — accepted for robustness
    confidence?: string;            // pre-v0.6 field name
    values_notes: string;
    suggested_intro: string;
    reach_via: string[];
  }>;
  try {
    ranked = JSON.parse(text);
  } catch {
    const cleaned = text.replace(/```json?\n?/g, "").replace(/```\n?/g, "").trim();
    ranked = JSON.parse(cleaned);
  }

  return ranked
    .filter((r) => r.index >= 1 && r.index <= candidates.length)
    .map((r) => {
      const c = candidates[r.index - 1];
      const alignment = r.public_values_alignment ?? r.values_score ?? 0;
      const confRaw = r.evidence_confidence ?? r.confidence;
      const conf = confRaw === "low" || confRaw === "high" ? confRaw : "medium";
      return {
        login: c.login,
        name: c.name,
        bio: c.bio,
        html_url: c.html_url,
        values_score: alignment,                    // kept: stored alerts / receipts / UI read this
        public_values_alignment: alignment,          // v0.6 canonical name
        connection_actionability: r.connection_actionability ?? null,
        confidence: conf,
        requires_human_review: true as const,
        source_kind: c.source_kind ?? "github" as const,
        values_notes: r.values_notes,
        suggested_intro: r.suggested_intro,
        reach_via: r.reach_via,
        contributed_to: c.contributed_to,
      };
    });
}

// ── HTML Rendering ─────────────────────────────────────────────

function renderSearchPage(query?: string, results?: DaemonResult[], error?: string): string {
  const resultsHtml = results
    ? results
        .map(
          (r) => `
      <div class="result">
        <div class="score">${r.daemon_score}</div>
        <div class="content">
          <a href="${escapeHtml(r.url)}" class="title" target="_blank">${escapeHtml(r.title)}</a>
          <div class="note">${escapeHtml(r.daemon_note)}</div>
          <div class="snippet">${escapeHtml(r.snippet)}</div>
          <div class="url">${escapeHtml(r.url)}</div>
        </div>
      </div>`,
        )
        .join("")
    : "";

  const errorHtml = error ? `<div class="error">${escapeHtml(error)}</div>` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lookout${query ? ` — ${escapeHtml(query)}` : ""}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 2rem 1rem; }
    .header { text-align: center; margin-bottom: 2rem; }
    .header h1 { color: #58a6ff; font-size: 1.5rem; font-weight: 600; letter-spacing: 0.02em; }
    .header p { color: #484f58; font-size: 0.85rem; margin-top: 0.3rem; }
    .header .nav { margin-top: 0.5rem; font-size: 0.8rem; }
    .header .nav a { color: #58a6ff; text-decoration: none; margin: 0 0.5rem; }
    form { width: 100%; max-width: 640px; margin-bottom: 2rem; }
    input[type="text"] { width: 100%; padding: 0.75rem 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 1rem; outline: none; }
    input[type="text"]:focus { border-color: #58a6ff; }
    .results { width: 100%; max-width: 640px; }
    .result { display: flex; gap: 1rem; padding: 1rem 0; border-bottom: 1px solid #21262d; }
    .score { flex-shrink: 0; width: 2.5rem; height: 2.5rem; display: flex; align-items: center; justify-content: center; background: #1f6feb22; border: 1px solid #1f6feb44; border-radius: 6px; color: #58a6ff; font-weight: 700; font-size: 1rem; }
    .content { flex: 1; min-width: 0; }
    .title { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 1.05rem; display: block; }
    .title:hover { text-decoration: underline; }
    .note { color: #f0883e; font-weight: 600; font-size: 0.85rem; margin: 0.3rem 0; }
    .snippet { color: #8b949e; font-size: 0.85rem; line-height: 1.4; }
    .url { color: #484f58; font-size: 0.75rem; margin-top: 0.25rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .error { color: #f85149; background: #f8514922; border: 1px solid #f8514944; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 1rem; max-width: 640px; width: 100%; }
    .footer { margin-top: auto; padding-top: 3rem; color: #484f58; font-size: 0.75rem; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Lookout — Search Through Your Daemon</h1>
    <p>Identity-lensed search. Your daemon is the filter.</p>
    <div class="nav"><a href="/">Search</a> · <a href="/discover">Discover humans</a></div>
  </div>
  <form action="/search" method="GET">
    <input type="text" name="q" placeholder="Search..." value="${escapeHtml(query ?? "")}" autofocus />
  </form>
  ${errorHtml}
  <div class="results">${resultsHtml}</div>
  <div class="footer">Searched through your daemon &middot; Northwoods Sentinel Labs</div>
</body>
</html>`;
}

function renderDiscoverPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lookout — Discover Humans</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 2rem 1rem; }
    .header { text-align: center; margin-bottom: 2rem; }
    .header h1 { color: #58a6ff; font-size: 1.5rem; font-weight: 600; }
    .header p { color: #484f58; font-size: 0.85rem; margin-top: 0.3rem; }
    .header .nav { margin-top: 0.5rem; font-size: 0.8rem; }
    .header .nav a { color: #58a6ff; text-decoration: none; margin: 0 0.5rem; }
    form { width: 100%; max-width: 720px; margin-bottom: 1rem; }
    label { display: block; color: #8b949e; font-size: 0.8rem; margin-bottom: 0.3rem; }
    textarea { width: 100%; padding: 0.75rem 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.9rem; outline: none; font-family: ui-monospace, monospace; min-height: 6rem; resize: vertical; }
    textarea:focus { border-color: #58a6ff; }
    .row { display: flex; gap: 0.5rem; align-items: center; margin-top: 0.5rem; }
    button { padding: 0.5rem 1rem; background: #1f6feb; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
    button:hover { background: #388bfd; }
    input[type="password"] { flex: 1; padding: 0.5rem 0.75rem; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.85rem; outline: none; font-family: ui-monospace, monospace; }
    .results { width: 100%; max-width: 720px; }
    .result { display: flex; gap: 1rem; padding: 1rem 0; border-bottom: 1px solid #21262d; }
    .score { flex-shrink: 0; width: 2.5rem; height: 2.5rem; display: flex; align-items: center; justify-content: center; background: #1f6feb22; border: 1px solid #1f6feb44; border-radius: 6px; color: #58a6ff; font-weight: 700; font-size: 1rem; }
    .content { flex: 1; min-width: 0; }
    .title { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 1.05rem; display: block; }
    .title:hover { text-decoration: underline; }
    .bio { color: #8b949e; font-size: 0.85rem; margin: 0.3rem 0; }
    .note { color: #f0883e; font-weight: 600; font-size: 0.85rem; margin: 0.3rem 0; }
    .intro { color: #c9d1d9; font-size: 0.85rem; margin: 0.5rem 0; background: #161b22; padding: 0.5rem 0.75rem; border-radius: 4px; border-left: 2px solid #1f6feb; }
    .intro strong { color: #58a6ff; }
    .meta { color: #484f58; font-size: 0.75rem; margin-top: 0.25rem; }
    .error { color: #f85149; background: #f8514922; border: 1px solid #f8514944; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 1rem; max-width: 720px; width: 100%; }
    .footer { margin-top: auto; padding-top: 3rem; color: #484f58; font-size: 0.75rem; text-align: center; }
    .status { color: #8b949e; padding: 2rem 0; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Lookout — Discover Humans</h1>
    <p>Find values-aligned operators on GitHub, ranked through your daemon.</p>
    <div class="nav"><a href="/">Search</a> · <a href="/discover">Discover humans</a></div>
  </div>
  <form id="discover-form">
    <label for="anchors">Anchor repos (one per line, format owner/repo). Empty = defaults.</label>
    <textarea id="anchors" name="anchors" placeholder="NorthwoodsSentinel/loam&#10;NorthwoodsSentinel/mycelia&#10;modelcontextprotocol/servers&#10;bluesky-social/atproto"></textarea>
    <div class="row">
      <input type="password" id="apikey" placeholder="LOOKOUT_API_KEY (stored in this tab only)" autocomplete="current-password" />
      <button type="submit">Find</button>
    </div>
  </form>
  <div class="results" id="results"></div>
  <div class="footer">Adjacency mode &middot; Northwoods Sentinel Labs</div>
  <script>
    (function(){
      var form = document.getElementById('discover-form');
      var results = document.getElementById('results');
      var apikeyInput = document.getElementById('apikey');
      try { var stored = sessionStorage.getItem('lookout_key'); if (stored) apikeyInput.value = stored; } catch(e) {}
      form.addEventListener('submit', function(e) {
        e.preventDefault();
        var anchorsText = document.getElementById('anchors').value.trim();
        var anchors = anchorsText ? anchorsText.split('\\n').map(function(s){return s.trim();}).filter(Boolean) : undefined;
        var key = apikeyInput.value.trim();
        if (!key) { results.innerHTML = '<div class="error">API key required.</div>'; return; }
        try { sessionStorage.setItem('lookout_key', key); } catch(e) {}
        results.innerHTML = '<div class="status">Searching... 20-40 seconds (GitHub API + Claude re-rank).</div>';
        fetch('/discover', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
          body: JSON.stringify({ mode: 'adjacency', anchors: anchors, count: 15 })
        })
        .then(function(r){ return r.json(); })
        .then(function(data) {
          if (data.error) { results.innerHTML = '<div class="error">' + esc(data.error) + '</div>'; return; }
          if (!data.results || data.results.length === 0) {
            results.innerHTML = '<div class="status">No values-aligned candidates surfaced. Try different anchor repos.</div>';
            return;
          }
          results.innerHTML = data.results.map(function(r){
            return '<div class="result">' +
              '<div class="score">' + r.values_score + '</div>' +
              '<div class="content">' +
                '<a href="' + esc(r.html_url) + '" class="title" target="_blank">@' + esc(r.login) + (r.name ? ' — ' + esc(r.name) : '') + '</a>' +
                (r.bio ? '<div class="bio">' + esc(r.bio) + '</div>' : '') +
                '<div class="note">' + esc(r.values_notes) + '</div>' +
                '<div class="intro"><strong>Suggested intro:</strong> ' + esc(r.suggested_intro) + '</div>' +
                '<div class="meta">Showed up in: ' + r.contributed_to.map(esc).join(', ') + '</div>' +
                '<div class="meta">Reach via: ' + r.reach_via.map(esc).join(' · ') + '</div>' +
              '</div>' +
            '</div>';
          }).join('');
        })
        .catch(function(err){ results.innerHTML = '<div class="error">Request failed.</div>'; });
      });
      function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); }
    })();
  </script>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Search Handler ─────────────────────────────────────────────

async function handleSearch(
  query: string,
  count: number,
  env: Env,
): Promise<SearchResponse> {
  let braveResults: BraveResult[];
  try {
    braveResults = await braveSearch(query, Math.max(count * 2, 15), env.BRAVE_SEARCH_KEY);
  } catch (e) {
    return {
      query,
      results: [],
      daemon: "lookout",
      ts: new Date().toISOString(),
      error: "Search temporarily unavailable",
    };
  }

  if (braveResults.length === 0) {
    return {
      query,
      results: [],
      daemon: "lookout",
      ts: new Date().toISOString(),
    };
  }

  const lens = await getLens(env);
  let daemonResults: DaemonResult[];
  try {
    daemonResults = await daemonRerank(query, braveResults, env.ANTHROPIC_API_KEY, lens.text);
  } catch (e) {
    // Fallback: return un-ranked Brave results
    daemonResults = braveResults.slice(0, count).map((r) => ({
      title: r.title,
      url: r.url,
      snippet: r.description,
      daemon_score: 0,
      daemon_note: "Re-ranking unavailable — raw result",
    }));
    return {
      query,
      results: daemonResults,
      daemon: "lookout",
      lens_version: lens.version,
      lens_state: lens.state,
      ts: new Date().toISOString(),
      error: "Search temporarily unavailable — showing unranked results",
    };
  }

  return {
    query,
    results: daemonResults.slice(0, count),
    daemon: "lookout",
    lens_version: lens.version,
    lens_state: lens.state,
    ts: new Date().toISOString(),
  };
}

// ── Discover Handler ───────────────────────────────────────────

async function handleDiscover(body: DiscoverRequest, env: Env): Promise<DiscoverResponse> {
  const mode = body.mode ?? "adjacency";
  const count = Math.min(Math.max(body.count ?? 10, 1), 25);
  const perAnchor = Math.min(Math.max(body.per_anchor ?? 15, 5), 30);

  const defaultAnchors = [
    "NorthwoodsSentinel/loam",
    "NorthwoodsSentinel/mycelia",
    "modelcontextprotocol/servers",
    "bluesky-social/atproto",
    "NorthwoodsSentinel/brook",
  ];

  // Validate user-provided anchors; silently drop invalid ones
  const rawAnchors = body.anchors && body.anchors.length > 0 ? body.anchors : defaultAnchors;
  const anchors = rawAnchors
    .filter((a) => typeof a === "string" && isValidRepoSlug(a))
    .slice(0, 10);

  if (anchors.length === 0) {
    return {
      mode,
      total_candidates: 0,
      results: [],
      daemon: "lookout-discover",
      ts: new Date().toISOString(),
      error: "No valid anchor repos. Use owner/repo format.",
    };
  }

  // Phase 1: gather contributor logins across all anchors
  const selfLogins = parseSelfLogins(env.SELF_GITHUB_LOGINS);
  const knownContacts = await getKnownContacts(env.LOOKOUT_KV);
  const loginToAnchors = new Map<string, Set<string>>();
  for (const anchor of anchors) {
    let logins: string[];
    try {
      logins = await fetchContributors(anchor, env.GITHUB_TOKEN, perAnchor);
    } catch {
      continue;
    }
    for (const login of logins) {
      // Identity layer BEFORE the values layer (CoE 2026-07-29, unanimous):
      // the operator is the positive control, never a candidate; known
      // contacts graduated out of discovery. Deterministic — identity
      // recognition must not depend on an LLM.
      if (classify(login, selfLogins, knownContacts) !== "candidate") continue;
      if (!loginToAnchors.has(login)) loginToAnchors.set(login, new Set());
      loginToAnchors.get(login)!.add(anchor);
    }
  }

  if (loginToAnchors.size === 0) {
    return {
      mode,
      total_candidates: 0,
      results: [],
      daemon: "lookout-discover",
      ts: new Date().toISOString(),
      error: "No contributors found. Check anchor repos and GitHub token scope.",
    };
  }

  // Phase 2: build candidate dossiers (parallel, but bounded)
  const logins = Array.from(loginToAnchors.keys()).slice(0, 60);
  const BATCH = 8;
  const candidates: Candidate[] = [];
  for (let i = 0; i < logins.length; i += BATCH) {
    const slice = logins.slice(i, i + BATCH);
    const built = await Promise.all(
      slice.map((login) => {
        const anchorList = Array.from(loginToAnchors.get(login)!);
        return buildCandidate(login, anchorList[0], env.GITHUB_TOKEN).then((c) => {
          if (c) {
            for (const a of anchorList.slice(1)) {
              if (!c.contributed_to.includes(a)) c.contributed_to.push(a);
            }
          }
          return c;
        });
      }),
    );
    for (const c of built) if (c) candidates.push(c);
  }

  if (candidates.length === 0) {
    return {
      mode,
      total_candidates: 0,
      results: [],
      daemon: "lookout-discover",
      ts: new Date().toISOString(),
      error: "Contributors found but no candidate profiles could be fetched.",
    };
  }

  // Phase 3: re-rank via Claude through the values lens (daemon-fed, v0.5)
  const vlens = await getValuesLens(env);
  let ranked: DiscoverResult[];
  try {
    ranked = await valuesRerank(candidates, env.ANTHROPIC_API_KEY, vlens.text);
  } catch (e) {
    return {
      mode,
      total_candidates: candidates.length,
      results: [],
      daemon: "lookout-discover",
      values_lens_version: vlens.version,
      values_lens_state: vlens.state,
      ts: new Date().toISOString(),
      error: "Re-ranking temporarily unavailable",
    };
  }

  return {
    mode,
    total_candidates: candidates.length,
    results: ranked.slice(0, count),
    daemon: "lookout-discover",
    values_lens_version: vlens.version,
    values_lens_state: vlens.state,
    ts: new Date().toISOString(),
  };
}

// ── Notifications (Mycelia event + email via MailChannels) ─────

async function notifyMycelia(env: Env, payload: { type: string; title: string; body: string; metadata?: Record<string, unknown> }): Promise<void> {
  if (!env.MYCELIA_API_BASE || !env.MYCELIA_KEY_LOOKOUT) return;
  await fetch(`${env.MYCELIA_API_BASE}/v1/request`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.MYCELIA_KEY_LOOKOUT}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  }).catch(() => {});
}

async function notifyEmail(env: Env, subject: string, plain: string): Promise<void> {
  if (!env.NOTIFY_EMAIL_TO || !env.NOTIFY_EMAIL_FROM) return;
  await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: env.NOTIFY_EMAIL_TO }] }],
      from: { email: env.NOTIFY_EMAIL_FROM, name: "Lookout Discover" },
      subject,
      content: [{ type: "text/plain", value: plain }],
    }),
  }).catch(() => {});
}

// ── v0.4: Dynamic anchors (KV-config, GitHub + experimental RSS) ──
// Council verdict: a hardcoded refresh repeats the original sin. Anchors live
// in KV, seeded once, editable via POST /anchors without a deploy. Per-anchor
// yield counters make rotation decisions evidence-based (surfaced in digest,
// rotated by a human — never auto-dropped).

interface Anchor { kind: "github-repo" | "rss"; target: string }

const DEFAULT_ANCHORS: Anchor[] = [
  { kind: "github-repo", target: "NorthwoodsSentinel/loam" },
  { kind: "github-repo", target: "NorthwoodsSentinel/mycelia" },
  { kind: "github-repo", target: "modelcontextprotocol/servers" },
  { kind: "github-repo", target: "bluesky-social/atproto" },
  { kind: "github-repo", target: "NorthwoodsSentinel/brook" },
  { kind: "github-repo", target: "modelcontextprotocol/registry" },
  { kind: "github-repo", target: "the-metafactory/cortex" },
  { kind: "github-repo", target: "the-metafactory/myelin" },
  { kind: "github-repo", target: "mellanon/pai-collab" },
  { kind: "github-repo", target: "danielmiessler/PAI" },
  { kind: "github-repo", target: "wally-kroeker/mycelia" },
  // The 2026-01-26 brief said BLOGS. Experimental RSS anchors honor it.
  { kind: "rss", target: "https://danielmiessler.com/feed.xml" },
  { kind: "rss", target: "https://simonwillison.net/atom/everything/" },
];

const ANCHORS_KV_KEY = "config:anchors";

async function getAnchors(kv: KVNamespace): Promise<Anchor[]> {
  const raw = await kv.get(ANCHORS_KV_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown[];
      // Validate every entry — a malformed/migrated config must never rotate on undefined
      const valid = Array.isArray(parsed) ? parsed.filter(isValidAnchor) : [];
      if (valid.length > 0) return valid;
    } catch { /* reseed below */ }
  }
  await kv.put(ANCHORS_KV_KEY, JSON.stringify(DEFAULT_ANCHORS));
  return DEFAULT_ANCHORS;
}

function isValidAnchor(a: unknown): a is Anchor {
  if (typeof a !== "object" || a === null) return false;
  const x = a as Record<string, unknown>;
  if (x.kind === "github-repo") return typeof x.target === "string" && isValidRepoSlug(x.target);
  if (x.kind === "rss") {
    if (typeof x.target !== "string" || x.target.length > 300) return false;
    try { return new URL(x.target).protocol === "https:"; } catch { return false; }
  }
  return false;
}

async function recordYield(kv: KVNamespace, anchor: string, evaluated: number, alerted: number): Promise<void> {
  const key = `yield:${anchor}`;
  const raw = await kv.get(key);
  const y = raw ? (JSON.parse(raw) as { evaluated: number; alerted: number; runs: number }) : { evaluated: 0, alerted: 0, runs: 0 };
  y.evaluated += evaluated; y.alerted += alerted; y.runs += 1;
  await kv.put(key, JSON.stringify(y));
}

// ── v0.4: RSS anchor pipeline (experimental) ──
// Minimal by design: fetch feed, extract entries, one candidate per unique
// author/domain, dossier = recent post titles. Same valuesRerank path.

async function fetchRssCandidates(feedUrl: string): Promise<Candidate[]> {
  try {
    const res = await fetch(feedUrl, { headers: { "User-Agent": "lookout-discover/0.4", "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml" } });
    if (!res.ok) return [];
    const xml = (await res.text()).slice(0, 500_000);
    const entries = xml.match(/<(entry|item)[\s\S]*?<\/\1>/g)?.slice(0, 20) ?? [];
    const strip = (s: string) => s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/<[^>]+>/g, "").trim().slice(0, 160);
    const byAuthor = new Map<string, { titles: string[]; links: string[] }>();
    const host = new URL(feedUrl).hostname;
    for (const e of entries) {
      const title = strip(e.match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1] ?? "");
      const link = e.match(/<link[^>]*href="([^"]+)"/)?.[1] ?? strip(e.match(/<link[^>]*>([\s\S]*?)<\/link>/)?.[1] ?? "");
      const author = strip(e.match(/<(?:author|dc:creator)[^>]*>[\s\S]*?<name[^>]*>([\s\S]*?)<\/name>/)?.[1] ?? e.match(/<dc:creator[^>]*>([\s\S]*?)<\/dc:creator>/)?.[1] ?? "") || host;
      const cur = byAuthor.get(author) ?? { titles: [], links: [] };
      if (title) cur.titles.push(title);
      if (link) cur.links.push(link);
      byAuthor.set(author, cur);
    }
    const out: Candidate[] = [];
    for (const [author, v] of Array.from(byAuthor.entries()).slice(0, 5)) {
      // Collision-proof login: feed-controlled author strings could truncate
      // to the same 60 chars, so a content hash disambiguates the identity.
      const idHash = await sha256Short(`${host}:${author}`);
      out.push({
        login: `${host}:${author}`.slice(0, 48) + `:${idHash.slice(0, 8)}`,
        name: author,
        bio: `Blog author at ${host}. Recent posts: ${v.titles.slice(0, 5).join(" · ")}`,
        location: null,
        html_url: v.links[0] ?? feedUrl,
        blog: `https://${host}`,
        twitter_username: null,
        email: null,
        public_repos: 0,
        followers: 0,
        top_repos: [],
        contributed_to: [feedUrl],
        source_kind: "rss" as const,
      });
    }
    return out;
  } catch {
    return [];
  }
}

// ── Scheduled Discover (rotates anchors, diffs against seen, alerts) ──

async function getSeenLogins(kv: KVNamespace): Promise<Set<string>> {
  const raw = await kv.get("seen:logins");
  return new Set(raw ? (JSON.parse(raw) as string[]) : []);
}

async function setSeenLogins(kv: KVNamespace, logins: Set<string>): Promise<void> {
  // Cap at 5000 logins to avoid unbounded growth
  const arr = Array.from(logins).slice(-5000);
  await kv.put("seen:logins", JSON.stringify(arr));
}

async function runScheduledDiscover(env: Env): Promise<{ anchor: string; new_candidates: number; alerts: number }> {
  // Daily rotation over the KV-config anchor list (github + rss kinds)
  const anchors = await getAnchors(env.LOOKOUT_KV);
  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getUTCFullYear(), 0, 0).getTime()) / 86400000);
  const a = anchors[dayOfYear % anchors.length];
  const anchor = a.target;

  const seen = await getSeenLogins(env.LOOKOUT_KV);
  let candidates: Candidate[] = [];
  let fresh: string[] = [];

  const selfLogins = parseSelfLogins(env.SELF_GITHUB_LOGINS);
  const knownContacts = await getKnownContacts(env.LOOKOUT_KV);
  const isCandidate = (l: string) => classify(l, selfLogins, knownContacts) === "candidate";
  if (a.kind === "rss") {
    const rssCandidates = await fetchRssCandidates(anchor);
    candidates = rssCandidates.filter((c) => !seen.has(c.login) && isCandidate(c.login));
    fresh = candidates.map((c) => c.login);
  } else {
    // Pull contributors from today's anchor
    let logins: string[];
    try {
      logins = await fetchContributors(anchor, env.GITHUB_TOKEN, 30);
    } catch {
      return { anchor, new_candidates: 0, alerts: 0 };
    }
    fresh = logins.filter((l) => !seen.has(l) && isCandidate(l));
    if (fresh.length === 0) {
      await recordYield(env.LOOKOUT_KV, anchor, 0, 0);
      return { anchor, new_candidates: 0, alerts: 0 };
    }
    for (const login of fresh.slice(0, 30)) {
      const c = await buildCandidate(login, anchor, env.GITHUB_TOKEN);
      if (c) candidates.push(c);
    }
  }

  if (candidates.length === 0) {
    // Still mark fresh as seen so we don't keep re-fetching dead profiles
    fresh.forEach((l) => seen.add(l));
    await setSeenLogins(env.LOOKOUT_KV, seen);
    await recordYield(env.LOOKOUT_KV, anchor, 0, 0);
    return { anchor, new_candidates: 0, alerts: 0 };
  }

  // Re-rank via Claude through the values lens (daemon-fed, v0.5)
  const vlens = await getValuesLens(env);
  let ranked: DiscoverResult[];
  try {
    ranked = await valuesRerank(candidates, env.ANTHROPIC_API_KEY, vlens.text);
  } catch {
    fresh.forEach((l) => seen.add(l));
    await setSeenLogins(env.LOOKOUT_KV, seen);
    return { anchor, new_candidates: candidates.length, alerts: 0 };
  }

  // v0.6 judgment predicate: strong observable alignment AND readable surface.
  // (Previously a bare >=8 threshold; thin-dossier guesses no longer page.)
  const asTriple = (r: DiscoverResult) => ({
    public_values_alignment: r.public_values_alignment ?? r.values_score,
    evidence_confidence: r.confidence,
    connection_actionability: r.connection_actionability ?? 5,
  });
  const alerts = ranked.filter((r) => shouldAlert(asTriple(r)));
  const digestOnly = ranked.filter((r) => !shouldAlert(asTriple(r)) && r.values_score >= 6);

  // Store each alert as a separate KV row for later /alerts review
  const ts = Date.now();
  for (const a of alerts) {
    const key = `alert:${ts}:${a.login}`;
    await env.LOOKOUT_KV.put(
      key,
      JSON.stringify({ ...a, anchor, values_lens_version: vlens.version, found_at: new Date(ts).toISOString(), read: false }),
      { expirationTtl: 60 * 60 * 24 * 90 }, // 90 days
    );
  }
  for (const d of digestOnly) {
    await env.LOOKOUT_KV.put(
      `digest:${ts}:${d.login}`,
      JSON.stringify({ ...d, anchor, found_at: new Date(ts).toISOString() }),
      { expirationTtl: 60 * 60 * 24 * 45 }, // covers the monthly digest window
    );
  }

  // Mark all fresh logins as seen
  fresh.forEach((l) => seen.add(l));
  await setSeenLogins(env.LOOKOUT_KV, seen);
  await recordYield(env.LOOKOUT_KV, anchor, candidates.length, alerts.length);

  // Fan-out notifications
  if (alerts.length > 0) {
    const bodyLines = alerts.map((a) =>
      `@${a.login}${a.name ? ` (${a.name})` : ""}  score:${a.values_score} conf:${a.confidence}\n` +
      `  ${a.html_url}\n` +
      `  bio: ${a.bio || "—"}\n` +
      `  why: ${a.values_notes}\n` +
      `  intro (DRAFT, needs your review): ${a.suggested_intro}\n` +
      `  reach: ${a.reach_via.join(" · ")}\n`
    );
    const plain = `Lookout found ${alerts.length} new high-scoring values-aligned candidate(s) in ${anchor}.\n\n${bodyLines.join("\n")}\n\nReview at /alerts on your Lookout instance.`;
    const urgent = alerts.some((a) => a.values_score >= 9);

    await Promise.allSettled([
      notifyNtfy(env, `Lookout: ${alerts.length} values-aligned candidate(s) from ${anchor}`, plain, urgent),
      notifyMycelia(env, {
        type: "lookout-discover-alert",
        title: `${alerts.length} new values-aligned candidate(s) from ${anchor}`,
        body: plain,
        metadata: { anchor, count: alerts.length, ts },
      }),
      notifyEmail(env, `Lookout: ${alerts.length} new values-aligned candidate(s) from ${anchor}`, plain),
    ]);
  }

  return { anchor, new_candidates: candidates.length, alerts: alerts.length };
}

// ── v0.4.1: The daily pipeline — ONE code path for cron and manual trigger ──
// The scheduled handler and POST /cron/run execute THIS function. A manual
// run therefore observes exactly what the cron will do — no test-path drift.

async function runDailyPipeline(env: Env): Promise<{ lens_version: string | null; lens_state: string; deadman_paged: boolean; calibration_score?: number | null; calibration_drifted?: boolean; anchor: string; new_candidates: number; alerts: number }> {
  const lens = await refreshLens(env);
  let deadman_paged = false;
  if (!lens) {
    const active = await getLens(env);
    if (active.state !== "fresh") {
      await notifyNtfy(env, "Lookout lens DEGRADED", `Daily lens refresh failed and active lens is ${active.state} (${active.version}). Results are being scored through an outdated lens until this is fixed.`, true);
      deadman_paged = true;
    }
  }
  const r = await runScheduledDiscover(env);
  // Layer 3: calibration rides every daily run; its failure never blocks discovery.
  let calibration: { score: number | null; drifted: boolean } = { score: null, drifted: false };
  try { calibration = await runCalibration(env); } catch { /* calibration is advisory */ }
  const after = await getLens(env);
  return { lens_version: lens?.version ?? null, lens_state: after.state, deadman_paged, calibration_score: calibration.score, calibration_drifted: calibration.drifted, ...r };
}

// ── v0.4: Outcomes ledger + monthly digest ─────────────────────
// "The model score is not the truth; Rob's later behavior is the truth."

const OUTCOME_STATUSES = ["alerted", "reviewed", "contacted", "replied", "collaborating", "ignored"] as const;
type OutcomeStatus = (typeof OUTCOME_STATUSES)[number];

async function recordOutcome(kv: KVNamespace, login: string, status: OutcomeStatus, note: string): Promise<{ login: string; history: Array<{ status: string; note: string; ts: string }> }> {
  const key = `outcome:${login}`;
  const raw = await kv.get(key);
  const rec = raw ? (JSON.parse(raw) as { login: string; history: Array<{ status: string; note: string; ts: string }> }) : { login, history: [] };
  rec.history.push({ status, note: note.slice(0, 500), ts: new Date().toISOString() });
  await kv.put(key, JSON.stringify(rec));
  // v0.6 Layer 4 → Layer 0 wiring: a relationship in motion graduates the
  // login out of discovery permanently. Discovery's job is strangers.
  if ((GRADUATING_OUTCOMES as readonly string[]).includes(status)) {
    await addKnownContact(kv, login, `outcome:${status}`);
  }
  return rec;
}

// ── v0.6 Layer 3: calibration — the operator as positive control ──
// Scores the operator's own profile through the live lens ON PURPOSE, daily.
// Never alerted, never intro'd; stored as a time series. If today's self-score
// drops >=2 below the trailing median, either the public surface changed or
// the LENS drifted — either way the run says so instead of staying quiet.
async function runCalibration(env: Env): Promise<{ score: number | null; drifted: boolean; median: number | null; lens_version: string | null }> {
  const operator = [...parseSelfLogins(env.SELF_GITHUB_LOGINS)][0];
  if (!operator) return { score: null, drifted: false, median: null, lens_version: null };
  const vlens = await getLens(env);
  const candidate = await buildCandidate(operator, "calibration", env.GITHUB_TOKEN);
  if (!candidate) return { score: null, drifted: false, median: null, lens_version: vlens.version };
  const ranked = await valuesRerank([candidate], env.ANTHROPIC_API_KEY, vlens.text, { calibration: true });
  const score = ranked[0]?.public_values_alignment ?? ranked[0]?.values_score ?? null;
  if (score === null) return { score: null, drifted: false, median: null, lens_version: vlens.version };

  const today = new Date().toISOString().slice(0, 10);
  const prior = await env.LOOKOUT_KV.list({ prefix: "calibration:" });
  const history: number[] = [];
  for (const k of prior.keys.slice(-7)) {
    if (k.name === `calibration:${today}`) continue;
    try {
      const row = JSON.parse((await env.LOOKOUT_KV.get(k.name)) ?? "null") as { score?: number } | null;
      if (row?.score != null) history.push(row.score);
    } catch { /* skip */ }
  }
  const { drifted, median } = calibrationDrift(history, score);
  await env.LOOKOUT_KV.put(
    `calibration:${today}`,
    JSON.stringify({ score, lens_version: vlens.version, drifted, median, ts: new Date().toISOString() }),
    { expirationTtl: 60 * 60 * 24 * 180 },
  );
  if (drifted) {
    await notifyNtfy(env, "Lookout lens CALIBRATION DRIFT",
      `Operator self-score ${score} vs trailing median ${median}. Either the public surface changed or the lens drifted — scores from this lens deserve suspicion until reviewed.`, true);
  }
  return { score, drifted, median, lens_version: vlens.version };
}

async function buildMonthlyDigest(env: Env): Promise<string> {
  const kv = env.LOOKOUT_KV;
  const [alertList, digestList, outcomeList, yieldList] = await Promise.all([
    kv.list({ prefix: "alert:" }), kv.list({ prefix: "digest:" }), kv.list({ prefix: "outcome:" }), kv.list({ prefix: "yield:" }),
  ]);
  const lines: string[] = [`Lookout monthly digest — ${new Date().toISOString().slice(0, 10)}`, ""];
  lines.push(`Alerts on file: ${alertList.keys.length} · mid-score (6-7) candidates: ${digestList.keys.length} · outcomes recorded: ${outcomeList.keys.length}`);
  lines.push("", "Anchor yield (evaluated → alerted, runs):");
  for (const k of yieldList.keys.slice(0, 30)) {
    const raw = await kv.get(k.name);
    if (!raw) continue;
    const y = JSON.parse(raw) as { evaluated: number; alerted: number; runs: number };
    lines.push(`  ${k.name.slice(6)}: ${y.evaluated} → ${y.alerted} (${y.runs} runs)`);
  }
  const outcomes: string[] = [];
  for (const k of outcomeList.keys.slice(0, 30)) {
    const raw = await kv.get(k.name);
    if (!raw) continue;
    const o = JSON.parse(raw) as { login: string; history: Array<{ status: string; ts: string }> };
    const last = o.history[o.history.length - 1];
    if (last) outcomes.push(`  ${o.login}: ${last.status} (${last.ts.slice(0, 10)})`);
  }
  if (outcomes.length > 0) lines.push("", "Latest outcomes:", ...outcomes);
  lines.push("", "Low-yield anchors are rotation-out candidates — your call, never automatic. Review: /alerts");
  return lines.join("\n");
}

// ── /alerts review helpers ─────────────────────────────────────

async function listAlerts(kv: KVNamespace, unreadOnly: boolean): Promise<Array<DiscoverResult & { anchor: string; found_at: string; read: boolean }>> {
  const list = await kv.list({ prefix: "alert:" });
  const out: Array<DiscoverResult & { anchor: string; found_at: string; read: boolean }> = [];
  for (const k of list.keys) {
    const raw = await kv.get(k.name);
    if (!raw) continue;
    const a = JSON.parse(raw) as DiscoverResult & { anchor: string; found_at: string; read: boolean };
    if (unreadOnly && a.read) continue;
    out.push(a);
  }
  out.sort((a, b) => b.found_at.localeCompare(a.found_at));
  return out;
}

// ── Worker Entry ───────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Periodic rate limit cleanup
    cleanupRateLimits();

    // Health check
    if (path === "/health") {
      let lens_version = "none";
      let lens_age_hours: number | null = null;
      try {
        const raw = await env.LOOKOUT_KV.get(LENS_KV_KEY);
        if (raw) {
          const lens = JSON.parse(raw) as LensSnapshot;
          lens_version = lens.version;
          lens_age_hours = Math.round((Date.now() - Date.parse(lens.fetched_at)) / 3600_000 * 10) / 10;
        }
      } catch { /* health never fails on lens state */ }
      let calibration: unknown = null;
      try {
        const today = new Date().toISOString().slice(0, 10);
        const raw = await env.LOOKOUT_KV.get(`calibration:${today}`);
        if (raw) calibration = JSON.parse(raw);
      } catch { /* health never fails on calibration state */ }
      return secureJsonResponse({
        status: "ok",
        daemon: "lookout",
        version: "0.6",
        features: ["search", "discover", "lens", "outcomes", "intents", "rss-anchors", "identity-layer", "calibration"],
        lens_version,
        lens_age_hours,
        calibration,
        ts: new Date().toISOString(),
      });
    }

    // Everything below requires auth
    const authFail = requireAuth(request, env);
    if (authFail) return authFail;

    // Landing page
    if (path === "/" && request.method === "GET") {
      return secureHtmlResponse(renderSearchPage());
    }

    // Discover UI
    if (path === "/discover" && request.method === "GET") {
      return secureHtmlResponse(renderDiscoverPage());
    }

    // Rate limit check for search endpoints
    const ip = request.headers.get("cf-connecting-ip") || "unknown";

    // POST /discover — JSON API for adjacency mining
    if (path === "/discover" && request.method === "POST") {
      if (!checkDiscoverRateLimit(ip)) {
        return secureJsonResponse(
          { error: "Discover rate limit exceeded. Max 2 requests per minute." },
          { status: 429 }
        );
      }

      const contentType = request.headers.get("Content-Type") || "";
      if (!contentType.includes("application/json")) {
        return secureJsonResponse({ error: "Content-Type must be application/json" }, { status: 415 });
      }

      let body: DiscoverRequest;
      try {
        body = (await request.json()) as DiscoverRequest;
      } catch {
        return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 });
      }

      const data = await handleDiscover(body, env);
      return secureJsonResponse(data);
    }

    if (path === "/search" && !checkRateLimit(ip)) {
      return secureJsonResponse(
        { error: "Rate limit exceeded. Max 10 searches per minute." },
        { status: 429 }
      );
    }

    // GET /search?q=...
    if (path === "/search" && request.method === "GET") {
      const query = url.searchParams.get("q")?.trim();
      if (!query) {
        return secureHtmlResponse(renderSearchPage());
      }
      if (query.length > 500) {
        return secureJsonResponse({ error: "Query too long. Maximum 500 characters." }, { status: 400 });
      }

      const data = await handleSearch(query, 5, env);
      return secureHtmlResponse(renderSearchPage(query, data.results, data.error));
    }

    // POST /search — JSON API
    if (path === "/search" && request.method === "POST") {
      const contentType = request.headers.get("Content-Type") || "";
      if (!contentType.includes("application/json")) {
        return secureJsonResponse({ error: "Content-Type must be application/json" }, { status: 415 });
      }

      let body: { query?: string; count?: number };
      try {
        body = (await request.json()) as { query?: string; count?: number };
      } catch {
        return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 });
      }

      const query = body.query?.trim();
      if (!query) {
        return secureJsonResponse({ error: "Missing 'query' field" }, { status: 400 });
      }
      if (query.length > 500) {
        return secureJsonResponse({ error: "Query too long. Maximum 500 characters." }, { status: 400 });
      }

      const count = Math.min(Math.max(body.count ?? 5, 1), 10);
      const data = await handleSearch(query, count, env);
      return secureJsonResponse(data);
    }

    // GET /alerts — list high-scoring candidates surfaced by scheduled discover
    if (path === "/alerts" && request.method === "GET") {
      const unreadOnly = url.searchParams.get("unread") === "true";
      const alerts = await listAlerts(env.LOOKOUT_KV, unreadOnly);
      return secureJsonResponse({
        alerts,
        total: alerts.length,
        unread: alerts.filter((a) => !a.read).length,
      });
    }

    // POST /alerts/ack — mark alerts as read
    if (path === "/alerts/ack" && request.method === "POST") {
      let body: { logins?: string[]; all?: boolean };
      try {
        body = (await request.json()) as { logins?: string[]; all?: boolean };
      } catch {
        return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 });
      }
      const list = await env.LOOKOUT_KV.list({ prefix: "alert:" });
      let acked = 0;
      for (const k of list.keys) {
        const raw = await env.LOOKOUT_KV.get(k.name);
        if (!raw) continue;
        const a = JSON.parse(raw) as DiscoverResult & { anchor: string; found_at: string; read: boolean };
        if (a.read) continue;
        if (body.all || body.logins?.includes(a.login)) {
          a.read = true;
          await env.LOOKOUT_KV.put(k.name, JSON.stringify(a), { expirationTtl: 60 * 60 * 24 * 90 });
          acked++;
        }
      }
      return secureJsonResponse({ acked });
    }

    // POST /cron/run — manual trigger for the FULL daily pipeline (same code path
    // as the cron). Optional {"mode":"deadman-drill"} exercises only the
    // failure-paging leg against current lens state.
    // v0.6 Layer 0: known-contact set — GET lists, POST graduates a login manually
    if (path === "/contacts/known" && request.method === "GET") {
      const denied = requireAuth(request, env);
      if (denied) return denied;
      const raw = (await env.LOOKOUT_KV.get(KNOWN_CONTACTS_KEY)) ?? "{}";
      return secureJsonResponse({ known: JSON.parse(raw), ts: new Date().toISOString() });
    }
    if (path === "/contacts/known" && request.method === "POST") {
      const denied = requireAuth(request, env);
      if (denied) return denied;
      let body: { login?: string; source?: string };
      try { body = (await request.json()) as { login?: string; source?: string }; } catch { body = {}; }
      if (!body.login) return secureJsonResponse({ error: "login required" }, { status: 400 });
      await addKnownContact(env.LOOKOUT_KV, body.login, body.source ?? "manual");
      return secureJsonResponse({ added: body.login.toLowerCase(), ts: new Date().toISOString() });
    }

    if (path === "/cron/run" && request.method === "POST") {
      let mode = "daily";
      try { mode = ((await request.json()) as { mode?: string }).mode ?? "daily"; } catch { /* empty body = daily */ }
      if (mode === "calibrate") {
        // Layer 3 alone — score the operator through the live lens, no discovery.
        const cal = await runCalibration(env);
        return secureJsonResponse({ mode: "calibrate", ...cal, ts: new Date().toISOString() });
      }
      if (mode === "deadman-drill") {
        const active = await getLens(env);
        if (active.state !== "fresh") {
          await notifyNtfy(env, "Lookout lens DEGRADED", `[DRILL] Active lens is ${active.state} (${active.version}). This page proves lens failure cannot be silent.`, true);
          return secureJsonResponse({ drill: true, paged: true, lens_state: active.state, ts: new Date().toISOString() });
        }
        return secureJsonResponse({ drill: true, paged: false, lens_state: "fresh", note: "Lens is fresh — delete lens:snapshot first to make the drill real", ts: new Date().toISOString() });
      }
      const result = await runDailyPipeline(env);
      return secureJsonResponse({
        ...result,
        ts: new Date().toISOString(),
        message: `Daily pipeline: lens ${result.lens_version ?? "REFRESH-FAILED"} (${result.lens_state}) → ${result.anchor}: ${result.new_candidates} new candidates, ${result.alerts} alerts`,
      });
    }

    // v0.4 — POST /lens/refresh — force a daemon fetch + distillation now
    if (path === "/lens/refresh" && request.method === "POST") {
      const r = await refreshLensDetailed(env);
      if (!r.lens) return secureJsonResponse({ error: `Lens refresh failed: ${r.fail}` }, { status: 502 });
      return secureJsonResponse({ lens_version: r.lens.version, fetched_at: r.lens.fetched_at, source_bytes: r.lens.source_bytes, provenance: r.lens.provenance });
    }

    // v0.4 — GET/POST /anchors — read or replace the anchor config
    if (path === "/anchors" && request.method === "GET") {
      return secureJsonResponse({ anchors: await getAnchors(env.LOOKOUT_KV) });
    }
    if (path === "/anchors" && request.method === "POST") {
      let body: { anchors?: unknown[] };
      try { body = (await request.json()) as { anchors?: unknown[] }; } catch { return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 }); }
      const anchors = (body.anchors ?? []).filter(isValidAnchor);
      if (anchors.length === 0 || anchors.length > 30) return secureJsonResponse({ error: "Provide 1-30 valid anchors ({kind: github-repo|rss, target})" }, { status: 400 });
      await env.LOOKOUT_KV.put(ANCHORS_KV_KEY, JSON.stringify(anchors));
      return secureJsonResponse({ saved: anchors.length, anchors });
    }

    // v0.4 — POST /outcome — record what Rob actually did with a candidate
    if (path === "/outcome" && request.method === "POST") {
      let body: { login?: string; status?: string; note?: string };
      try { body = (await request.json()) as typeof body; } catch { return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 }); }
      const login = body.login?.trim();
      const status = body.status as OutcomeStatus;
      if (!login || login.length > 80) return secureJsonResponse({ error: "Missing/invalid 'login'" }, { status: 400 });
      if (!OUTCOME_STATUSES.includes(status)) return secureJsonResponse({ error: `'status' must be one of: ${OUTCOME_STATUSES.join(", ")}` }, { status: 400 });
      const rec = await recordOutcome(env.LOOKOUT_KV, login, status, body.note ?? "");
      return secureJsonResponse(rec);
    }

    // v0.4 — POST /intent — narrow named intents for fleet callers.
    // Caller MUST declare purpose; every call is logged. No generic passthrough —
    // "otherwise every agent can launder lazy research through Rob's lens."
    if (path === "/intent" && request.method === "POST") {
      let body: { intent?: string; purpose?: string; query?: string; count?: number; anchors?: string[]; login?: string; status?: string; note?: string; candidate?: string };
      try { body = (await request.json()) as typeof body; } catch { return secureJsonResponse({ error: "Invalid JSON body" }, { status: 400 }); }
      const purpose = body.purpose?.trim();
      if (!purpose || purpose.length < 8) return secureJsonResponse({ error: "Declare 'purpose' (≥8 chars): why this call serves the principal" }, { status: 400 });
      const logEntry = { intent: body.intent, purpose: purpose.slice(0, 200), ts: new Date().toISOString(), ip };
      await env.LOOKOUT_KV.put(`intent_log:${Date.now()}`, JSON.stringify(logEntry), { expirationTtl: 60 * 60 * 24 * 30 });

      switch (body.intent) {
        case "get_lens_version": {
          const lens = await getLens(env);
          return secureJsonResponse({ lens_version: lens.version, lens_state: lens.state });
        }
        case "rank_search_results": {
          const q = body.query?.trim();
          if (!q) return secureJsonResponse({ error: "Missing 'query'" }, { status: 400 });
          if (!checkRateLimit(ip)) return secureJsonResponse({ error: "Rate limited" }, { status: 429 });
          return secureJsonResponse(await handleSearch(q, Math.min(Math.max(body.count ?? 5, 1), 10), env));
        }
        case "discover_people": {
          if (!checkDiscoverRateLimit(ip)) return secureJsonResponse({ error: "Rate limited" }, { status: 429 });
          return secureJsonResponse(await handleDiscover({ anchors: body.anchors, count: body.count }, env));
        }
        case "explain_match": {
          const login = body.candidate?.trim() ?? body.login?.trim();
          if (!login) return secureJsonResponse({ error: "Missing 'candidate'" }, { status: 400 });
          const list = await env.LOOKOUT_KV.list({ prefix: "alert:" });
          for (const k of list.keys) {
            if (!k.name.endsWith(`:${login}`)) continue;
            const raw = await env.LOOKOUT_KV.get(k.name);
            if (raw) return secureJsonResponse(JSON.parse(raw));
          }
          return secureJsonResponse({ error: "No stored alert for that candidate" }, { status: 404 });
        }
        case "record_outcome": {
          const login = body.login?.trim();
          const status = body.status as OutcomeStatus;
          if (!login || !OUTCOME_STATUSES.includes(status)) return secureJsonResponse({ error: "Need 'login' + valid 'status'" }, { status: 400 });
          return secureJsonResponse(await recordOutcome(env.LOOKOUT_KV, login, status, body.note ?? ""));
        }
        default:
          return secureJsonResponse({ error: "Unknown intent. Valid: rank_search_results, discover_people, explain_match, record_outcome, get_lens_version" }, { status: 400 });
      }
    }

    return secureJsonResponse({ error: "Not found" }, { status: 404 });
  },

  // ── Cron Handler — dispatches by schedule string ─────────────
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    if (controller.cron === "0 15 1 * *") {
      // Monthly digest
      ctx.waitUntil(
        buildMonthlyDigest(env).then(async (digest) => {
          await notifyNtfy(env, "Lookout monthly digest", digest, false);
          await env.LOOKOUT_KV.put(`digest_report:${new Date().toISOString().slice(0, 10)}`, digest, { expirationTtl: 60 * 60 * 24 * 365 });
          console.log("Lookout monthly digest sent");
        }).catch((e) => console.error("Lookout monthly digest failed:", e)),
      );
      return;
    }
    // Daily: the same pipeline POST /cron/run exercises — no test-path drift
    ctx.waitUntil(
      runDailyPipeline(env)
        .then((r) => console.log(`Lookout daily: lens ${r.lens_version ?? "REFRESH-FAILED"} (${r.lens_state}) → ${r.anchor}: ${r.new_candidates} new, ${r.alerts} alerts, deadman_paged=${r.deadman_paged}`))
        .catch((e) => console.error("Lookout scheduled run failed:", e)),
    );
  },
} satisfies ExportedHandler<Env>;
