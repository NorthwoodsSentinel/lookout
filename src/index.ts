// Lookout — identity-lensed search through your daemon profile
// Brave Search API → Claude re-ranking → daemon-filtered results
// v0.2 adds /discover — find values-aligned humans on GitHub

interface Env {
  BRAVE_SEARCH_KEY: string;
  ANTHROPIC_API_KEY: string;
  LOOKOUT_API_KEY: string;
  GITHUB_TOKEN: string;
  ENVIRONMENT: string;
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
}

interface DiscoverResult {
  login: string;
  name: string | null;
  bio: string | null;
  html_url: string;
  values_score: number;
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
): Promise<DaemonResult[]> {
  const resultsBlock = results
    .map((r, i) => `[${i + 1}] ${r.title}\n    URL: ${r.url}\n    ${r.description}`)
    .join("\n\n");

  const prompt = `You are a daemon — a personalized search filter for a specific human. Your job is to re-rank search results based on how useful they are to THIS person, not to a generic user.

DAEMON PROFILE:
${DAEMON_PROFILE}

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
): Promise<DiscoverResult[]> {
  if (candidates.length === 0) return [];

  const block = candidates.map((c, i) => `[${i + 1}]\n${dossier(c)}`).join("\n\n");

  const prompt = `You are a values-alignment filter for Rob Chuvala. Your job is to read GitHub candidate profiles and rank them by how strongly they match Rob's values.

${VALUES_PROFILE}

CANDIDATES:
${block}

Return ONLY valid JSON — no markdown fences, no preamble. Use this exact format:
[
  {
    "index": 1,
    "values_score": 9,
    "values_notes": "2-3 sentences explaining the specific signals",
    "suggested_intro": "one short paragraph Rob could send",
    "reach_via": ["github", "blog:https://...", "email:..."]
  }
]

Where "index" is the 1-based candidate number. Only include candidates with values_score >= 6. Order by values_score descending. Cap at 15 results.`;

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
    values_score: number;
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
      return {
        login: c.login,
        name: c.name,
        bio: c.bio,
        html_url: c.html_url,
        values_score: r.values_score,
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

  let daemonResults: DaemonResult[];
  try {
    daemonResults = await daemonRerank(query, braveResults, env.ANTHROPIC_API_KEY);
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
      ts: new Date().toISOString(),
      error: "Search temporarily unavailable — showing unranked results",
    };
  }

  return {
    query,
    results: daemonResults.slice(0, count),
    daemon: "lookout",
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
  const loginToAnchors = new Map<string, Set<string>>();
  for (const anchor of anchors) {
    let logins: string[];
    try {
      logins = await fetchContributors(anchor, env.GITHUB_TOKEN, perAnchor);
    } catch {
      continue;
    }
    for (const login of logins) {
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

  // Phase 3: re-rank via Claude
  let ranked: DiscoverResult[];
  try {
    ranked = await valuesRerank(candidates, env.ANTHROPIC_API_KEY);
  } catch (e) {
    return {
      mode,
      total_candidates: candidates.length,
      results: [],
      daemon: "lookout-discover",
      ts: new Date().toISOString(),
      error: "Re-ranking temporarily unavailable",
    };
  }

  return {
    mode,
    total_candidates: candidates.length,
    results: ranked.slice(0, count),
    daemon: "lookout-discover",
    ts: new Date().toISOString(),
  };
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
      return secureJsonResponse({
        status: "ok",
        daemon: "lookout",
        version: "0.2",
        features: ["search", "discover"],
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

    return secureJsonResponse({ error: "Not found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
