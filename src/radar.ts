/**
 * radar.ts — the research radar, ported from Lares (PAI/TOOLS/RadarPull.ts + RadarSources.ts)
 * into lookout on 2026-09-27 (Rob: "these things need to live in cloudflare").
 *
 * Why here: the Lares cron went dark 2026-09-25 → 09-27 because the laptop was off. Logic now
 * lives on Cloudflare; Lares keeps only a thin cache (GET /radar → the statusline file).
 *
 * What it does (semantics preserved from RadarPull):
 *   1. TOPICS — each watch-topic runs through lookout's own search (daemon-lens scored, this-week
 *      freshness). Hits scoring >= FRONTPAGE_MIN_SCORE enter a 7-day rolling STORE.
 *   2. SOURCES — named publishers + arXiv queries, diffed against a per-source seen-set. The FIRST
 *      run for a source seeds silently so adding a source never floods. New posts enter the store
 *      at the source's score.
 *   3. BUILDERS — unread /discover alerts (people), carried onto the front page.
 *   4. FRONT PAGE — top-N of the store by recency-weighted score, written to KV (radar:frontpage).
 *   5. PINGS — ntfy once per genuinely-new item at/above PING_THRESHOLD; never re-alert.
 * Topics and sources live in KV (config:radar_topics / config:radar_sources), seeded from the
 * defaults below and editable without a deploy — same rule as anchors.
 *
 * Fail-loud: if every topic errors, the run pages "Radar producer DOWN" and records a FAIL run.
 */

export interface RadarEnv {
  LOOKOUT_KV: KVNamespace;
  NTFY_TOPIC?: string;
  RADAR_NTFY_TOPIC?: string;   // Rob's phone topic; falls back to NTFY_TOPIC
}

export interface RadarDeps {
  search: (query: string) => Promise<Array<{ url?: string; title?: string; daemon_score?: number; daemon_note?: string }>>;
  listAlerts: () => Promise<Array<Record<string, any>>>;
}

type Topic = { tag: string; relates_to: string; query: string };
type Source = { name: string; relates_to: string; url: string; score: number; filter: boolean } & (
  | { kind: "feed" }
  | { kind: "listing"; linkPrefix: string }
);

const FRONTPAGE_CAP = 5;
const FRONTPAGE_MIN_SCORE = 8;
const PING_THRESHOLD = 9;
const WINDOW_DAYS = 7;

// Rewritten 2026-09-27 from where Rob is now (verification, faithfulness, attribution, promotion
// gates, MCP state, durable execution, authority); two August topics kept.
export const DEFAULT_TOPICS: Topic[] = [
  { tag: "faithfulness-detection", relates_to: "claim→evidence gate / HHEM + revcheck", query: "hallucination faithfulness detection for LLM summaries and agent memory claim-level verification against source" },
  { tag: "attribution-errors", relates_to: "voice fidelity / actor-swap detector", query: "attribution errors who said what speaker swap in LLM summaries and meeting notes detection" },
  { tag: "memory-promotion-gate", relates_to: "an assertion cannot promote its own trust", query: "verifying LLM-extracted memory against source before storing agent long-term memory corruption error propagation" },
  { tag: "provenance-memory", relates_to: "substrate / Day Metabolism / SEEM class", query: "provenance-grounded episodic memory for LLM agents raw evidence pointers retrieval" },
  { tag: "mcp-state-mrtr", relates_to: "puzzlebox / MCP MRTR / Tasks", query: "Model Context Protocol multi round-trip requests tasks input_required stateful tool workflow state machine" },
  { tag: "durable-agent-execution", relates_to: "Day Metabolism runner / saga receipts", query: "durable execution saga log for AI agents resume receipts idempotent steps workflow verification" },
  { tag: "agent-authority-delegation", relates_to: "Mycelia delegation / margin-wake authority", query: "AI agent authority delegation capability attenuation least privilege tokens multi-agent" },
  { tag: "agent-reference-monitor", relates_to: "capsule (Straight Edge) / deny-by-default", query: "capability-bound execution gate reference monitor for AI agent tool calls deny by default" },
  { tag: "mcp-tool-trust-boundary", relates_to: "fleet security pipeline", query: "MCP model context protocol server security tool call trust boundary prompt injection" },
];

const arxiv = (q: string) =>
  `https://export.arxiv.org/api/query?search_query=${encodeURIComponent(q)}&sortBy=submittedDate&sortOrder=descending&max_results=25`;

export const DEFAULT_SOURCES: Source[] = [
  // Publishers (from RadarSources.ts, 2026-09-16). Google's threat-intel "rss" URL serves HTML, so watch the listing.
  { name: "Google Threat Intelligence (Mandiant/GTIG)", relates_to: "_SWARMREVIEW / NWS swarm review", kind: "listing", score: 9, filter: true,
    url: "https://cloud.google.com/blog/topics/threat-intelligence", linkPrefix: "https://cloud.google.com/blog/topics/threat-intelligence/" },
  { name: "Google Security Blog", relates_to: "_SWARMREVIEW / NWS swarm review", kind: "feed", score: 9, filter: true, url: "https://security.googleblog.com/feeds/posts/default" },
  { name: "Project Zero", relates_to: "_SWARMREVIEW / NWS swarm review", kind: "feed", score: 9, filter: true, url: "https://googleprojectzero.blogspot.com/feeds/posts/default" },
  { name: "Unit 42", relates_to: "_SWARMREVIEW / NWS swarm review", kind: "feed", score: 9, filter: true, url: "https://unit42.paloaltonetworks.com/feed/" },
  { name: "Trail of Bits", relates_to: "_SWARMREVIEW / NWS swarm review", kind: "feed", score: 9, filter: true, url: "https://blog.trailofbits.com/feed/" },
  // Papers (new 2026-09-27 — SEEM reached us only because Rob brought it). Query-scoped, so no word
  // filter; score 8 = front-page eligible but below the ping line (papers must not flood the phone).
  { name: "arXiv: faithfulness/hallucination", relates_to: "claim→evidence gate", kind: "feed", score: 8, filter: false,
    url: arxiv("cat:cs.CL AND (abs:faithfulness OR abs:hallucination) AND (abs:summary OR abs:summarization OR abs:memory)") },
  { name: "arXiv: agent memory", relates_to: "substrate / provenance memory", kind: "feed", score: 8, filter: false,
    url: arxiv("(cat:cs.CL OR cat:cs.AI) AND abs:\"agent memory\"") },
  { name: "arXiv: agent security", relates_to: "fleet security / reference monitor", kind: "feed", score: 8, filter: false,
    url: arxiv("cat:cs.CR AND (abs:\"LLM agent\" OR abs:\"AI agent\" OR abs:\"agentic\")") },
];

const RELEVANT = new Set(["ai", "agent", "agents", "agentic", "llm", "llms", "gemini", "claude", "gpt", "model", "models",
  "vulnerability", "vulnerabilities", "harness", "autonomous", "fuzzing", "codemender"]);
const RELEVANT_PHRASES = ["code review", "source code", "big sleep", "zero-day", "vulnerability discovery"];
function isRelevant(text: string): boolean {
  const t = text.toLowerCase();
  if (RELEVANT_PHRASES.some((p) => t.includes(p) || t.includes(p.replace(/ /g, "-")))) return true;
  return t.split(/[^a-z0-9]+/).filter(Boolean).some((w) => RELEVANT.has(w));
}

const decode = (s: string) =>
  s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&amp;/g, "&").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, " ").trim();

async function fetchItems(s: Source): Promise<{ url: string; title: string }[]> {
  const res = await fetch(s.url, { headers: { "User-Agent": "Mozilla/5.0 (lookout radar)" }, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${res.status}`);
  const body = await res.text();
  if (s.kind === "listing") {
    const urls = new Set<string>();
    for (const m of body.matchAll(/href="([^"]+)"/g)) {
      const u = m[1];
      if (u.startsWith(s.linkPrefix) && /^[a-z0-9-]+$/.test(u.slice(s.linkPrefix.length))) urls.add(u);
    }
    return [...urls].map((url) => ({ url, title: url.slice(s.linkPrefix.length).replace(/-/g, " ") }));
  }
  const items: { url: string; title: string }[] = [];
  for (const block of body.split(/<item[\s>]|<entry[\s>]/).slice(1)) {
    const title = decode(block.match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1] ?? "");
    const link = block.match(/<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/)?.[1]
      ?? block.match(/<link>([\s\S]*?)<\/link>/)?.[1]
      ?? block.match(/<link(?![^>]*rel=["'](?:replies|self|edit|related)["'])[^>]*href=["']([^"']+)["']/)?.[1];
    if (title && link) items.push({ url: decode(link), title });
  }
  return items;
}

async function kvJson<T>(kv: KVNamespace, key: string, fallback: T): Promise<T> {
  try { const raw = await kv.get(key); return raw ? JSON.parse(raw) as T : fallback; } catch { return fallback; }
}

async function configList<T>(kv: KVNamespace, key: string, defaults: T[]): Promise<T[]> {
  const v = await kvJson<T[] | null>(kv, key, null);
  if (Array.isArray(v) && v.length > 0) return v;
  await kv.put(key, JSON.stringify(defaults));
  return defaults;
}

export const RADAR_TOPICS_KEY = "config:radar_topics";
export const RADAR_SOURCES_KEY = "config:radar_sources";

async function ping(env: RadarEnv, title: string, body: string, priority: "high" | "urgent") {
  const topic = env.RADAR_NTFY_TOPIC || env.NTFY_TOPIC;
  if (!topic) return;
  await fetch(`https://ntfy.sh/${topic}`, {
    method: "POST",
    headers: { Title: title.replace(/[^\x20-\x7E]/g, ""), Priority: priority, Tags: "satellite" },
    body, signal: AbortSignal.timeout(15_000),
  }).catch(() => {});
}

export async function runRadar(env: RadarEnv, deps: RadarDeps, now = new Date()) {
  const kv = env.LOOKOUT_KV;
  const nowIso = now.toISOString(), nowMs = now.getTime();
  const topics = await configList(kv, RADAR_TOPICS_KEY, DEFAULT_TOPICS);
  const sources = await configList(kv, RADAR_SOURCES_KEY, DEFAULT_SOURCES);
  const store = await kvJson<Record<string, any>>(kv, "radar:store", {});
  const seen = await kvJson<Record<string, string>>(kv, "radar:seen", {});
  const sourcesSeen = await kvJson<Record<string, string>>(kv, "radar:sources_seen", {});
  const bseen = await kvJson<Record<string, string>>(kv, "radar:builders_seen", {});
  const newlySurfaced: any[] = [];
  const errors: string[] = [];

  // 1. Topics
  let topicFailures = 0;
  for (const t of topics) {
    try {
      for (const r of await deps.search(t.query)) {
        if (!r?.url || typeof r.daemon_score !== "number" || r.daemon_score < FRONTPAGE_MIN_SCORE) continue;
        const isNew = !store[r.url];
        store[r.url] = { score: Math.max(r.daemon_score, store[r.url]?.score ?? 0), title: r.title, url: r.url,
          relates_to: t.relates_to, topic: t.tag, note: r.daemon_note, ts: store[r.url]?.ts ?? nowIso };
        if (isNew && !seen[r.url]) { seen[r.url] = nowIso; newlySurfaced.push(store[r.url]); }
      }
    } catch (e) { topicFailures++; errors.push(`${t.tag}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  if (topicFailures === topics.length) {
    await kv.put("radar:last_run", JSON.stringify({ at: nowIso, verdict: "fail", errors }));
    await ping(env, "Radar producer DOWN", `lookout radar: all ${topics.length} topics failed at ${nowIso} — ${errors[0]}. Do not trust the quiet.`, "high");
    throw new Error(`radar: all topics failed: ${errors[0]}`);
  }

  // 2. Sources (first run per source seeds silently)
  for (const s of sources) {
    try {
      const items = await fetchItems(s);
      if (items.length === 0) { errors.push(`source ${s.name}: 0 items (parser or page changed)`); continue; }
      const seeded = Object.keys(sourcesSeen).some((k) => k.startsWith(`${s.name}|`));
      for (const it of items) {
        const key = `${s.name}|${it.url}`;
        if (sourcesSeen[key]) continue;
        sourcesSeen[key] = nowIso;
        if (!seeded || (s.filter && !isRelevant(it.title)) || store[it.url]) continue;
        store[it.url] = { score: s.score, title: `${s.name}: ${it.title}`, url: it.url, relates_to: s.relates_to,
          topic: "source-follow", note: "followed source, new post", ts: nowIso };
        if (!seen[it.url]) { seen[it.url] = nowIso; newlySurfaced.push(store[it.url]); }
      }
    } catch (e) { errors.push(`source ${s.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }

  // 3. Rolling window + recency-weighted front page (0.6/day decay, as RadarPull)
  for (const [url, it] of Object.entries(store)) {
    if (nowMs - (Date.parse(it.ts) || nowMs) > WINDOW_DAYS * 86_400_000) delete store[url];
  }
  const eff = (it: any) => it.score - Math.min(Math.max(0, (nowMs - (Date.parse(it.ts) || nowMs)) / 86_400_000), WINDOW_DAYS) * 0.6;
  const items = Object.values(store).sort((a: any, b: any) => eff(b) - eff(a)).slice(0, FRONTPAGE_CAP);

  // 4. Builders: unread /discover alerts (RadarPull filtered on `acknowledged`, a field alerts never carry)
  let builders: any[] = [];
  try {
    builders = (await deps.listAlerts())
      .filter((b) => !b.read)
      .map((b) => ({ login: b.login, values_score: b.public_values_alignment ?? b.values_score, url: b.html_url,
        notes: b.values_notes, reach_via: b.reach_via, intro: b.suggested_intro }))
      .sort((a, b) => (b.values_score ?? 0) - (a.values_score ?? 0));
  } catch (e) { errors.push(`alerts: ${e instanceof Error ? e.message : String(e)}`); }

  const frontpage = { generated: nowIso, count: items.length, items, builders: builders.slice(0, 8), errors, producer: "lookout/radar" };
  await Promise.all([
    kv.put("radar:frontpage", JSON.stringify(frontpage)),
    kv.put("radar:store", JSON.stringify(store)),
    kv.put("radar:seen", JSON.stringify(seen)),
    kv.put("radar:sources_seen", JSON.stringify(sourcesSeen)),
  ]);

  // 5. Pings — once per genuinely-new item at/above threshold
  const pings = newlySurfaced.filter((f) => f.score >= PING_THRESHOLD);
  const sourcePings = pings.filter((f) => f.topic === "source-follow");
  if (sourcePings.length) await ping(env, `Radar sources: ${sourcePings.length} new post(s)`,
    sourcePings.slice(0, 3).map((f) => `${f.title}\n${f.url}`).join("\n\n") + (sourcePings.length > 3 ? "\n..." : ""), "high");
  const topicPings = pings.filter((f) => f.topic !== "source-follow");
  if (topicPings.length) { const top = topicPings[0];
    await ping(env, `Radar [${top.score}] ${top.relates_to}`, `${top.title}\n${top.url}`, top.score >= 10 ? "urgent" : "high"); }

  const firstBuilderRun = Object.keys(bseen).length === 0;
  const newBuilders = builders.filter((b) => b.login && !bseen[b.login] && (b.values_score ?? 0) >= PING_THRESHOLD);
  for (const b of builders) if (b.login && !bseen[b.login]) bseen[b.login] = nowIso;
  await kv.put("radar:builders_seen", JSON.stringify(bseen));
  if (!firstBuilderRun && newBuilders.length) await ping(env, `Radar builders: ${newBuilders.length} kindred`,
    `${newBuilders.slice(0, 5).map((b) => `${b.login} (${b.values_score})`).join(", ")}${newBuilders.length > 5 ? " ..." : ""}\nlookout /alerts`, "high");

  const summary = { at: nowIso, verdict: "ok", fresh: items.length, surfaced: newlySurfaced.length, pinged: pings.length,
    builders: builders.length, builders_new: newBuilders.length, errors: errors.length, error_detail: errors.slice(0, 10) };
  await kv.put("radar:last_run", JSON.stringify(summary));
  return summary;
}
