// Lookout — identity-lensed search through your daemon profile
// Brave Search API → Claude re-ranking → daemon-filtered results

interface Env {
  BRAVE_SEARCH_KEY: string;
  ANTHROPIC_API_KEY: string;
  ENVIRONMENT: string;
}

// ── Daemon Profile (inline for MVP) ────────────────────────────

// ── EDIT THIS ── Your daemon profile controls how results are filtered.
// See: https://danielmiessler.com/blog/launching-daemon-personal-api
const DAEMON_PROFILE = `Name: [Your name]
Role: [Your profession, background, expertise level]
Expertise: [What you already know — helps skip beginner content]
Preferences: [How you like content delivered — code vs theory, practical vs academic, etc]
Already knows: [Topics to skip introductory content for]
Skip: [Types of content you never want — marketing, listicles, beginner tutorials, etc]
Prefer: [Types of sources you trust — GitHub repos, research papers, specific blogs, etc]`;

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
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem 1rem;
    }
    .header {
      text-align: center;
      margin-bottom: 2rem;
    }
    .header h1 {
      color: #58a6ff;
      font-size: 1.5rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .header p {
      color: #484f58;
      font-size: 0.85rem;
      margin-top: 0.3rem;
    }
    form {
      width: 100%;
      max-width: 640px;
      margin-bottom: 2rem;
    }
    input[type="text"] {
      width: 100%;
      padding: 0.75rem 1rem;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-size: 1rem;
      outline: none;
    }
    input[type="text"]:focus {
      border-color: #58a6ff;
    }
    .results {
      width: 100%;
      max-width: 640px;
    }
    .result {
      display: flex;
      gap: 1rem;
      padding: 1rem 0;
      border-bottom: 1px solid #21262d;
    }
    .score {
      flex-shrink: 0;
      width: 2.5rem;
      height: 2.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #1f6feb22;
      border: 1px solid #1f6feb44;
      border-radius: 6px;
      color: #58a6ff;
      font-weight: 700;
      font-size: 1rem;
    }
    .content { flex: 1; min-width: 0; }
    .title {
      color: #58a6ff;
      text-decoration: none;
      font-weight: 600;
      font-size: 1.05rem;
      display: block;
    }
    .title:hover { text-decoration: underline; }
    .note {
      color: #f0883e;
      font-weight: 600;
      font-size: 0.85rem;
      margin: 0.3rem 0;
    }
    .snippet {
      color: #8b949e;
      font-size: 0.85rem;
      line-height: 1.4;
    }
    .url {
      color: #484f58;
      font-size: 0.75rem;
      margin-top: 0.25rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .error {
      color: #f85149;
      background: #f8514922;
      border: 1px solid #f8514944;
      border-radius: 6px;
      padding: 0.75rem 1rem;
      margin-bottom: 1rem;
      max-width: 640px;
      width: 100%;
    }
    .footer {
      margin-top: auto;
      padding-top: 3rem;
      color: #484f58;
      font-size: 0.75rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Lookout — Search Through Your Daemon</h1>
    <p>Identity-lensed search. Your daemon is the filter.</p>
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

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Request Handler ────────────────────────────────────────────

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
      error: `Brave Search failed: ${e instanceof Error ? e.message : String(e)}`,
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
      error: `Claude re-ranking failed (showing raw results): ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  return {
    query,
    results: daemonResults.slice(0, count),
    daemon: "lookout",
    ts: new Date().toISOString(),
  };
}

// ── Worker Entry ───────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check
    if (path === "/health") {
      return Response.json({
        status: "ok",
        daemon: "lookout",
        ts: new Date().toISOString(),
      });
    }

    // Landing page
    if (path === "/" && request.method === "GET") {
      return new Response(renderSearchPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // GET /search?q=...
    if (path === "/search" && request.method === "GET") {
      const query = url.searchParams.get("q")?.trim();
      if (!query) {
        return new Response(renderSearchPage(), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      const data = await handleSearch(query, 5, env);
      return new Response(renderSearchPage(query, data.results, data.error), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // POST /search — JSON API
    if (path === "/search" && request.method === "POST") {
      let body: { query?: string; count?: number };
      try {
        body = (await request.json()) as { query?: string; count?: number };
      } catch {
        return Response.json({ error: "Invalid JSON body" }, { status: 400 });
      }

      const query = body.query?.trim();
      if (!query) {
        return Response.json({ error: "Missing 'query' field" }, { status: 400 });
      }

      const count = Math.min(Math.max(body.count ?? 5, 1), 10);
      const data = await handleSearch(query, count, env);
      return Response.json(data);
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
