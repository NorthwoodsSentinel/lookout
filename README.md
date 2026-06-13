# Lookout

A personal search engine that filters web results through your daemon profile, plus a discovery mode that finds values-aligned humans on GitHub.

Google personalizes search based on surveillance. Lookout personalizes based on declaration.

## What it does

**`/search`** — your search query hits the [Brave Search API](https://brave.com/search/api/) for raw web results, then Claude re-ranks them against your daemon profile. You get back 5 results scored 1-10 with a one-line note on why each one matters to *you*, specifically.

**`/discover`** — adjacency-mining mode for finding values-aligned humans. Pulls contributors from N anchor repos (defaults: substrate-first projects like `loam`, `mycelia`, `modelcontextprotocol/servers`, `bluesky-social/atproto`), builds a candidate dossier for each (profile + top non-fork repos + topics), then Claude re-ranks against your values profile. Returns ranked candidates with values_score, the signals that landed, a suggested intro paragraph in your voice, and reachable contact paths.

The whole thing runs on a single Cloudflare Worker. No database, no state, no tracking.

## What's a daemon profile?

The concept comes from Daniel Miessler's [daemon / personal API](https://danielmiessler.com/blog/launching-daemon-personal-api) — a structured declaration of who you are, what you know, and how you want information delivered. Your daemon profile lives in `src/index.ts` as a template string (`DAEMON_PROFILE`). Edit it to match you.

For `/discover`, there's a parallel `VALUES_PROFILE` constant that captures what you're looking *for* in other people. Tune it the same way.

## Quick start

```bash
# Fork this repo
git clone https://github.com/YOUR_USERNAME/lookout.git
cd lookout

# Install dependencies (bun preferred, npm works)
bun install

# Edit your daemon profile + values profile in src/index.ts
# Replace the template fields with your actual identity

# Set your secrets
wrangler secret put BRAVE_SEARCH_KEY     # Brave Search API token
wrangler secret put ANTHROPIC_API_KEY    # Claude API key
wrangler secret put LOOKOUT_API_KEY      # bearer token YOU pick (protects all non-/health endpoints)
wrangler secret put GITHUB_TOKEN         # GitHub PAT, read-only scope (for /discover rate limit headroom)

# Deploy
wrangler deploy
```

For local development:

```bash
# Create .dev.vars with your keys (see .dev.vars.example)
cp .dev.vars.example .dev.vars
# Edit .dev.vars with real keys

# Run locally
bun run dev
```

## Auth

Every endpoint except `/health` requires a bearer token. Pass `LOOKOUT_API_KEY` via either:

- HTTP header: `Authorization: Bearer YOUR_KEY`
- Query param: `?key=YOUR_KEY` (for the HTML UI, which also stores it in sessionStorage)

Unauthorized requests return `401`.

## Rate limits

- `/search` — 10 requests/minute/IP
- `/discover` — 2 requests/minute/IP (each call makes ~150-200 GitHub API requests + one big Claude call)

## Security

- HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy applied to every response
- Repo slug and GitHub login validated against strict regex (anti path-injection)
- Anchor count capped at 10, candidate count capped at 60, output capped at 25
- Error responses are sanitized — no leakage of GitHub or Claude API error details
- Query length capped at 500 characters

## Cost

Cheap enough to run personally:

- **Brave Search**: Free tier 2,000 queries/month; paid starts at $5/mo for 20K
- **Anthropic (Claude Sonnet)**: ~$0.003 per `/search` call, ~$0.10 per `/discover` call
- **GitHub API**: Free with a PAT (5,000 req/hr authenticated rate limit; `/discover` consumes ~150-200 per call)
- **Cloudflare Workers**: Free tier 100K requests/day

At typical personal use (10-30 searches/day, occasional discover runs), under $5/month total.

## API

### POST /search

```bash
curl -X POST https://your-worker.workers.dev/search \
  -H "Authorization: Bearer YOUR_LOOKOUT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "rust async runtime internals", "count": 5}'
```

Response:

```json
{
  "query": "rust async runtime internals",
  "results": [
    {
      "title": "...",
      "url": "...",
      "snippet": "...",
      "daemon_score": 9,
      "daemon_note": "Deep implementation walkthrough with code — exactly your level"
    }
  ],
  "daemon": "lookout",
  "ts": "2026-06-13T..."
}
```

### POST /discover

```bash
curl -X POST https://your-worker.workers.dev/discover \
  -H "Authorization: Bearer YOUR_LOOKOUT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "adjacency",
    "anchors": ["NorthwoodsSentinel/loam", "modelcontextprotocol/servers"],
    "count": 15,
    "per_anchor": 15
  }'
```

`anchors` is optional. If omitted, uses the defaults baked into `src/index.ts`. `count` capped at 25, `per_anchor` between 5 and 30.

Response:

```json
{
  "mode": "adjacency",
  "total_candidates": 42,
  "results": [
    {
      "login": "...",
      "name": "...",
      "bio": "...",
      "html_url": "https://github.com/...",
      "values_score": 9,
      "values_notes": "Three sentences explaining the specific signals.",
      "suggested_intro": "A paragraph you could send to start the conversation.",
      "reach_via": ["github", "blog:https://...", "email:..."],
      "contributed_to": ["NorthwoodsSentinel/loam", "NorthwoodsSentinel/mycelia"]
    }
  ],
  "daemon": "lookout-discover",
  "ts": "2026-06-13T..."
}
```

### GET /health

No auth required. Returns `{ status: "ok", daemon: "lookout", version: "0.2", features: ["search", "discover"], ts: "..." }`.

## Project structure

```
src/index.ts     # Everything — daemon profile, values profile, search, discover, UI, auth, rate limits
wrangler.toml    # Cloudflare Worker config
```

Yes, it's one file. That's the point.

## Versions

- **v0.2** (June 2026) — added `/discover` for values-aligned human discovery on GitHub
- **v0.1** (March 2026) — initial release: identity-lensed search via Brave + Claude

---

## Northwoods Sentinel Labs

Part of the [Northwoods Sentinel Labs](https://northwoodssentinel.com) ecosystem — open-source tools for human-centered AI.

[Blog](https://northwoodssentinel.com) · [Substack](https://chewvala.substack.com) · [GitHub](https://github.com/NorthwoodsSentinel)
