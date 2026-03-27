# Lookout

A personal search engine that filters web results through your daemon profile. Instead of getting generic results optimized for everyone, Lookout re-ranks results based on who you are -- your expertise, preferences, and what you actually find useful. Google personalizes search based on surveillance. Lookout personalizes based on declaration.

## How it works

1. Your search query hits the [Brave Search API](https://brave.com/search/api/) for raw web results
2. Those results are sent to Claude (Anthropic) along with your daemon profile
3. Claude re-ranks, filters, and annotates each result based on how useful it is to *you specifically*
4. You get back 5 results scored 1-10 with a note explaining why each one matters to you

The whole thing runs on a single Cloudflare Worker. No database, no state, no tracking.

## What's a daemon profile?

The concept comes from Daniel Miessler's [daemon / personal API](https://danielmiessler.com/blog/launching-daemon-personal-api) -- a structured declaration of who you are, what you know, and how you want information delivered. Your daemon profile lives in `src/index.ts` as a template string. Edit it to match you.

## Quick start

```bash
# Fork this repo
git clone https://github.com/YOUR_USERNAME/lookout.git
cd lookout

# Install dependencies
npm install

# Edit your daemon profile in src/index.ts
# Replace the template fields with your actual identity

# Set your API keys
wrangler secret put BRAVE_SEARCH_KEY
wrangler secret put ANTHROPIC_API_KEY

# Deploy
wrangler deploy
```

For local development:

```bash
# Create .dev.vars with your keys (see .dev.vars.example)
cp .dev.vars.example .dev.vars
# Edit .dev.vars with real keys

# Run locally
npm run dev
```

## Cost

This is designed to be cheap enough to run personally:

- **Brave Search**: Free tier gives you 2,000 queries/month (paid plans start at $5/mo for 20K)
- **Anthropic (Claude Sonnet)**: ~$0.003 per search (re-ranking 15 results with a short prompt)
- **Cloudflare Workers**: Free tier gives you 100K requests/day

At typical personal use (10-30 searches/day), you're looking at under $5/month total.

## API

Lookout also exposes a JSON API:

```bash
# POST /search
curl -X POST https://your-worker.workers.dev/search \
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
  "ts": "2026-03-27T..."
}
```

## Project structure

```
src/index.ts     # Everything — daemon profile, search, re-ranking, UI
wrangler.toml    # Cloudflare Worker config
```

Yes, it's one file. That's the point.

---

## Northwoods Sentinel Labs

Part of the [Northwoods Sentinel Labs](https://northwoodssentinel.com) ecosystem -- open-source tools for human-centered AI.

[Blog](https://northwoodssentinel.com) · [Substack](https://substack.com/@chewvala) · [GitHub](https://github.com/NorthwoodsSentinel)
