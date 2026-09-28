import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { runRadar, RADAR_TOPICS_KEY, RADAR_SOURCES_KEY } from "../src/radar";

function fakeKV() {
  const m = new Map<string, string>();
  return { m, kv: { get: async (k: string) => m.get(k) ?? null, put: async (k: string, v: string) => { m.set(k, v); } } as any };
}

const FEED = (items: [string, string][]) =>
  `<feed>${items.map(([t, u]) => `<entry><title>${t}</title><link href="${u}" rel="alternate"/><link title="pdf" href="${u}.pdf" rel="related"/></entry>`).join("")}</feed>`;

let feedItems: [string, string][] = [];
let pings: { title: string; body: string }[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  pings = [];
  feedItems = [["Paper A", "https://arxiv.org/abs/1"]];
  globalThis.fetch = (async (url: any, init?: any) => {
    const u = String(url);
    if (u.startsWith("https://ntfy.sh/")) { pings.push({ title: init.headers.Title, body: init.body }); return new Response("ok"); }
    return new Response(FEED(feedItems));
  }) as any;
});
afterEach(() => { globalThis.fetch = realFetch; });

const topic = [{ tag: "t", relates_to: "r", query: "q" }];
const source = [{ name: "S", relates_to: "src", url: "https://feed", kind: "feed", score: 9, filter: false }];

function setup(results: any[]) {
  const { m, kv } = fakeKV();
  m.set(RADAR_TOPICS_KEY, JSON.stringify(topic));
  m.set(RADAR_SOURCES_KEY, JSON.stringify(source));
  const env = { LOOKOUT_KV: kv, RADAR_NTFY_TOPIC: "x" };
  const deps = { search: async () => results, listAlerts: async () => [] };
  return { m, env, deps };
}

describe("radar", () => {
  test("only >=8 search hits reach the front page; a 9 pings once, never twice", async () => {
    const { m, env, deps } = setup([
      { url: "https://a", title: "A", daemon_score: 9, daemon_note: "n" },
      { url: "https://b", title: "B", daemon_score: 7, daemon_note: "n" },
    ]);
    const r1 = await runRadar(env, deps);
    const fp = JSON.parse(m.get("radar:frontpage")!);
    expect(fp.items.map((i: any) => i.url)).toEqual(["https://a"]);
    expect(r1.verdict).toBe("ok");
    expect(pings.filter((p) => p.title.startsWith("Radar [9]")).length).toBe(1);
    pings = [];
    await runRadar(env, deps);
    expect(pings.filter((p) => p.title.startsWith("Radar [")).length).toBe(0);
  });

  test("first run seeds a source silently; a later new post surfaces and pings", async () => {
    const { m, env, deps } = setup([]);
    await runRadar(env, deps);
    expect(JSON.parse(m.get("radar:frontpage")!).items.length).toBe(0);
    expect(pings.length).toBe(0);
    feedItems = [["Paper A", "https://arxiv.org/abs/1"], ["Paper B", "https://arxiv.org/abs/2"]];
    await runRadar(env, deps);
    const items = JSON.parse(m.get("radar:frontpage")!).items;
    expect(items.map((i: any) => i.url)).toEqual(["https://arxiv.org/abs/2"]);   // abs link, not the related .pdf
    expect(pings.some((p) => p.title.startsWith("Radar sources: 1"))).toBe(true);
  });

  test("every topic failing is loud: pages DOWN and throws", async () => {
    const { m, env } = setup([]);
    const deps = { search: async () => { throw new Error("brave 500"); }, listAlerts: async () => [] };
    await expect(runRadar(env, deps)).rejects.toThrow("all topics failed");
    expect(pings.some((p) => p.title === "Radar producer DOWN")).toBe(true);
    expect(JSON.parse(m.get("radar:last_run")!).verdict).toBe("fail");
  });

  test("builders: read alerts are excluded", async () => {
    const { m, env } = setup([]);
    const deps = { search: async () => [], listAlerts: async () => [
      { login: "u1", values_score: 9, read: true }, { login: "u2", values_score: 8, read: false }] };
    await runRadar(env, deps);
    expect(JSON.parse(m.get("radar:frontpage")!).builders.map((b: any) => b.login)).toEqual(["u2"]);
  });
});
