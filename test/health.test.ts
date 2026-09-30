// /health reports deployment identity (CF_VERSION_METADATA) SEPARATELY from the constant app version.
import { describe, expect, test } from "bun:test";
import worker from "../src/index";

const kv = { get: async () => null, put: async () => {}, list: async () => ({ keys: [] }) } as any;
const ctx = { waitUntil() {}, passThroughOnException() {} } as any;
const health = async (env: Record<string, unknown>) => {
  const r = await (worker as any).fetch(new Request("https://lookout.example/health"), { ENVIRONMENT: "test", LOOKOUT_KV: kv, ...env }, ctx);
  return { status: r.status, body: await r.json() as any };
};

describe("/health deployment identity", () => {
  test("with the version_metadata binding: deployment = {id, tag, timestamp}; app version unchanged", async () => {
    const md = { id: "83c89f8e-4794-4b6c-a31c-be177606f46d", tag: "df47dde", timestamp: "2026-10-01T15:00:00.000Z" };
    const { status, body } = await health({ CF_VERSION_METADATA: md });
    expect(status).toBe(200);
    expect(body.deployment).toEqual(md);
    expect(body.version).toBe("0.6");
    expect(body.daemon).toBe("lookout");
  });
  test("without the binding: deployment = null (never a fabricated identity); app version unchanged", async () => {
    const { body } = await health({});
    expect(body.deployment).toBeNull();
    expect(body.version).toBe("0.6");
  });
});
