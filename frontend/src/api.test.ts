import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchSession, uploadPcap } from "./api";

const upload = () => uploadPcap(new File(["x"], "a.pcap"));

function respondWith(body: string, status: number) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status })));
}

describe("uploadPcap errors", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("throws FastAPI's detail string", async () => {
    respondWith('{"detail":"pcap too large (max 100 MB)"}', 413);
    await expect(upload()).rejects.toThrow("pcap too large (max 100 MB)");
  });

  it("falls back to the HTTP status for a non-JSON body", async () => {
    respondWith("<html>Bad Gateway</html>", 502);
    await expect(upload()).rejects.toThrow(/^HTTP 502$/);
  });

  it("falls back to the HTTP status when detail is not a string", async () => {
    respondWith('{"detail":[{"msg":"x"}]}', 422);
    await expect(upload()).rejects.toThrow(/^HTTP 422$/);
  });

  it("explains a network failure in words", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(upload()).rejects.toThrow(
      "Couldn't reach the pcap-viz server. Is it still running?",
    );
  });
});

describe("fetchSession errors", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("throws the server's detail string", async () => {
    respondWith('{"detail":"session not found"}', 404);
    await expect(fetchSession("s1")).rejects.toThrow(/^session not found$/);
  });
});
