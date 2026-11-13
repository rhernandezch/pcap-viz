import { afterEach, describe, expect, it, vi } from "vitest";
import { parseApiError, uploadPcap } from "./api";

describe("parseApiError", () => {
  it("reads FastAPI's detail string", () => {
    expect(parseApiError(413, '{"detail":"pcap too large (max 100 MB)"}')).toBe(
      "pcap too large (max 100 MB)",
    );
  });

  it("falls back to the HTTP status for a non-JSON body", () => {
    expect(parseApiError(502, "<html>Bad Gateway</html>")).toBe("HTTP 502");
  });

  it("falls back to the HTTP status when detail is not a string", () => {
    expect(parseApiError(422, '{"detail":[{"msg":"x"}]}')).toBe("HTTP 422");
  });
});

describe("uploadPcap", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("explains a network failure in words", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

    await expect(uploadPcap(new File(["x"], "a.pcap"))).rejects.toThrow(
      "Couldn't reach the pcap-viz server. Is it still running?",
    );
  });

  it("throws the server's reason on an error status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response('{"detail":"failed to parse pcap"}', { status: 400 })),
    );

    await expect(uploadPcap(new File(["x"], "a.pcap"))).rejects.toThrow("failed to parse pcap");
  });
});
