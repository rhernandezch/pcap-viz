import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { Call, SipMessage } from "./types";
import { defaultLaneName, laneLabel, useLaneAliases } from "./laneNames";

const A = "10.0.0.1:5060";
const B = "10.0.0.2:5060";

function msg(src: string, headers: Record<string, string>): SipMessage {
  return {
    index: 0, timestamp: 0, src, dst: src === A ? B : A, transport: "UDP",
    method: null, status_code: null, status_phrase: null, request_line: null, status_line: null,
    cseq: "", call_id: "c", from_uri: "", to_uri: "", headers, body: null, sdp: null,
  };
}

function call(messages: SipMessage[]): Call {
  return {
    call_id: "c", endpoints: [A, B], started_at: 0, ended_at: 1,
    from_uri: "", to_uri: "", message_count: messages.length, messages,
  };
}

describe("defaultLaneName", () => {
  it("uses the User-Agent of the first message sent by the endpoint", () => {
    const c = call([msg(B, { "User-Agent": "late" }), msg(A, { "User-Agent": "Asterisk PBX" }), msg(A, { "User-Agent": "other" })]);
    expect(defaultLaneName(c, A)).toBe("Asterisk PBX");
  });

  it("falls back to the Server header", () => {
    expect(defaultLaneName(call([msg(A, { Server: "Kamailio" })]), A)).toBe("Kamailio");
  });

  it("looks headers up case-insensitively", () => {
    expect(defaultLaneName(call([msg(A, { "user-agent": "bot" })]), A)).toBe("bot");
  });

  it("returns null when neither header is present", () => {
    expect(defaultLaneName(call([msg(A, {})]), A)).toBeNull();
  });
});

describe("laneLabel", () => {
  it("prefers the alias, then the default name, then Unnamed", () => {
    const c = call([msg(A, { "User-Agent": "Asterisk PBX" })]);
    expect(laneLabel({ [A]: "Voice bot" }, c, A)).toBe("Voice bot");
    expect(laneLabel({}, c, A)).toBe("Asterisk PBX");
    expect(laneLabel({}, c, B)).toBe("Unnamed");
  });
});

describe("useLaneAliases", () => {
  afterEach(() => localStorage.clear());

  it("persists a trimmed name capped at 40 characters and deletes it on empty", () => {
    const { result } = renderHook(() => useLaneAliases());

    act(() => result.current[1](A, "  Voice bot  "));
    expect(result.current[0]).toEqual({ [A]: "Voice bot" });
    expect(JSON.parse(localStorage.getItem("pcap-viz:lane-aliases")!)).toEqual({ [A]: "Voice bot" });

    act(() => result.current[1](A, "x".repeat(50)));
    expect(result.current[0][A]).toHaveLength(40);

    act(() => result.current[1](A, "   "));
    expect(result.current[0]).toEqual({});
  });

  it("starts empty when the stored value is not a string map", () => {
    localStorage.setItem("pcap-viz:lane-aliases", JSON.stringify({ [A]: 42 }));
    const { result } = renderHook(() => useLaneAliases());
    expect(result.current[0]).toEqual({});
  });
});
