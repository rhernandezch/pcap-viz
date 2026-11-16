import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { SipMessage } from "./types";
import { laneLabel, useLaneAliases } from "./laneNames";
import { sipCall, sipMessage } from "./test-fixtures";

const A = "10.0.0.1:5060";
const B = "10.0.0.2:5060";

const msg = (src: string, headers: Record<string, string>) =>
  sipMessage({ src, dst: src === A ? B : A, headers });

const call = (messages: SipMessage[]) => sipCall(messages, { endpoints: [A, B] });

describe("laneLabel", () => {
  it("prefers the saved alias", () => {
    const c = call([msg(A, { "User-Agent": "Asterisk PBX" })]);
    expect(laneLabel({ [A]: "Voice bot" }, c, A)).toBe("Voice bot");
  });

  it("uses the User-Agent of the first message sent by the endpoint", () => {
    const c = call([msg(B, { "User-Agent": "late" }), msg(A, { "User-Agent": "Asterisk PBX" }), msg(A, { "User-Agent": "other" })]);
    expect(laneLabel({}, c, A)).toBe("Asterisk PBX");
  });

  it("falls back to the Server header", () => {
    expect(laneLabel({}, call([msg(A, { Server: "Kamailio" })]), A)).toBe("Kamailio");
  });

  it("looks headers up case-insensitively", () => {
    expect(laneLabel({}, call([msg(A, { "user-agent": "bot" })]), A)).toBe("bot");
  });

  it("is Unnamed without an alias or a naming header", () => {
    expect(laneLabel({}, call([msg(A, {})]), A)).toBe("Unnamed");
    expect(laneLabel({}, call([msg(A, {})]), B)).toBe("Unnamed");
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
