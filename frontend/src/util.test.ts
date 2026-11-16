import { describe, expect, it } from "vitest";
import type { Call, SipMessage } from "./types";
import {
  arrowClass,
  callStateOf,
  filterCalls,
  formatDelta,
  formatDuration,
  formatOffset,
  labelOf,
  plural,
  shortUri,
} from "./util";

function msg(overrides: Partial<SipMessage>): SipMessage {
  return {
    index: 0,
    timestamp: 0,
    src: "10.0.0.1:5060",
    dst: "10.0.0.2:5060",
    transport: "UDP",
    method: null,
    status_code: null,
    status_phrase: null,
    request_line: null,
    status_line: null,
    cseq: "",
    call_id: "",
    from_uri: "",
    to_uri: "",
    headers: {},
    body: null,
    sdp: null,
    ...overrides,
  };
}

function call(messages: SipMessage[]): Call {
  return {
    call_id: "c1",
    endpoints: ["10.0.0.1:5060", "10.0.0.2:5060"],
    started_at: 0,
    ended_at: 0,
    from_uri: "",
    to_uri: "",
    message_count: messages.length,
    messages,
  };
}

describe("shortUri", () => {
  it("extracts sip URI from Name-Addr form", () => {
    expect(shortUri('"Alice" <sip:alice@example.com>;tag=a1')).toBe("alice@example.com");
  });

  it("strips sips: prefix", () => {
    expect(shortUri("<sips:bob@secure.example.com>")).toBe("bob@secure.example.com");
  });

  it("handles bare sip: URI without angle brackets", () => {
    expect(shortUri("sip:carol@example.com;tag=c2")).toBe("carol@example.com");
  });

  it("returns ? for empty input", () => {
    expect(shortUri("")).toBe("?");
  });
});

describe("formatDuration", () => {
  it("renders sub-second as ms", () => {
    expect(formatDuration(0.25)).toBe("250ms");
  });

  it("renders sub-minute as 0.0s", () => {
    expect(formatDuration(12.34)).toBe("12.3s");
  });

  it("renders multi-minute as m..s with zero-padded seconds", () => {
    expect(formatDuration(125)).toBe("2m05s");
  });

  it("returns em-dash for negative or non-finite input", () => {
    expect(formatDuration(-1)).toBe("—");
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe("—");
    expect(formatDuration(Number.NaN)).toBe("—");
  });
});

describe("callStateOf", () => {
  const invite = (cseq = "1 INVITE") => msg({ method: "INVITE", cseq });
  const resp = (code: number, cseq = "1 INVITE", phrase = "") =>
    msg({ status_code: code, cseq, status_phrase: phrase, status_line: `SIP/2.0 ${code} ${phrase}`.trim() });

  it("is Completed when the INVITE got a 2xx and a BYE followed", () => {
    const c = call([invite(), resp(200, "1 INVITE", "OK"), msg({ method: "ACK", cseq: "1 ACK" }), msg({ method: "BYE", cseq: "2 BYE" }), resp(200, "2 BYE", "OK")]);
    expect(callStateOf(c)).toEqual({ label: "Completed", tone: "ok", title: "SIP/2.0 200 OK" });
  });

  it("is In call when the INVITE got a 2xx and no BYE was seen", () => {
    expect(callStateOf(call([invite(), resp(200, "1 INVITE", "OK")])).label).toBe("In call");
  });

  it("is Cancelled on a 487 or a CANCEL without a final response", () => {
    expect(callStateOf(call([invite(), resp(487, "1 INVITE", "Request Terminated")])).label).toBe("Cancelled");
    expect(callStateOf(call([invite(), msg({ method: "CANCEL", cseq: "1 CANCEL" }), resp(200, "1 CANCEL", "OK")])).tone).toBe("warn");
  });

  it("is Redirected <code> on a 3xx", () => {
    expect(callStateOf(call([invite(), resp(302, "1 INVITE", "Moved Temporarily")]))).toMatchObject({ label: "Redirected 302", tone: "warn" });
  });

  it("is Rejected <code> on a 4xx to 6xx other than 487", () => {
    expect(callStateOf(call([invite(), resp(486, "1 INVITE", "Busy Here")]))).toEqual({ label: "Rejected 486", tone: "error", title: "SIP/2.0 486 Busy Here" });
  });

  it("is Unanswered when the INVITE got no final response", () => {
    expect(callStateOf(call([invite(), resp(100, "1 INVITE", "Trying")]))).toMatchObject({ label: "Unanswered", tone: "neutral" });
  });

  it("judges a credential-challenged call by the retried INVITE", () => {
    const c = call([invite(), resp(407, "1 INVITE", "Proxy Authentication Required"), msg({ method: "ACK", cseq: "1 ACK" }), invite("2 INVITE"), resp(200, "2 INVITE", "OK")]);
    expect(callStateOf(c)).toMatchObject({ label: "In call", tone: "active" });
  });

  it("gives a non-INVITE dialog with only a provisional reply a neutral tone", () => {
    expect(callStateOf(call([msg({ method: "SUBSCRIBE", cseq: "1 SUBSCRIBE" }), resp(100, "1 SUBSCRIBE", "Trying")]))).toMatchObject({ label: "SUBSCRIBE 100", tone: "neutral" });
  });

  it("ignores re-INVITE responses", () => {
    const c = call([invite(), resp(200), invite("2 INVITE"), resp(491, "2 INVITE"), msg({ method: "BYE", cseq: "3 BYE" })]);
    expect(callStateOf(c).label).toBe("Completed");
  });

  it("names non-INVITE dialogs by method and last status", () => {
    expect(callStateOf(call([msg({ method: "OPTIONS", cseq: "1 OPTIONS" }), resp(200, "1 OPTIONS", "OK")]))).toMatchObject({ label: "OPTIONS 200", tone: "ok" });
    expect(callStateOf(call([msg({ method: "REGISTER", cseq: "1 REGISTER" }), resp(401, "1 REGISTER")])).tone).toBe("error");
    expect(callStateOf(call([msg({ method: "OPTIONS", cseq: "1 OPTIONS" })]))).toMatchObject({ label: "OPTIONS", tone: "neutral" });
  });

  it("is a dash for a call with no messages", () => {
    expect(callStateOf(call([]))).toMatchObject({ label: "—", tone: "neutral" });
  });
});

describe("filterCalls", () => {
  const a = { ...call([msg({ method: "OPTIONS", cseq: "1 OPTIONS" })]), call_id: "keepalive@x", from_uri: "<sip:sbc@x>", to_uri: "<sip:bot@x>" };
  const b = { ...call([msg({ method: "INVITE", cseq: "1 INVITE" }), msg({ status_code: 486, cseq: "1 INVITE" })]), call_id: "busy@x", from_uri: '"Alice" <sip:alice@x>', to_uri: "<sip:Bob@x>", endpoints: ["192.0.2.7:5060"] };

  it("keeps every call for a blank query", () => {
    expect(filterCalls([a, b], "  ")).toEqual([a, b]);
  });

  it("matches From, To, Call-ID, endpoints and state, case-insensitively", () => {
    expect(filterCalls([a, b], "ALICE")).toEqual([b]);
    expect(filterCalls([a, b], "bob@")).toEqual([b]);
    expect(filterCalls([a, b], "keepalive")).toEqual([a]);
    expect(filterCalls([a, b], "192.0.2.7")).toEqual([b]);
    expect(filterCalls([a, b], "rejected 486")).toEqual([b]);
  });
});

describe("labelOf", () => {
  it("returns method for requests", () => {
    expect(labelOf(msg({ method: "INVITE" }))).toBe("INVITE");
  });

  it("returns status code + phrase for responses", () => {
    expect(labelOf(msg({ status_code: 200, status_phrase: "OK" }))).toBe("200 OK");
  });

  it("returns bare status code when phrase is missing", () => {
    expect(labelOf(msg({ status_code: 100, status_phrase: null }))).toBe("100");
  });
});

describe("arrowClass", () => {
  it("classifies requests", () => {
    expect(arrowClass(msg({ method: "BYE" }))).toBe("request");
  });

  it("classifies responses by hundreds digit", () => {
    expect(arrowClass(msg({ status_code: 100 }))).toBe("response-1xx");
    expect(arrowClass(msg({ status_code: 180 }))).toBe("response-1xx");
    expect(arrowClass(msg({ status_code: 200 }))).toBe("response-2xx");
    expect(arrowClass(msg({ status_code: 302 }))).toBe("response-3xx");
    expect(arrowClass(msg({ status_code: 486 }))).toBe("response-4xx");
    expect(arrowClass(msg({ status_code: 503 }))).toBe("response-5xx");
    expect(arrowClass(msg({ status_code: 603 }))).toBe("response-6xx");
  });

  it("returns empty string when neither method nor status is set", () => {
    expect(arrowClass(msg({}))).toBe("");
  });
});

describe("plural", () => {
  it("uses the singular only for exactly one", () => {
    expect(plural(1, "call")).toBe("1 call");
    expect(plural(0, "call")).toBe("0 calls");
    expect(plural(1234, "packet")).toBe("1234 packets");
  });
});

describe("formatOffset and formatDelta", () => {
  it("use milliseconds below one second and two decimals above", () => {
    expect([0, 0.0999, 1, 125].map(formatOffset)).toEqual(["+0ms", "+100ms", "+1.00s", "+125.00s"]);
    expect([0, 0.0999, 1, 125].map(formatDelta)).toEqual(["Δ0ms", "Δ100ms", "Δ1.00s", "Δ125.00s"]);
  });
});
