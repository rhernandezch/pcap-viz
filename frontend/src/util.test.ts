import { describe, expect, it } from "vitest";
import type { Call, SipMessage } from "./types";
import { arrowClass, finalStatusOf, formatDuration, labelOf, shortUri } from "./util";

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

describe("finalStatusOf", () => {
  it("returns the last status code when the call ended on a response", () => {
    const c = call([
      msg({ method: "INVITE" }),
      msg({ status_code: 200, status_phrase: "OK" }),
      msg({ method: "ACK" }),
      msg({ method: "BYE" }),
      msg({ status_code: 487, status_phrase: "Request Terminated" }),
    ]);
    expect(finalStatusOf(c)).toBe("487");
  });

  it("returns BYE when the last message is a BYE with no response after it", () => {
    const c = call([
      msg({ method: "INVITE" }),
      msg({ status_code: 200, status_phrase: "OK" }),
      msg({ method: "BYE" }),
    ]);
    expect(finalStatusOf(c)).toBe("BYE");
  });

  it("returns CANCEL when the last message is a CANCEL", () => {
    const c = call([msg({ method: "INVITE" }), msg({ method: "CANCEL" })]);
    expect(finalStatusOf(c)).toBe("CANCEL");
  });

  it("returns — for empty call", () => {
    expect(finalStatusOf(call([]))).toBe("—");
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
