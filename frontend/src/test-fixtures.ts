import type { Call, SipMessage } from "./types";

// One builder per parsed shape, so a field added to the API changes one place.
export function sipMessage(overrides: Partial<SipMessage> = {}): SipMessage {
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
    call_id: "c1",
    from_uri: "",
    to_uri: "",
    headers: {},
    body: null,
    sdp: null,
    ...overrides,
  };
}

export function sipCall(messages: SipMessage[], overrides: Partial<Call> = {}): Call {
  return {
    call_id: messages[0]?.call_id ?? "c1",
    endpoints: [...new Set(messages.flatMap((m) => [m.src, m.dst]))],
    started_at: messages[0]?.timestamp ?? 0,
    ended_at: messages[messages.length - 1]?.timestamp ?? 0,
    from_uri: "",
    to_uri: "",
    message_count: messages.length,
    messages,
    ...overrides,
  };
}
