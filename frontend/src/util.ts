import type { Call, SipMessage } from "./types";

export function shortUri(uri: string): string {
  if (!uri) return "?";
  // Extract sip:user@host from a Name-Addr like '"Alice" <sip:alice@example.com>;tag=a1'
  const m = uri.match(/<([^>]+)>/);
  const inner = m ? m[1] : uri;
  const sip = inner.replace(/^sips?:/, "");
  return sip.split(";")[0];
}

export function formatDuration(seconds: number): string {
  if (!isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds - m * 60);
  return `${m}m${s.toString().padStart(2, "0")}s`;
}

type CallTone = "ok" | "active" | "warn" | "error" | "neutral";

interface CallState {
  label: string;
  tone: CallTone;
  title: string;
}

const AUTH_CHALLENGES = [401, 407];
const callStates = new WeakMap<Call, CallState>();

// Parsed calls never change, so each call's state is computed once.
export function callStateOf(call: Call): CallState {
  let state = callStates.get(call);
  if (!state) {
    state = deriveCallState(call);
    callStates.set(call, state);
  }
  return state;
}

function deriveCallState(call: Call): CallState {
  const invites = call.messages.filter((m) => m.method === "INVITE");
  if (invites.length === 0) {
    const request = call.messages.find((m): m is SipMessage & { method: string } => m.method !== null);
    const last = [...call.messages]
      .reverse()
      .find((m): m is SipMessage & { status_code: number } => m.status_code !== null);
    if (!request) return { label: "—", tone: "neutral", title: "" };
    if (!last) return { label: request.method, tone: "neutral", title: "" };
    const code = last.status_code;
    return {
      label: `${request.method} ${code}`,
      tone: code < 200 ? "neutral" : code < 300 ? "ok" : "error",
      title: last.status_line ?? "",
    };
  }
  const finalFor = (invite: SipMessage) =>
    call.messages.find((m) => (m.status_code ?? 0) >= 200 && m.cseq === invite.cseq);
  // A 401/407 challenge creates no dialog, so the next INVITE is the
  // authenticated retry; later INVITEs after an answer are re-INVITEs.
  let final = finalFor(invites[0]);
  for (let i = 1; i < invites.length && AUTH_CHALLENGES.includes(final?.status_code ?? 0); i++) {
    final = finalFor(invites[i]);
  }
  const title = final?.status_line ?? "";
  const code = final?.status_code ?? null;
  if (code !== null && code < 300) {
    const ended = call.messages.some((m) => m.method === "BYE");
    return ended ? { label: "Completed", tone: "ok", title } : { label: "In call", tone: "active", title };
  }
  if (code === 487 || (code === null && call.messages.some((m) => m.method === "CANCEL"))) {
    return { label: "Cancelled", tone: "warn", title };
  }
  if (code !== null && code < 400) return { label: `Redirected ${code}`, tone: "warn", title };
  if (code !== null) return { label: `Rejected ${code}`, tone: "error", title };
  return { label: "Unanswered", tone: "neutral", title };
}

export function filterCalls(calls: Call[], query: string): Call[] {
  const q = query.trim().toLowerCase();
  if (!q) return calls;
  return calls.filter((c) =>
    [shortUri(c.from_uri), shortUri(c.to_uri), c.call_id, ...c.endpoints, callStateOf(c).label]
      .some((field) => field.toLowerCase().includes(q)),
  );
}

export function formatClock(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleTimeString("en-GB", { timeZone: "UTC", hour12: false });
}

export function labelOf(m: SipMessage): string {
  if (m.method) return m.method;
  if (m.status_code !== null) {
    return m.status_phrase
      ? `${m.status_code} ${m.status_phrase}`
      : `${m.status_code}`;
  }
  return "?";
}

export function arrowClass(m: SipMessage): string {
  if (m.method) return "request";
  if (m.status_code === null) return "";
  const hundreds = Math.floor(m.status_code / 100);
  return `response-${hundreds}xx`;
}

export function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function formatSpan(seconds: number): string {
  return seconds < 1 ? `${Math.round(seconds * 1000)}ms` : `${seconds.toFixed(2)}s`;
}

export const formatOffset = (seconds: number) => `+${formatSpan(seconds)}`;
export const formatDelta = (seconds: number) => `Δ${formatSpan(seconds)}`;

export function formatUtc(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
}

export function messageTiming(call: Call, pos: number): { offset: string; delta: string | null } {
  const m = call.messages[pos];
  return {
    offset: formatOffset(m.timestamp - call.started_at),
    delta: pos > 0 ? formatDelta(m.timestamp - call.messages[pos - 1].timestamp) : null,
  };
}
