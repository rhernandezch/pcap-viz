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

export function finalStatusOf(call: Call): string {
  for (let i = call.messages.length - 1; i >= 0; i--) {
    const m = call.messages[i];
    if (m.status_code !== null) {
      return `${m.status_code}`;
    }
    if (m.method === "BYE") return "BYE";
    if (m.method === "CANCEL") return "CANCEL";
  }
  return "—";
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
