import type { ParseResponse, ParseResult } from "./types";

export const PCAP_FILE_TYPES = ".pcap,.pcapng,application/vnd.tcpdump.pcap";

function parseApiError(status: number, bodyText: string): string {
  try {
    const detail: unknown = JSON.parse(bodyText)?.detail;
    if (typeof detail === "string") return detail;
  } catch {
    // Not JSON (a proxy page, an empty body): fall back to the status.
  }
  return `HTTP ${status}`;
}

export async function uploadPcap(file: File): Promise<ParseResponse> {
  const form = new FormData();
  form.append("file", file);
  let resp: Response;
  try {
    resp = await fetch("/api/parse", { method: "POST", body: form });
  } catch {
    throw new Error("Couldn't reach the pcap-viz server. Is it still running?");
  }
  if (!resp.ok) throw new Error(parseApiError(resp.status, await resp.text()));
  return resp.json();
}

export async function fetchSession(sessionId: string): Promise<ParseResult> {
  const resp = await fetch(`/api/session/${sessionId}`);
  if (!resp.ok) throw new Error(parseApiError(resp.status, await resp.text()));
  return resp.json();
}

export async function fetchPreloadSessionId(): Promise<string | null> {
  const resp = await fetch("/api/preload");
  if (!resp.ok) return null;
  const body = (await resp.json()) as { session_id: string | null };
  return body.session_id ?? null;
}
