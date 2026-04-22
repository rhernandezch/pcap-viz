import type { ParseResponse, ParseResult } from "./types";

export async function uploadPcap(file: File): Promise<ParseResponse> {
  const form = new FormData();
  form.append("file", file);
  const resp = await fetch("/api/parse", { method: "POST", body: form });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`upload failed (${resp.status}): ${text}`);
  }
  return resp.json();
}

export async function fetchSession(sessionId: string): Promise<ParseResult> {
  const resp = await fetch(`/api/session/${sessionId}`);
  if (!resp.ok) throw new Error(`session fetch failed (${resp.status})`);
  return resp.json();
}

export async function fetchPreloadSessionId(): Promise<string | null> {
  const resp = await fetch("/api/preload");
  if (!resp.ok) return null;
  const body = (await resp.json()) as { session_id: string | null };
  return body.session_id ?? null;
}
