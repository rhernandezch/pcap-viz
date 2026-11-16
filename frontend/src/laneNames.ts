import { useState } from "react";
import { readStored, writeStored } from "./storage";
import type { Call } from "./types";

const STORAGE_KEY = "pcap-viz:lane-aliases";
const MAX_ALIAS_LENGTH = 40;
const NAME_HEADERS = ["user-agent", "server"];

type Aliases = Record<string, string>;

const isAliases = (v: unknown): v is Aliases =>
  typeof v === "object" &&
  v !== null &&
  !Array.isArray(v) &&
  Object.values(v).every((name) => typeof name === "string");

function defaultLaneName(call: Call, endpoint: string): string | null {
  const first = call.messages.find((m) => m.src === endpoint);
  if (!first) return null;
  const headers = Object.entries(first.headers);
  for (const wanted of NAME_HEADERS) {
    const hit = headers.find(([name]) => name.toLowerCase() === wanted);
    if (hit) return hit[1];
  }
  return null;
}

export const normalizeLaneName = (name: string): string =>
  name.trim().slice(0, MAX_ALIAS_LENGTH);

export function laneLabel(aliases: Aliases, call: Call, endpoint: string): string {
  return aliases[endpoint] ?? defaultLaneName(call, endpoint) ?? "Unnamed";
}

export function useLaneAliases(): [Aliases, (endpoint: string, name: string) => void] {
  const [aliases, setAliases] = useState(() => readStored(STORAGE_KEY, {}, isAliases));
  const rename = (endpoint: string, name: string) => {
    const next = { ...aliases };
    const normalized = normalizeLaneName(name);
    if (normalized) next[endpoint] = normalized;
    else delete next[endpoint];
    setAliases(next);
    writeStored(STORAGE_KEY, next);
  };
  return [aliases, rename];
}
