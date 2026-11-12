import { useState } from "react";
import { readStored, writeStored } from "./storage";

export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "pcap-viz:theme";
const CYCLE: ThemePreference[] = ["system", "light", "dark"];

const isThemePreference = (v: unknown): v is ThemePreference =>
  CYCLE.includes(v as ThemePreference);

function nextThemePreference(p: ThemePreference): ThemePreference {
  return CYCLE[(CYCLE.indexOf(p) + 1) % CYCLE.length];
}

// "system" leaves <html> without data-theme, so `color-scheme: light dark` in
// styles.css follows the OS setting live.
export function applyThemePreference(p: ThemePreference): void {
  if (p === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = p;
}

export function storedThemePreference(): ThemePreference {
  return readStored(STORAGE_KEY, "system", isThemePreference);
}

export function useThemePreference(): [ThemePreference, () => void] {
  const [preference, setPreference] = useState(storedThemePreference);
  const cycle = () => {
    const next = nextThemePreference(preference);
    setPreference(next);
    writeStored(STORAGE_KEY, next);
    applyThemePreference(next);
  };
  return [preference, cycle];
}
