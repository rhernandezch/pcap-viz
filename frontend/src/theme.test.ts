import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { applyThemePreference, useThemePreference } from "./theme";

const STORAGE_KEY = "pcap-viz:theme";

afterEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe("applyThemePreference", () => {
  it("sets data-theme on <html> for an explicit preference", () => {
    applyThemePreference("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("removes data-theme for system so the OS setting applies", () => {
    document.documentElement.dataset.theme = "light";
    applyThemePreference("system");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });
});

describe("useThemePreference", () => {
  it("starts from the stored preference", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify("light"));
    const { result } = renderHook(() => useThemePreference());
    expect(result.current[0]).toBe("light");
  });

  it("falls back to system when the stored value is invalid", () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify("purple"));
    const { result } = renderHook(() => useThemePreference());
    expect(result.current[0]).toBe("system");
  });

  it("cycles system → light → dark → system", () => {
    const { result } = renderHook(() => useThemePreference());
    const seen = [result.current[0]];

    for (let i = 0; i < 3; i++) {
      act(() => result.current[1]());
      seen.push(result.current[0]);
    }

    expect(seen).toEqual(["system", "light", "dark", "system"]);
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("cycling persists the preference and applies it to <html>", () => {
    const { result } = renderHook(() => useThemePreference());

    act(() => result.current[1]());

    expect(result.current[0]).toBe("light");
    expect(localStorage.getItem(STORAGE_KEY)).toBe('"light"');
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
