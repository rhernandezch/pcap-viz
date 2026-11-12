import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { applyThemePreference, nextThemePreference, useThemePreference } from "./theme";

const STORAGE_KEY = "pcap-viz:theme";

afterEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe("nextThemePreference", () => {
  it("cycles system → light → dark → system", () => {
    expect(nextThemePreference("system")).toBe("light");
    expect(nextThemePreference("light")).toBe("dark");
    expect(nextThemePreference("dark")).toBe("system");
  });
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

  it("cycling persists the preference and applies it to <html>", () => {
    const { result } = renderHook(() => useThemePreference());

    act(() => result.current[1]());

    expect(result.current[0]).toBe("light");
    expect(localStorage.getItem(STORAGE_KEY)).toBe('"light"');
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
