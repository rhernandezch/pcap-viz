import { afterEach, describe, expect, it, vi } from "vitest";
import { readStored, safeStorage, writeStored } from "./storage";

const isString = (v: unknown): v is string => typeof v === "string";

describe("readStored", () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("returns the stored value when it is valid", () => {
    localStorage.setItem("k", JSON.stringify("dark"));
    expect(readStored("k", "system", isString)).toBe("dark");
  });

  it("returns the fallback when nothing is stored", () => {
    expect(readStored("k", "system", isString)).toBe("system");
  });

  it("returns the fallback on invalid JSON", () => {
    localStorage.setItem("k", "{not json");
    expect(readStored("k", "system", isString)).toBe("system");
  });

  it("returns the fallback when the stored value fails validation", () => {
    localStorage.setItem("k", JSON.stringify(42));
    expect(readStored("k", "system", isString)).toBe("system");
  });

  it("returns the fallback when localStorage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });
    expect(readStored("k", "system", isString)).toBe("system");
  });
});

describe("writeStored", () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("stores the value as JSON", () => {
    writeStored("k", { a: 1 });
    expect(localStorage.getItem("k")).toBe('{"a":1}');
  });

  it("swallows quota errors", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(() => writeStored("k", "v")).not.toThrow();
  });
});

describe("safeStorage", () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("passes raw strings through to localStorage", () => {
    safeStorage.setItem("k", "raw");
    expect(safeStorage.getItem("k")).toBe("raw");
  });

  it("reads null when localStorage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });
    expect(safeStorage.getItem("k")).toBeNull();
  });

  it("swallows write errors", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(() => safeStorage.setItem("k", "v")).not.toThrow();
  });
});
