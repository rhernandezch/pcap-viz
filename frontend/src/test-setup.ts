import "@testing-library/jest-dom/vitest";

// jsdom has no ResizeObserver, which react-resizable-panels requires.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}
