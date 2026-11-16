import "@testing-library/jest-dom/vitest";

// jsdom has no ResizeObserver, which react-resizable-panels requires.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

// jsdom has no PointerEvent; without it fireEvent.pointer* drops clientX/Y.
if (typeof globalThis.PointerEvent === "undefined") {
  globalThis.PointerEvent = class extends MouseEvent {
    readonly pointerId: number;
    constructor(type: string, init: PointerEventInit = {}) {
      super(type, init);
      this.pointerId = init.pointerId ?? 1;
    }
  } as typeof PointerEvent;
}
