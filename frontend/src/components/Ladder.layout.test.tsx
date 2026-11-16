import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { sipCall, sipMessage } from "../test-fixtures";
import type { Call } from "../types";
import { Ladder } from "./Ladder";

vi.mock("../hooks/useElementWidth", () => ({ useElementWidth: () => mockWidth }));
let mockWidth = 1200;

function callBetween(endpoints: string[]): Call {
  const m = (index: number, src: string, dst: string) =>
    sipMessage({ index, timestamp: index, src, dst, method: "INVITE" });
  return sipCall([m(0, endpoints[0], endpoints[1]), m(1, endpoints[1], endpoints[0])], { endpoints });
}

function laneXs(container: HTMLElement): number[] {
  return [...container.querySelectorAll("line.lane-line")].map((l) => Number(l.getAttribute("x1")));
}

describe("<Ladder /> layout", () => {
  it("spans rows across the pane when it is wider than the ladder", () => {
    mockWidth = 1200;
    const { container } = render(
      <Ladder call={callBetween(["a:1", "b:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );

    for (const rect of container.querySelectorAll("rect.row-bg")) {
      expect(rect.getAttribute("width")).toBe("1200");
    }
  });

  it("spreads lanes to fill the pane, clamped to 200..420 px apart", () => {
    mockWidth = 1200;
    const wide = render(
      <Ladder call={callBetween(["a:1", "b:1", "c:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );
    const [x0, x1, x2] = laneXs(wide.container);
    expect([x1 - x0, x2 - x1]).toEqual([420, 420]);
    wide.unmount();

    mockWidth = 600;
    const narrow = render(
      <Ladder call={callBetween(["a:1", "b:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );
    const [y0, y1] = laneXs(narrow.container);
    // 600 px pane minus the 110 px time column and 120 px right pad.
    expect(y1 - y0).toBe(370);
    narrow.unmount();

    mockWidth = 300;
    const cramped = render(
      <Ladder call={callBetween(["a:1", "b:1", "c:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );
    const [z0, z1] = laneXs(cramped.container);
    expect(z1 - z0).toBe(200);
  });
});
