import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Call, SipMessage } from "../types";
import { Ladder } from "./Ladder";

vi.mock("../hooks/useElementWidth", () => ({ useElementWidth: () => mockWidth }));
let mockWidth = 1200;

function threeLaneCall(endpoints: string[]): Call {
  const m = (index: number, src: string, dst: string): SipMessage => ({
    index, timestamp: index, src, dst, transport: "UDP", method: "INVITE", status_code: null,
    status_phrase: null, request_line: null, status_line: null, cseq: "", call_id: "c",
    from_uri: "", to_uri: "", headers: {}, body: null, sdp: null,
  });
  return {
    call_id: "c", endpoints, started_at: 0, ended_at: 1, from_uri: "", to_uri: "",
    message_count: 2, messages: [m(0, endpoints[0], endpoints[1]), m(1, endpoints[1], endpoints[0])],
  };
}

function laneXs(container: HTMLElement): number[] {
  return [...container.querySelectorAll("line.lane-line")].map((l) => Number(l.getAttribute("x1")));
}

describe("<Ladder /> layout", () => {
  it("spans rows across the pane when it is wider than the ladder", () => {
    mockWidth = 1200;
    const { container } = render(
      <Ladder call={threeLaneCall(["a:1", "b:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );

    for (const rect of container.querySelectorAll("rect.row-bg")) {
      expect(rect.getAttribute("width")).toBe("1200");
    }
  });

  it("spreads lanes to fill the pane, clamped to 200..420 px apart", () => {
    mockWidth = 1200;
    const wide = render(
      <Ladder call={threeLaneCall(["a:1", "b:1", "c:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );
    const [x0, x1, x2] = laneXs(wide.container);
    expect([x1 - x0, x2 - x1]).toEqual([420, 420]);
    wide.unmount();

    mockWidth = 600;
    const narrow = render(
      <Ladder call={threeLaneCall(["a:1", "b:1"])} selectedIndex={null} onSelect={() => {}} aliases={{}} onRename={() => {}} />,
    );
    const [y0, y1] = laneXs(narrow.container);
    // 600 px pane minus the 110 px time column and 120 px right pad.
    expect(y1 - y0).toBe(370);
  });
});
