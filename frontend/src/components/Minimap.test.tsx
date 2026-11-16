import { fireEvent, render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { sipCall as call, sipMessage } from "../test-fixtures";
import type { SipMessage } from "../types";
import { Minimap } from "./Minimap";

const msg = (index: number, timestamp: number, overrides: Partial<SipMessage> = {}) =>
  sipMessage({ index, timestamp, method: "INVITE", ...overrides });

const threeMessages = () =>
  call([msg(0, 100), msg(1, 101, { method: null, status_code: 200 }), msg(2, 110)]);

function ticks(container: HTMLElement) {
  return [...container.querySelectorAll("line.minimap-tick")];
}

describe("<Minimap />", () => {
  it("places one tick per message at its time-proportional position", () => {
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={null} selectedIndex={null} onJump={() => {}} />,
    );

    expect(ticks(container).map((t) => t.getAttribute("y1"))).toEqual(["0", "100", "1000"]);
  });

  it("colors ticks like their arrows", () => {
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={null} selectedIndex={null} onJump={() => {}} />,
    );

    expect(ticks(container)[0]).toHaveClass("request");
    expect(ticks(container)[1]).toHaveClass("response-2xx");
  });

  it("marks the visible rows' time span", () => {
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={{ start: 101, end: 110 }} selectedIndex={null} onJump={() => {}} />,
    );

    const box = container.querySelector("rect.viewport")!;
    expect([box.getAttribute("y"), box.getAttribute("height")]).toEqual(["100", "900"]);
  });

  it("selects the message nearest in time to the pointer, also while dragging", () => {
    const onJump = vi.fn();
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={null} selectedIndex={null} onJump={onJump} />,
    );
    const svg = container.querySelector("svg")!;
    // The strip is 1012 px tall, matching the viewBox (1000 plus 6 above and below).
    vi.spyOn(svg, "getBoundingClientRect").mockReturnValue({ top: 0, height: 1012 } as DOMRect);

    // clientY 55 is scale y 49, just before the 100 s / 101 s midpoint at 50.
    fireEvent.pointerDown(svg, { clientY: 55, buttons: 1 });
    expect(onJump).toHaveBeenLastCalledWith(0);

    fireEvent.pointerDown(svg, { clientY: 506, buttons: 1 });
    expect(onJump).toHaveBeenLastCalledWith(1);

    fireEvent.pointerMove(svg, { clientY: 1000, buttons: 1 });
    expect(onJump).toHaveBeenLastCalledWith(2);

    fireEvent.pointerMove(svg, { clientY: 6, buttons: 0 });
    expect(onJump).toHaveBeenCalledTimes(3);
  });

  it("is hidden for calls with fewer than 2 messages", () => {
    const { container } = render(
      <Minimap call={call([msg(0, 100)])} visibleRange={null} selectedIndex={null} onJump={() => {}} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("puts every tick at the top for a zero-duration call", () => {
    const { container } = render(
      <Minimap call={call([msg(0, 100), msg(1, 100)])} visibleRange={null} selectedIndex={null} onJump={() => {}} />,
    );

    expect(ticks(container).map((t) => t.getAttribute("y1"))).toEqual(["0", "0"]);
  });

  it("keeps a thin band for a very short visible span", () => {
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={{ start: 101, end: 101.001 }} selectedIndex={null} onJump={() => {}} />,
    );

    expect(container.querySelector("rect.viewport")!.getAttribute("height")).toBe("4");
  });

  it("only reacts to the primary button and skips re-selecting the selected message", () => {
    const onJump = vi.fn();
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={null} selectedIndex={1} onJump={onJump} />,
    );
    const svg = container.querySelector("svg")!;
    vi.spyOn(svg, "getBoundingClientRect").mockReturnValue({ top: 0, height: 1012 } as DOMRect);

    fireEvent.pointerDown(svg, { clientY: 1000, button: 2 });
    fireEvent.pointerDown(svg, { clientY: 506, button: 0 });

    expect(onJump).not.toHaveBeenCalled();
  });

  it("tells mouse users the strip can be clicked", () => {
    const { container } = render(
      <Minimap call={threeMessages()} visibleRange={null} selectedIndex={null} onJump={() => {}} />,
    );

    expect(container.querySelector("svg title")).toHaveTextContent("Click or drag to jump to a message");
  });
});
