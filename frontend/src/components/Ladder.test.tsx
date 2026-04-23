import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Call, SipMessage } from "../types";
import { Ladder } from "./Ladder";

function msg(overrides: Partial<SipMessage> & { index: number }): SipMessage {
  return {
    timestamp: 0,
    src: "10.0.0.1:5060",
    dst: "10.0.0.2:5060",
    transport: "UDP",
    method: null,
    status_code: null,
    status_phrase: null,
    request_line: null,
    status_line: null,
    cseq: "",
    call_id: "c1",
    from_uri: "",
    to_uri: "",
    headers: {},
    body: null,
    ...overrides,
  };
}

function sampleCall(): Call {
  const a = "10.0.0.1:5060";
  const b = "10.0.0.2:5060";
  return {
    call_id: "c1",
    endpoints: [a, b],
    started_at: 0,
    ended_at: 0.5,
    from_uri: "",
    to_uri: "",
    message_count: 3,
    messages: [
      msg({ index: 0, timestamp: 0, method: "INVITE", src: a, dst: b }),
      msg({
        index: 1,
        timestamp: 0.1,
        status_code: 100,
        status_phrase: "Trying",
        src: b,
        dst: a,
      }),
      msg({
        index: 2,
        timestamp: 0.5,
        status_code: 200,
        status_phrase: "OK",
        src: b,
        dst: a,
      }),
    ],
  };
}

describe("<Ladder />", () => {
  it("renders the empty state when no call is selected", () => {
    render(<Ladder call={null} selectedIndex={null} onSelect={() => {}} />);
    expect(screen.getByText(/select a call/i)).toBeInTheDocument();
  });

  it("renders lane labels, arrow labels, and time annotations for a call", () => {
    render(<Ladder call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);

    expect(screen.getByText("10.0.0.1:5060")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2:5060")).toBeInTheDocument();

    expect(screen.getByText("INVITE")).toBeInTheDocument();
    expect(screen.getByText("100 Trying")).toBeInTheDocument();
    expect(screen.getByText("200 OK")).toBeInTheDocument();

    expect(screen.getByText("+0ms")).toBeInTheDocument();
    expect(screen.getByText("+100ms")).toBeInTheDocument();
    expect(screen.getByText("+500ms")).toBeInTheDocument();
  });

  it("invokes onSelect with the message index when a row is clicked", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <Ladder call={sampleCall()} selectedIndex={null} onSelect={onSelect} />,
    );

    const rows = container.querySelectorAll("g.row");
    expect(rows.length).toBe(3);
    (rows[1] as SVGGElement).dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("gives self-loop rows extra vertical space so the U-curve doesn't overlap the next row", () => {
    const a = "10.0.0.1:5060";
    const b = "10.0.0.2:5060";
    const call: Call = {
      call_id: "c1",
      endpoints: [a, b],
      started_at: 0,
      ended_at: 0.5,
      from_uri: "",
      to_uri: "",
      message_count: 3,
      messages: [
        // Regular arrow
        msg({ index: 0, timestamp: 0, method: "INVITE", src: a, dst: b }),
        // Self-loop (src === dst)
        msg({ index: 1, timestamp: 0.1, method: "OPTIONS", src: a, dst: a }),
        // Regular arrow after — its row must start below the self-loop's U.
        msg({
          index: 2,
          timestamp: 0.5,
          status_code: 200,
          status_phrase: "OK",
          src: b,
          dst: a,
        }),
      ],
    };

    const { container } = render(
      <Ladder call={call} selectedIndex={null} onSelect={() => {}} />,
    );

    const bgs = Array.from(container.querySelectorAll("rect.row-bg"));
    expect(bgs).toHaveLength(3);

    const y0 = Number(bgs[0].getAttribute("y"));
    const h0 = Number(bgs[0].getAttribute("height"));
    const y1 = Number(bgs[1].getAttribute("y"));
    const h1 = Number(bgs[1].getAttribute("height"));
    const y2 = Number(bgs[2].getAttribute("y"));

    // Rows stack tightly with no gaps or overlaps.
    expect(y1).toBe(y0 + h0);
    expect(y2).toBe(y1 + h1);

    // The self-loop row is taller than a regular row, so there's room for the
    // U-curve (which drops ~h1-32 px) without spilling into row 2.
    expect(h1).toBeGreaterThan(h0);
  });
});
