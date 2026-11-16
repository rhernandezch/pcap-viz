import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { sipCall, sipMessage as msg } from "../test-fixtures";
import type { Call } from "../types";
import { Ladder } from "./Ladder";

function sampleCall(): Call {
  const a = "10.0.0.1:5060";
  const b = "10.0.0.2:5060";
  return sipCall([
    msg({ index: 0, timestamp: 0, method: "INVITE", src: a, dst: b }),
    msg({ index: 1, timestamp: 0.1, status_code: 100, status_phrase: "Trying", src: b, dst: a }),
    msg({ index: 2, timestamp: 0.5, status_code: 200, status_phrase: "OK", src: b, dst: a }),
  ]);
}

describe("<Ladder />", () => {
  it("renders the empty state when no call is selected", () => {
    render(<Ladder aliases={{}} onRename={() => {}} call={null} selectedIndex={null} onSelect={() => {}} />);
    expect(screen.getByText(/select a call/i)).toBeInTheDocument();
  });

  it("renders lane labels, arrow labels, and time annotations for a call", () => {
    render(<Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);

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
      <Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={onSelect} />,
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
      <Ladder aliases={{}} onRename={() => {}} call={call} selectedIndex={null} onSelect={() => {}} />,
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

  it("shows each lane's name and ip:port in a header outside the svg", () => {
    const c = sampleCall();
    c.messages[0].headers = { "User-Agent": "Asterisk PBX" };
    const { container } = render(
      <Ladder aliases={{ "10.0.0.2:5060": "Voice bot" }} onRename={() => {}} call={c} selectedIndex={null} onSelect={() => {}} />,
    );

    const heads = [...container.querySelectorAll(".lane-head")] as HTMLElement[];
    expect(heads.map((h) => h.textContent)).toEqual([
      "Asterisk PBX10.0.0.1:5060",
      "Voice bot10.0.0.2:5060",
    ]);
    expect(heads[0].closest("svg")).toBeNull();
  });

  it("renames a lane in place: Enter saves, Escape cancels", () => {
    const onRename = vi.fn();
    render(<Ladder aliases={{}} onRename={onRename} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);

    fireEvent.click(screen.getAllByRole("button", { name: /Rename lane/ })[0]);
    const input = screen.getByRole("textbox", { name: "Lane name for 10.0.0.1:5060" });
    fireEvent.change(input, { target: { value: "Voice bot" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onRename).toHaveBeenCalledWith("10.0.0.1:5060", "Voice bot");

    fireEvent.click(screen.getAllByRole("button", { name: /Rename lane/ })[1]);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "nope" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Escape" });
    expect(onRename).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("saves nothing when a rename is left without changes", () => {
    const onRename = vi.fn();
    render(<Ladder aliases={{}} onRename={onRename} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);

    fireEvent.click(screen.getAllByRole("button", { name: /Rename lane/ })[0]);
    fireEvent.blur(screen.getByRole("textbox"));

    expect(onRename).not.toHaveBeenCalled();
  });

  it("saves nothing when a long header-derived name is left unchanged", () => {
    const onRename = vi.fn();
    const c = sampleCall();
    // Longer than the 40-char alias cap, so the capped draft differs from the shown name.
    c.messages[0].headers = { "User-Agent": "FreeSWITCH-mod_sofia/1.10.9-release~64bit-extra" };
    render(<Ladder aliases={{}} onRename={onRename} call={c} selectedIndex={null} onSelect={() => {}} />);

    fireEvent.click(screen.getAllByRole("button", { name: /Rename lane/ })[0]);
    fireEvent.blur(screen.getByRole("textbox"));

    expect(onRename).not.toHaveBeenCalled();
  });

  it("saves nothing when a rename only adds surrounding spaces", () => {
    const onRename = vi.fn();
    render(<Ladder aliases={{}} onRename={onRename} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);

    fireEvent.click(screen.getAllByRole("button", { name: /Rename lane/ })[0]);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: " Unnamed " } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });

    expect(onRename).not.toHaveBeenCalled();
  });

  it("returns focus to the rename button after Enter or Escape", () => {
    render(<Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />);
    const renameFirst = () => screen.getByRole("button", { name: /Rename lane Unnamed \(10.0.0.1:5060\)/ });

    fireEvent.click(renameFirst());
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Escape" });
    expect(renameFirst()).toHaveFocus();

    fireEvent.click(renameFirst());
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "Voice bot" } });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });
    expect(renameFirst()).toHaveFocus();
  });

  it("shows the delta from the previous message on every row but the first", () => {
    const { container } = render(
      <Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />,
    );

    const rows = [...container.querySelectorAll("g.row")] as HTMLElement[];
    expect(rows[0].textContent).not.toContain("Δ");
    expect(within(rows[1]).getByText("Δ100ms")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Δ400ms")).toBeInTheDocument();
  });

  it("makes rows buttons with a descriptive label and one tab stop", () => {
    render(<Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={2} onSelect={() => {}} />);

    const row = screen.getByRole("button", { name: "200 OK, 10.0.0.2:5060 to 10.0.0.1:5060, +500ms" });
    expect(row).toHaveAttribute("aria-pressed", "true");
    const tabStops = screen
      .getAllByRole("button", { name: /, \+/ })
      .filter((r) => r.getAttribute("tabindex") === "0");
    expect(tabStops).toEqual([row]);
  });

  it("selects a focused row with Enter", () => {
    const onSelect = vi.fn();
    render(<Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={onSelect} />);

    fireEvent.keyDown(screen.getByRole("button", { name: /^100 Trying,/ }), { key: "Enter" });

    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("leaves focus on a lane's rename button when the selection moves", () => {
    const props = { aliases: {}, onRename: () => {}, call: sampleCall(), onSelect: () => {} };
    const { rerender } = render(<Ladder {...props} selectedIndex={0} />);
    const rename = screen.getAllByRole("button", { name: /Rename lane/ })[0];
    rename.focus();

    rerender(<Ladder {...props} selectedIndex={1} />);

    expect(rename).toHaveFocus();
  });

  it("moves focus with the selection while focus is in the ladder", () => {
    const props = { aliases: {}, onRename: () => {}, call: sampleCall(), onSelect: () => {} };
    const { rerender } = render(<Ladder {...props} selectedIndex={0} />);
    screen.getByRole("button", { name: /^INVITE,/ }).focus();

    rerender(<Ladder {...props} selectedIndex={1} />);

    expect(screen.getByRole("button", { name: /^100 Trying,/ })).toHaveFocus();
  });

  it("shows a minimap that marks the visible rows and selects on click", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={onSelect} />,
    );
    const wrap = container.querySelector(".ladder-wrap")!;
    // 100 px shows the first two 56 px rows (they start 28 px down).
    Object.defineProperty(wrap, "clientHeight", { value: 100 });
    fireEvent.scroll(wrap);

    const viewport = container.querySelector("svg.minimap rect.viewport")!;
    expect([viewport.getAttribute("y"), viewport.getAttribute("height")]).toEqual(["0", "200"]);

    const minimap = container.querySelector("svg.minimap")!;
    vi.spyOn(minimap, "getBoundingClientRect").mockReturnValue({ top: 0, height: 1012 } as DOMRect);
    fireEvent.pointerDown(minimap, { clientY: 1006 });
    expect(onSelect).toHaveBeenCalledWith(2);
  });

  it("leaves rows scrolled above the pane out of the minimap's visible span", () => {
    const { container } = render(
      <Ladder aliases={{}} onRename={() => {}} call={sampleCall()} selectedIndex={null} onSelect={() => {}} />,
    );
    const wrap = container.querySelector(".ladder-wrap")!;
    // Scrolled past the first 56 px row (rows start 28 px down); 100 px tall.
    Object.defineProperty(wrap, "scrollTop", { value: 84 });
    Object.defineProperty(wrap, "clientHeight", { value: 100 });
    fireEvent.scroll(wrap);

    const viewport = container.querySelector("svg.minimap rect.viewport")!;
    expect([viewport.getAttribute("y"), viewport.getAttribute("height")]).toEqual(["200", "800"]);
  });

  it("recomputes the minimap span when switching to a shorter call", () => {
    const long = sampleCall();
    const props = { aliases: {}, onRename: () => {}, selectedIndex: null, onSelect: () => {} };
    const { container, rerender } = render(<Ladder {...props} call={long} />);
    const wrap = container.querySelector(".ladder-wrap")!;
    Object.defineProperty(wrap, "clientHeight", { value: 1000 });
    fireEvent.scroll(wrap);

    const short = { ...long, messages: long.messages.slice(0, 2), ended_at: 0.1, message_count: 2 };
    rerender(<Ladder {...props} call={short} />);

    const viewport = container.querySelector("svg.minimap rect.viewport")!;
    expect([viewport.getAttribute("y"), viewport.getAttribute("height")]).toEqual(["0", "1000"]);
  });

  it("keeps the minimap span when switching to a call with the same visible rows", () => {
    const first = sampleCall();
    const props = { aliases: {}, onRename: () => {}, selectedIndex: null, onSelect: () => {} };
    const { container, rerender } = render(<Ladder {...props} call={first} />);
    const wrap = container.querySelector(".ladder-wrap")!;
    Object.defineProperty(wrap, "clientHeight", { value: 1000 });
    fireEvent.scroll(wrap);

    rerender(<Ladder {...props} call={{ ...first, call_id: "c2" }} />);

    const viewport = container.querySelector("svg.minimap rect.viewport")!;
    expect([viewport.getAttribute("y"), viewport.getAttribute("height")]).toEqual(["0", "1000"]);
  });
});
