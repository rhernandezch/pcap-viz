import { fireEvent, render, screen } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { TabBar } from "./TabBar";

const twoTabs = [
  { id: "s1", label: "a.pcap", title: "a.pcap" },
  { id: "s2", label: "b.pcap", title: "b.pcap" },
];
const threeTabs = [...twoTabs, { id: "s3", label: "c.pcap", title: "c.pcap" }];

function Harness({
  initial,
  initialActive = 0,
}: {
  initial: { id: string; label: string; title: string }[];
  initialActive?: number;
}) {
  const [tabs, setTabs] = useState(initial);
  const [activeIdx, setActiveIdx] = useState(initialActive);
  const fallbackRef = useRef<HTMLButtonElement>(null);
  return (
    <>
      <TabBar
        tabs={tabs}
        activeIdx={activeIdx}
        onSelect={setActiveIdx}
        onClose={(idx) => {
          setTabs(tabs.filter((_, i) => i !== idx));
          setActiveIdx((a) => Math.max(0, Math.min(idx < a ? a - 1 : a, tabs.length - 2)));
        }}
        fallbackFocusRef={fallbackRef}
      />
      <button ref={fallbackRef}>Open pcap</button>
      <button>Elsewhere</button>
    </>
  );
}

describe("<TabBar />", () => {
  it("renders a tablist whose active tab is selected", () => {
    render(<TabBar tabs={twoTabs} activeIdx={1} onSelect={() => {}} onClose={() => {}} />);

    expect(screen.getByRole("tablist")).toBeInTheDocument();
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual(["false", "true"]);
    expect(tabs.every((t) => t.tagName === "BUTTON")).toBe(true);
  });

  it("selects a tab when it is clicked", () => {
    const onSelect = vi.fn();
    render(<TabBar tabs={twoTabs} activeIdx={0} onSelect={onSelect} onClose={() => {}} />);

    fireEvent.click(screen.getByRole("tab", { name: "b.pcap" }));

    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("closes a tab from its close control without selecting it", () => {
    const onSelect = vi.fn();
    const onClose = vi.fn();
    render(<TabBar tabs={twoTabs} activeIdx={0} onSelect={onSelect} onClose={onClose} />);

    fireEvent.click(screen.getByTitle("Close b.pcap"));

    expect(onClose).toHaveBeenCalledWith(1);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("closes the focused tab with Delete and keeps only tabs inside the tablist", () => {
    const onClose = vi.fn();
    render(<TabBar tabs={twoTabs} activeIdx={0} onSelect={() => {}} onClose={onClose} />);
    const tab = screen.getByRole("tab", { name: "b.pcap" });

    fireEvent.keyDown(tab, { key: "Delete" });

    expect(onClose).toHaveBeenCalledWith(1);
    expect(screen.getByRole("tablist").querySelectorAll("button:not([role=tab])")).toHaveLength(0);
  });

  it("moves focus to the newly active tab after closing the active tab", () => {
    render(<Harness initial={twoTabs} />);
    const active = screen.getByRole("tab", { name: "a.pcap" });
    active.focus();

    fireEvent.keyDown(active, { key: "Delete" });

    expect(screen.getByRole("tab", { name: "b.pcap" })).toHaveFocus();
  });

  it("moves focus to the fallback element after closing the last tab", () => {
    render(<Harness initial={[twoTabs[0]]} />);

    fireEvent.click(screen.getByTitle("Close a.pcap"));

    expect(screen.getByRole("button", { name: "Open pcap" })).toHaveFocus();
  });

  it("closes the focused tab with Backspace, the delete key on Mac keyboards", () => {
    const onClose = vi.fn();
    render(<TabBar tabs={twoTabs} activeIdx={0} onSelect={() => {}} onClose={onClose} />);
    const tab = screen.getByRole("tab", { name: "b.pcap" });

    fireEvent.keyDown(tab, { key: "Backspace" });

    expect(onClose).toHaveBeenCalledWith(1);
    expect(tab).toHaveAttribute("aria-keyshortcuts", "Delete Backspace");
  });

  it("leaves focus alone when a background tab is closed with the mouse", () => {
    render(<Harness initial={twoTabs} />);
    const elsewhere = screen.getByRole("button", { name: "Elsewhere" });
    elsewhere.focus();

    fireEvent.click(screen.getByTitle("Close b.pcap"));

    expect(elsewhere).toHaveFocus();
  });

  it("does not take focus when tabs are added or selected", () => {
    const { rerender } = render(
      <TabBar tabs={twoTabs} activeIdx={0} onSelect={() => {}} onClose={() => {}} />,
    );
    const elsewhere = document.createElement("button");
    document.body.appendChild(elsewhere);
    elsewhere.focus();

    rerender(<TabBar tabs={threeTabs} activeIdx={2} onSelect={() => {}} onClose={() => {}} />);

    expect(elsewhere).toHaveFocus();
    elsewhere.remove();
  });

  it("keeps only the active tab in the Tab order", () => {
    render(<TabBar tabs={threeTabs} activeIdx={1} onSelect={() => {}} onClose={() => {}} />);

    expect(screen.getAllByRole("tab").map((t) => t.tabIndex)).toEqual([-1, 0, -1]);
  });

  it("moves focus and selection between tabs with the arrow, Home and End keys", () => {
    render(<Harness initial={threeTabs} />);
    const tab = (name: string) => screen.getByRole("tab", { name });
    tab("a.pcap").focus();

    fireEvent.keyDown(tab("a.pcap"), { key: "ArrowRight" });
    expect(tab("b.pcap")).toHaveFocus();
    expect(tab("b.pcap")).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(tab("b.pcap"), { key: "End" });
    expect(tab("c.pcap")).toHaveFocus();

    fireEvent.keyDown(tab("c.pcap"), { key: "ArrowRight" });
    expect(tab("a.pcap")).toHaveFocus();

    fireEvent.keyDown(tab("a.pcap"), { key: "ArrowLeft" });
    expect(tab("c.pcap")).toHaveFocus();

    fireEvent.keyDown(tab("c.pcap"), { key: "Home" });
    expect(tab("a.pcap")).toHaveFocus();
    expect(tab("a.pcap")).toHaveAttribute("aria-selected", "true");
  });
});
