import { fireEvent, render, screen } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { TabBar } from "./TabBar";

const twoTabs = [
  { id: "s1", label: "a.pcap" },
  { id: "s2", label: "b.pcap" },
];

function Harness({ initial }: { initial: { id: string; label: string }[] }) {
  const [tabs, setTabs] = useState(initial);
  const [activeIdx, setActiveIdx] = useState(0);
  const fallbackRef = useRef<HTMLButtonElement>(null);
  return (
    <>
      <TabBar
        tabs={tabs}
        activeIdx={activeIdx}
        onSelect={setActiveIdx}
        onClose={(idx) => {
          const next = tabs.filter((_, i) => i !== idx);
          setTabs(next);
          setActiveIdx(Math.min(activeIdx, Math.max(0, next.length - 1)));
        }}
        fallbackFocusRef={fallbackRef}
      />
      <button ref={fallbackRef}>Open pcap</button>
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
    expect(tab).toHaveAttribute("aria-keyshortcuts", "Delete");
    expect(screen.getByRole("tablist").querySelectorAll("button:not([role=tab])")).toHaveLength(0);
  });

  it("moves focus to the newly active tab after closing the active tab", () => {
    render(<Harness initial={twoTabs} />);

    fireEvent.keyDown(screen.getByRole("tab", { name: "a.pcap" }), { key: "Delete" });

    expect(screen.getByRole("tab", { name: "b.pcap" })).toHaveFocus();
  });

  it("moves focus to the fallback element after closing the last tab", () => {
    render(<Harness initial={[twoTabs[0]]} />);

    fireEvent.click(screen.getByTitle("Close a.pcap"));

    expect(screen.getByRole("button", { name: "Open pcap" })).toHaveFocus();
  });
});
