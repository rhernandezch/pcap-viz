import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { SHORTCUTS } from "../shortcuts";
import { ShortcutsDialog } from "./ShortcutsDialog";

function Harness() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)}>Keyboard shortcuts</button>
      {open && <ShortcutsDialog onClose={() => setOpen(false)} />}
    </>
  );
}

describe("<ShortcutsDialog />", () => {
  it("lists every shortcut", () => {
    render(<ShortcutsDialog onClose={() => {}} />);

    const dialog = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    for (const s of SHORTCUTS) {
      expect(dialog).toHaveTextContent(s.keys);
      expect(dialog).toHaveTextContent(s.description);
    }
  });

  it("focuses Close on open, closes on Escape and returns focus", () => {
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "Keyboard shortcuts" });
    opener.focus();
    fireEvent.click(opener);

    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();

    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("closes when the backdrop is clicked", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Keyboard shortcuts" }));

    fireEvent.click(screen.getByTestId("dialog-backdrop"));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("closes on Escape even when focus has left the dialog", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Keyboard shortcuts" }));
    const outside = screen.getByRole("button", { name: "Keyboard shortcuts" });
    outside.focus();

    fireEvent.keyDown(outside, { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
