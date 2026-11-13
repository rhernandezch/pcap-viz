import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ThemeToggle } from "./ThemeToggle";

afterEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe("<ThemeToggle />", () => {
  it("names the current preference and switches to the next one on click", () => {
    render(<ThemeToggle />);
    const button = screen.getByRole("button", { name: "Theme: System" });
    expect(button).toHaveTextContent("System");

    fireEvent.click(button);

    expect(screen.getByRole("button", { name: "Theme: Light" })).toHaveTextContent("Light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
