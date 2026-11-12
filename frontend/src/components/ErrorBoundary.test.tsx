import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

function Bomb({ message }: { message: string }): null {
  throw new Error(message);
}

describe("<ErrorBoundary />", () => {
  // React logs caught errors via console.error — silence it so the test
  // output stays readable, and restore after each case.
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it("renders children when no error occurs", () => {
    render(
      <ErrorBoundary>
        <div>happy path</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText("happy path")).toBeInTheDocument();
  });

  it("renders the fallback with a reload button when a child throws", () => {
    render(
      <ErrorBoundary>
        <Bomb message="kaboom" />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText("kaboom")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reload/i })).toBeInTheDocument();
  });

  it("logs the error to the console for debugging", () => {
    render(
      <ErrorBoundary>
        <Bomb message="debug-me" />
      </ErrorBoundary>,
    );
    const logged = consoleErrorSpy.mock.calls.some((args) =>
      args.some((arg) => String(arg).includes("[pcap-viz] render error")),
    );
    expect(logged).toBe(true);
  });
});
