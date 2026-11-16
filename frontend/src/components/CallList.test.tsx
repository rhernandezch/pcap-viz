import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { sipCall, sipMessage } from "../test-fixtures";
import type { SipMessage } from "../types";
import { CallList } from "./CallList";

const msg = (overrides: Partial<SipMessage>) =>
  sipMessage({ timestamp: 1_700_000_000, cseq: "1 INVITE", call_id: "busy@x", ...overrides });

const busy = sipCall(
  [
    msg({ method: "INVITE" }),
    msg({ status_code: 486, status_phrase: "Busy Here", status_line: "SIP/2.0 486 Busy Here" }),
  ],
  {
    ended_at: 1_700_000_000.5,
    from_uri: '"Alice" <sip:alice@example.com>;tag=1',
    to_uri: "<sip:bob@example.com>",
  },
);

function renderList(overrides: Partial<Parameters<typeof CallList>[0]> = {}) {
  const props = {
    calls: [busy],
    totalCount: 1,
    query: "",
    onQueryChange: vi.fn(),
    selectedCallId: null,
    onSelect: vi.fn(),
    ...overrides,
  };
  render(<CallList {...props} />);
  return props;
}

describe("<CallList />", () => {
  it("shows the call state as a toned badge with the final status as tooltip", () => {
    renderList();

    const badge = screen.getByText("Rejected 486");
    expect(badge).toHaveClass("badge", "tone-error");
    expect(badge).toHaveAttribute("title", "SIP/2.0 486 Busy Here");
  });

  it("keeps the full From → To in a tooltip and shows the UTC start time", () => {
    renderList();

    expect(screen.getByTitle("alice@example.com → bob@example.com")).toBeInTheDocument();
    expect(screen.getByText(/22:13:20/)).toBeInTheDocument();
  });

  it("reports how many calls match and offers Clear when none do", () => {
    const props = renderList({ calls: [], totalCount: 3, query: "zzz" });

    expect(screen.getByText("0 of 3 calls")).toBeInTheDocument();
    expect(screen.getByText('No calls match "zzz"')).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(props.onQueryChange).toHaveBeenCalledWith("");
  });

  it("pluralizes the match count", () => {
    renderList({ query: "busy" });

    expect(screen.getByText("1 of 1 call")).toBeInTheDocument();
  });

  it("clears the filter with Escape", () => {
    const props = renderList({ query: "busy" });

    fireEvent.keyDown(screen.getByRole("searchbox", { name: "Filter calls" }), { key: "Escape" });

    expect(props.onQueryChange).toHaveBeenCalledWith("");
  });
});
