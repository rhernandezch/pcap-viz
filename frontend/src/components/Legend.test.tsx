import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SipMessage } from "../types";
import { arrowClass } from "../util";
import { Legend } from "./Legend";

function msg(overrides: Partial<SipMessage>): SipMessage {
  return {
    index: 0,
    timestamp: 0,
    src: "a",
    dst: "b",
    transport: "UDP",
    method: null,
    status_code: null,
    status_phrase: null,
    request_line: null,
    status_line: null,
    cseq: "",
    call_id: "",
    from_uri: "",
    to_uri: "",
    headers: {},
    body: null,
    sdp: null,
    ...overrides,
  };
}

describe("<Legend />", () => {
  it("shows one swatch per arrow class, styled like the matching arrows", () => {
    render(<Legend />);

    const samples: [string, SipMessage][] = [
      ["Request", msg({ method: "INVITE" })],
      ["1xx", msg({ status_code: 180 })],
      ["2xx", msg({ status_code: 200 })],
      ["3xx", msg({ status_code: 302 })],
      ["4xx", msg({ status_code: 486 })],
      ["5xx/6xx", msg({ status_code: 503 })],
    ];
    expect(screen.getAllByRole("listitem")).toHaveLength(samples.length);
    for (const [label, sample] of samples) {
      const swatch = screen.getByText(label).previousElementSibling;
      expect(swatch).toHaveClass("legend-swatch", arrowClass(sample));
    }
  });
});
