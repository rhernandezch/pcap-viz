import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { sipMessage as msg } from "../test-fixtures";
import type { SipMessage } from "../types";
import { arrowClass } from "../util";
import { Legend } from "./Legend";

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
