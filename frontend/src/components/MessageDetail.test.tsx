import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Call, Sdp, SipMessage } from "../types";
import { MessageDetail } from "./MessageDetail";

function msg(overrides: Partial<SipMessage> = {}): SipMessage {
  return {
    index: 0,
    timestamp: 0,
    src: "10.0.0.1:5060",
    dst: "10.0.0.2:5060",
    transport: "UDP",
    method: "INVITE",
    status_code: null,
    status_phrase: null,
    request_line: "INVITE sip:bob@example.com SIP/2.0",
    status_line: null,
    cseq: "1 INVITE",
    call_id: "c1",
    from_uri: "",
    to_uri: "",
    headers: { "Content-Type": "application/sdp" },
    body: "v=0\r\n...",
    sdp: null,
    ...overrides,
  };
}

describe("<MessageDetail />", () => {
  it("renders nothing when no message is selected", () => {
    render(<MessageDetail call={null} aliases={{}} message={null} />);
    expect(screen.getByText("Select a message in the ladder, or press ↓.")).toBeInTheDocument();
  });

  it("renders the parsed SDP summary above the raw body when present", () => {
    const sdp: Sdp = {
      origin_addr: "10.0.0.1",
      session_name: "-",
      connection_addr: "10.0.0.1",
      media: [
        {
          kind: "audio",
          port: 49170,
          proto: "RTP/AVP",
          formats: [0, 8],
          rtpmaps: { "0": "PCMU/8000", "8": "PCMA/8000" },
          connection_addr: null,
        },
      ],
    };
    render(<MessageDetail call={null} aliases={{}} message={msg({ sdp })} />);

    // Header is present
    expect(screen.getByLabelText(/parsed sdp/i)).toBeInTheDocument();

    // Kind, endpoint, and proto appear in the summary
    expect(screen.getByText("audio")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1:49170")).toBeInTheDocument();
    expect(screen.getByText("RTP/AVP")).toBeInTheDocument();

    // Each format shows its codec
    expect(screen.getByText("PCMU/8000")).toBeInTheDocument();
    expect(screen.getByText("PCMA/8000")).toBeInTheDocument();
  });

  it("uses per-media connection address when it overrides the session-level one", () => {
    const sdp: Sdp = {
      origin_addr: null,
      session_name: null,
      connection_addr: "10.0.0.1",
      media: [
        {
          kind: "audio",
          port: 49170,
          proto: "RTP/AVP",
          formats: [0],
          rtpmaps: { "0": "PCMU/8000" },
          connection_addr: "192.0.2.5",
        },
      ],
    };
    render(<MessageDetail call={null} aliases={{}} message={msg({ sdp })} />);
    expect(screen.getByText("192.0.2.5:49170")).toBeInTheDocument();
    expect(screen.queryByText("10.0.0.1:49170")).not.toBeInTheDocument();
  });

  it("omits the SDP section when sdp is null", () => {
    render(<MessageDetail call={null} aliases={{}} message={msg({ sdp: null })} />);
    expect(screen.queryByLabelText(/parsed sdp/i)).not.toBeInTheDocument();
  });

  it("omits the SDP section when there is no media", () => {
    const sdp: Sdp = { origin_addr: null, session_name: null, connection_addr: null, media: [] };
    render(<MessageDetail call={null} aliases={{}} message={msg({ sdp })} />);
    expect(screen.queryByText("SDP")).not.toBeInTheDocument();
  });
});

const A = "10.0.0.1:5060";
const B = "10.0.0.2:5060";

function callOf(messages: SipMessage[], startedAt: number): Call {
  return {
    call_id: "c1", endpoints: [A, B], started_at: startedAt, ended_at: messages.at(-1)!.timestamp,
    from_uri: "", to_uri: "", message_count: messages.length, messages,
  };
}

function stubClipboard(writeText: (text: string) => Promise<void>) {
  vi.stubGlobal("navigator", Object.assign(Object.create(navigator), { clipboard: { writeText } }));
}

describe("<MessageDetail /> summary and sections", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("summarizes the message with lane names, UTC time, offset and delta", () => {
    const first = msg({ index: 0, timestamp: 1_699_999_997.3 });
    const second = msg({
      index: 1, timestamp: 1_700_000_000, src: B, dst: A, method: null, request_line: null,
      status_code: 200, status_line: "SIP/2.0 200 OK",
    });
    render(<MessageDetail call={callOf([first, second], 1_699_999_996.9)} aliases={{ [B]: "Voice bot" }} message={second} />);

    expect(screen.getByText("Voice bot (10.0.0.2:5060) → Unnamed (10.0.0.1:5060) · UDP")).toBeInTheDocument();
    expect(screen.getByText("2023-11-14 22:13:20.000 UTC · +3.10s · Δ2.70s")).toBeInTheDocument();
  });

  it("shows no delta for the first message of a call", () => {
    const first = msg({ index: 0, timestamp: 1_700_000_000 });
    render(<MessageDetail call={callOf([first], 1_700_000_000)} aliases={{}} message={first} />);

    expect(screen.getByText("2023-11-14 22:13:20.000 UTC · +0ms")).toBeInTheDocument();
  });

  it("calls out a Reason header", () => {
    render(<MessageDetail call={null} aliases={{}} message={msg({ headers: { reason: "Q.850;cause=16" } })} />);

    expect(screen.getByRole("note")).toHaveTextContent("reason: Q.850;cause=16");
  });

  it("filters headers by name or value, ignoring case", () => {
    const headers = { Via: "SIP/2.0/UDP 10.0.0.1", From: "<sip:alice@x>", To: "<sip:bob@x>" };
    render(<MessageDetail call={null} aliases={{}} message={msg({ headers })} />);

    const filter = screen.getByRole("searchbox", { name: "Filter headers" });
    const shown = () =>
      within(screen.getByRole("list", { name: "Headers" }))
        .getAllByRole("listitem")
        .map((li) => li.firstChild?.textContent);

    fireEvent.change(filter, { target: { value: "ALICE" } });
    expect(shown()).toEqual(["From"]);

    fireEvent.change(filter, { target: { value: "via" } });
    expect(shown()).toEqual(["Via"]);
  });

  it("copies one header's value", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    stubClipboard(writeText);
    render(<MessageDetail call={null} aliases={{}} message={msg({ headers: { From: "<sip:alice@x>" } })} />);

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy From" })));

    expect(writeText).toHaveBeenCalledWith("<sip:alice@x>");
  });

  it("doesn't carry copy feedback over to another message's same-named header", async () => {
    stubClipboard(vi.fn().mockResolvedValue(undefined));
    const { rerender } = render(<MessageDetail call={null} aliases={{}} message={msg({ headers: { From: "a" } })} />);
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy From" })));
    expect(screen.getByRole("button", { name: "Copy From" })).toHaveTextContent("Copied");

    rerender(<MessageDetail call={null} aliases={{}} message={msg({ index: 1, headers: { From: "b" } })} />);

    expect(screen.getByRole("button", { name: "Copy From" })).toHaveTextContent(/^Copy$/);
  });

  it("says when copying fails", async () => {
    stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
    render(<MessageDetail call={null} aliases={{}} message={msg()} />);

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy raw" })));

    expect(screen.getByRole("button", { name: "Copy failed" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
  });

  it("keeps a closed section closed after messages without it", async () => {
    const sdp: Sdp = {
      origin_addr: null, session_name: null, connection_addr: "10.0.0.1",
      media: [{ kind: "audio", port: 4000, proto: "RTP/AVP", formats: [0], rtpmaps: {}, connection_addr: null }],
    };
    const { rerender } = render(<MessageDetail call={null} aliases={{}} message={msg({ sdp })} />);
    // The browser fires "toggle" in a later task, after the click.
    await act(async () => {
      fireEvent.click(screen.getByText("SDP"));
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    rerender(<MessageDetail call={null} aliases={{}} message={msg({ index: 1, sdp: null })} />);
    rerender(<MessageDetail call={null} aliases={{}} message={msg({ index: 2, sdp })} />);

    expect(screen.getByText("SDP").closest("details")).not.toHaveAttribute("open");
  });
});
