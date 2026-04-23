import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Sdp, SipMessage } from "../types";
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
    render(<MessageDetail message={null} />);
    expect(screen.getByText(/click a message/i)).toBeInTheDocument();
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
    render(<MessageDetail message={msg({ sdp })} />);

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
    render(<MessageDetail message={msg({ sdp })} />);
    expect(screen.getByText("192.0.2.5:49170")).toBeInTheDocument();
    expect(screen.queryByText("10.0.0.1:49170")).not.toBeInTheDocument();
  });

  it("omits the SDP section when sdp is null", () => {
    render(<MessageDetail message={msg({ sdp: null })} />);
    expect(screen.queryByLabelText(/parsed sdp/i)).not.toBeInTheDocument();
  });
});
