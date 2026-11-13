import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { Call, ParseResult, SipMessage } from "./types";

function msg(overrides: Partial<SipMessage> & { index: number }): SipMessage {
  return {
    timestamp: 0,
    src: "10.0.0.1:5060",
    dst: "10.0.0.2:5060",
    transport: "UDP",
    method: null,
    status_code: null,
    status_phrase: null,
    request_line: null,
    status_line: null,
    cseq: "1 INVITE",
    call_id: "c1",
    from_uri: "",
    to_uri: "",
    headers: {},
    body: null,
    sdp: null,
    ...overrides,
  };
}

function call(callId: string, requestLine: string): Call {
  return {
    call_id: callId,
    endpoints: ["10.0.0.1:5060", "10.0.0.2:5060"],
    started_at: 0,
    ended_at: 0.1,
    from_uri: "<sip:alice@example.com>",
    to_uri: "<sip:bob@example.com>",
    message_count: 2,
    messages: [
      msg({ index: 0, call_id: callId, method: "INVITE", request_line: requestLine }),
      msg({
        index: 1,
        call_id: callId,
        timestamp: 0.1,
        status_code: 200,
        status_phrase: "OK",
        status_line: "SIP/2.0 200 OK",
        src: "10.0.0.2:5060",
        dst: "10.0.0.1:5060",
      }),
    ],
  };
}

function result(filename: string, calls: Call[]): ParseResult {
  return { filename, packet_count: 4, sip_message_count: 4, calls, warnings: [] };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function stubPreload(preloaded: ParseResult) {
  let uploads = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "/api/preload") return jsonResponse({ session_id: "s1" });
    if (url === "/api/session/s1") return jsonResponse(preloaded);
    if (url === "/api/parse") {
      const file = (init?.body as FormData).get("file") as File;
      uploads += 1;
      return jsonResponse({
        session_id: `upload-${uploads}`,
        result: result(file.name, [call("c9", "INVITE sip:zed@example.com SIP/2.0")]),
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function renderPreloaded(preloaded: ParseResult) {
  const fetchMock = stubPreload(preloaded);
  render(<App />);
  await screen.findByText(preloaded.filename);
  return fetchMock;
}

function fileDragEvent(type: string, file: File): Event {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: { types: ["Files"], files: [file] },
  });
  return event;
}

describe("<App />", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/?preload=1");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
    window.history.pushState({}, "", "/");
  });

  it("ArrowDown selects the first message of the selected call", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    fireEvent.keyDown(window, { key: "ArrowDown" });

    expect(await screen.findByText("INVITE sip:bob@example.com SIP/2.0")).toBeInTheDocument();
  });

  it("separates the three panes with labelled, resizable separators", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    const separators = screen.getAllByRole("separator");
    expect(separators.map((s) => s.getAttribute("aria-label"))).toEqual([
      "Resize calls panel",
      "Resize message panel",
    ]);
  });

  it("keeps the calls and message panes as labelled landmarks", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    const landmarks = screen.getAllByRole("complementary");
    expect(landmarks.map((l) => l.getAttribute("aria-label"))).toEqual(["Calls", "Message"]);
  });

  it("restores the saved pane layout", async () => {
    localStorage.setItem(
      "react-resizable-panels:pcap-viz:layout",
      JSON.stringify({ calls: 30, ladder: 45, detail: 25 }),
    );
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    expect(screen.getByTestId("calls")).toHaveStyle({ flexGrow: "30" });
    expect(screen.getByTestId("detail")).toHaveStyle({ flexGrow: "25" });
  });

  it("shows the arrow color legend and the theme toggle once a capture is open", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    expect(screen.getByRole("list", { name: "Arrow colors" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Theme: / })).toBeInTheDocument();
  });

  it("ArrowRight moves to the next call", async () => {
    await renderPreloaded(
      result("a.pcap", [
        call("c1", "INVITE sip:bob@example.com SIP/2.0"),
        call("c2", "INVITE sip:carol@example.com SIP/2.0"),
      ]),
    );

    fireEvent.keyDown(window, { key: "ArrowRight" });
    fireEvent.keyDown(window, { key: "ArrowDown" });

    expect(await screen.findByText("INVITE sip:carol@example.com SIP/2.0")).toBeInTheDocument();
  });

  it("ignores arrow keys while typing in an input", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));
    const input = document.createElement("input");
    document.body.appendChild(input);

    fireEvent.keyDown(input, { key: "ArrowDown" });

    expect(screen.queryByText("INVITE sip:bob@example.com SIP/2.0")).not.toBeInTheDocument();
    input.remove();
  });

  it("ignores arrow keys that a focused control already handled", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));
    // Stands in for a pane separator, which handles its own arrow keys.
    const control = document.createElement("div");
    control.addEventListener("keydown", (e) => e.preventDefault());
    document.body.appendChild(control);

    fireEvent.keyDown(control, { key: "ArrowDown" });

    expect(screen.queryByText("INVITE sip:bob@example.com SIP/2.0")).not.toBeInTheDocument();
    control.remove();
  });

  it("uploads a file dropped anywhere on the window once a tab is open", async () => {
    const fetchMock = await renderPreloaded(
      result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]),
    );
    const file = new File(["x"], "dropped.pcap");

    act(() => {
      window.dispatchEvent(fileDragEvent("dragover", file));
      window.dispatchEvent(fileDragEvent("drop", file));
    });

    expect(await screen.findByText("dropped.pcap")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/parse", expect.objectContaining({ method: "POST" }));
  });

  it("keeps the active capture selected when a tab to its left is closed", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));
    for (const name of ["b.pcap", "c.pcap"]) {
      act(() => {
        window.dispatchEvent(fileDragEvent("drop", new File(["x"], name)));
      });
      await screen.findByRole("tab", { name });
    }
    fireEvent.click(screen.getByRole("tab", { name: "b.pcap" }));

    fireEvent.keyDown(screen.getByRole("tab", { name: "a.pcap" }), { key: "Delete" });

    expect(screen.getByRole("tab", { name: "b.pcap" })).toHaveAttribute("aria-selected", "true");
  });

  it("ArrowRight on a focused tab switches captures instead of calls", async () => {
    await renderPreloaded(
      result("a.pcap", [
        call("c1", "INVITE sip:bob@example.com SIP/2.0"),
        call("c2", "INVITE sip:carol@example.com SIP/2.0"),
      ]),
    );
    act(() => {
      window.dispatchEvent(fileDragEvent("drop", new File(["x"], "b.pcap")));
    });
    await screen.findByRole("tab", { name: "b.pcap" });
    const first = screen.getByRole("tab", { name: "a.pcap" });
    fireEvent.click(first);
    first.focus();

    fireEvent.keyDown(first, { key: "ArrowRight" });

    expect(screen.getByRole("tab", { name: "b.pcap" })).toHaveAttribute("aria-selected", "true");
    fireEvent.click(screen.getByRole("tab", { name: "a.pcap" }));
    fireEvent.keyDown(document.body, { key: "ArrowDown" });
    expect(screen.getByText("INVITE sip:bob@example.com SIP/2.0")).toBeInTheDocument();
  });

  it("ArrowDown on a clicked tab still steps through messages", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));
    const tab = screen.getByRole("tab", { name: "a.pcap" });
    fireEvent.click(tab);
    tab.focus();

    fireEvent.keyDown(tab, { key: "ArrowDown" });

    expect(screen.getByText("INVITE sip:bob@example.com SIP/2.0")).toBeInTheDocument();
  });

  it("focuses Open pcap after the last tab is closed", async () => {
    await renderPreloaded(result("a.pcap", [call("c1", "INVITE sip:bob@example.com SIP/2.0")]));

    fireEvent.keyDown(screen.getByRole("tab", { name: "a.pcap" }), { key: "Delete" });

    expect(screen.getByRole("button", { name: "Open pcap" })).toHaveFocus();
  });
});
