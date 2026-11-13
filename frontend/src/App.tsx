import { useEffect, useRef, useState } from "react";
import { Group, Panel, Separator, useDefaultLayout } from "react-resizable-panels";
import { CallList } from "./components/CallList";
import { DropZone } from "./components/DropZone";
import { FilePickerButton } from "./components/FilePickerButton";
import { Ladder } from "./components/Ladder";
import { MessageDetail } from "./components/MessageDetail";
import { Legend } from "./components/Legend";
import { ShortcutsDialog } from "./components/ShortcutsDialog";
import { TabBar } from "./components/TabBar";
import { ThemeToggle } from "./components/ThemeToggle";
import { WarningsBar } from "./components/WarningsBar";
import { fetchPreloadSessionId, fetchSession, uploadPcap } from "./api";
import { useKeyboardNav } from "./hooks/useKeyboardNav";
import { useWindowFileDrop } from "./hooks/useWindowFileDrop";
import { safeStorage } from "./storage";
import { plural } from "./util";
import type { ParseResult, SipMessage } from "./types";

const LAYOUT_ID = "pcap-viz:layout";

interface Tab {
  sessionId: string;
  result: ParseResult;
  // selected-call-id and selected-message-index remembered per tab
  selectedCallId: string | null;
  selectedMessageIndex: number | null;
}

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function App() {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeIdx, setActiveIdx] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [parsing, setParsing] = useState<string | null>(null);
  const [preloading, setPreloading] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const openButtonRef = useRef<HTMLButtonElement>(null);
  const { defaultLayout, onLayoutChanged } = useDefaultLayout({
    id: LAYOUT_ID,
    storage: safeStorage,
    onlySaveAfterUserInteractions: true,
  });

  // One-time: if URL says ?preload=1, ask the server for the CLI-injected session.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("preload") !== "1") return;
    // StrictMode runs this effect twice in development; only the last run may add the tab.
    let cancelled = false;
    setPreloading(true);
    (async () => {
      try {
        const sid = await fetchPreloadSessionId();
        if (!sid) return;
        const result = await fetchSession(sid);
        if (!cancelled) setTabs((ts) => [...ts, makeTab(sid, result)]);
      } catch (e: unknown) {
        if (!cancelled) setError(`Couldn't load the preloaded capture: ${errorMessage(e)}`);
      } finally {
        if (!cancelled) setPreloading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const windowDragging = useWindowFileDrop(handleFile);

  const active = tabs[activeIdx] ?? null;

  useKeyboardNav({
    calls: active?.result.calls ?? [],
    selectedCallId: active?.selectedCallId ?? null,
    selectedMessageIndex: active?.selectedMessageIndex ?? null,
    onSelectCall: (callId) => updateActive({ selectedCallId: callId, selectedMessageIndex: null }),
    onSelectMessage: (idx) => updateActive({ selectedMessageIndex: idx }),
    onToggleHelp: () => setHelpOpen((open) => !open),
    paused: helpOpen,
  });

  const activeCall =
    active?.result.calls.find((c) => c.call_id === active.selectedCallId) ?? null;
  const activeMessage: SipMessage | null =
    activeCall && active?.selectedMessageIndex !== null
      ? activeCall.messages.find((m) => m.index === active!.selectedMessageIndex) ?? null
      : null;

  async function handleFile(file: File) {
    if (parsing !== null) return;
    setError(null);
    setParsing(file.name);
    try {
      const { session_id, result } = await uploadPcap(file);
      setTabs((ts) => {
        const next = [...ts, makeTab(session_id, result)];
        setActiveIdx(next.length - 1);
        return next;
      });
    } catch (e: unknown) {
      setError(`Couldn't open ${file.name}: ${errorMessage(e)}`);
    } finally {
      setParsing(null);
    }
  }

  function closeTab(idx: number) {
    const remaining = tabs.length - 1;
    setTabs((ts) => ts.filter((_, i) => i !== idx));
    setActiveIdx((a) => Math.max(0, Math.min(idx < a ? a - 1 : a, remaining - 1)));
  }

  function updateActive(patch: Partial<Tab>) {
    setTabs((ts) => ts.map((t, i) => (i === activeIdx ? { ...t, ...patch } : t)));
  }

  const busy = parsing !== null || preloading;
  const status = parsing !== null ? `Parsing ${parsing}…` : preloading ? "Loading capture…" : "";

  return (
    <div className={`app${windowDragging ? " window-drag-active" : ""}`}>
      {windowDragging && (
        <div className="window-drag-overlay" aria-hidden="true">
          <div className="window-drag-hint">
            {tabs.length > 0 ? "Drop to add another pcap" : "Drop to open the pcap"}
          </div>
        </div>
      )}
      <div className="topbar">
        <span className="title">pcap-viz</span>
        <TabBar
          tabs={tabs.map((t) => ({
            id: t.sessionId,
            label: t.result.filename,
            title: [
              t.result.filename,
              plural(t.result.calls.length, "call"),
              plural(t.result.sip_message_count, "SIP message"),
              plural(t.result.packet_count, "packet"),
            ].join(" · "),
          }))}
          activeIdx={activeIdx}
          onSelect={setActiveIdx}
          onClose={closeTab}
          fallbackFocusRef={openButtonRef}
        />
        <span className="parse-status" role="status">
          {status}
        </span>
        <FilePickerButton
          ref={openButtonRef}
          className="open-pcap"
          label="Open pcap"
          onFile={handleFile}
          disabled={busy}
        />
        <button
          type="button"
          aria-label="Keyboard shortcuts"
          aria-keyshortcuts="?"
          onClick={() => setHelpOpen(true)}
        >
          ?
        </button>
        <ThemeToggle />
      </div>

      {error && (
        <div className="error-banner" role="alert">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {active && <WarningsBar key={active.sessionId} warnings={active.result.warnings} />}

      {!active ? (
        <div className="empty-state">
          <DropZone onFile={handleFile} disabled={busy} />
        </div>
      ) : active.result.calls.length === 0 ? (
        <div className="empty-state">
          <p className="no-sip">
            No SIP calls found in {active.result.filename}. Scanned{" "}
            {plural(active.result.packet_count, "packet")}; pcap-viz reads SIP over UDP and TCP.
          </p>
        </div>
      ) : (
        <Group
          className="main"
          id={LAYOUT_ID}
          defaultLayout={defaultLayout}
          onLayoutChanged={onLayoutChanged}
        >
          <Panel
            id="calls"
            className="panel"
            defaultSize="20%"
            minSize={200}
            collapsible
            role="complementary"
            aria-label="Calls"
          >
            <div className="panel-header">Calls ({active.result.calls.length})</div>
            <CallList
              calls={active.result.calls}
              selectedCallId={active.selectedCallId}
              onSelect={(call_id) =>
                updateActive({ selectedCallId: call_id, selectedMessageIndex: null })
              }
            />
          </Panel>
          <Separator className="pane-separator" aria-label="Resize calls panel" />
          <Panel id="ladder" className="panel" minSize={320}>
            <div className="panel-header ladder-header">
              <span>
                {activeCall
                  ? `Ladder · ${activeCall.message_count} messages · ${activeCall.endpoints.length} endpoints`
                  : "Ladder"}
              </span>
              <Legend />
            </div>
            <Ladder
              call={activeCall}
              selectedIndex={active.selectedMessageIndex}
              onSelect={(idx) => updateActive({ selectedMessageIndex: idx })}
            />
          </Panel>
          <Separator className="pane-separator" aria-label="Resize message panel" />
          <Panel
            id="detail"
            className="panel panel-detail"
            defaultSize="28%"
            minSize={280}
            collapsible
            role="complementary"
            aria-label="Message"
          >
            <div className="panel-header">Message</div>
            <MessageDetail message={activeMessage} />
          </Panel>
        </Group>
      )}
      {helpOpen && <ShortcutsDialog onClose={() => setHelpOpen(false)} />}
    </div>
  );
}

function makeTab(sessionId: string, result: ParseResult): Tab {
  return {
    sessionId,
    result,
    selectedCallId: result.calls[0]?.call_id ?? null,
    selectedMessageIndex: null,
  };
}
