import { forwardRef, useEffect, useRef, useState } from "react";
import { CallList } from "./components/CallList";
import { DropZone } from "./components/DropZone";
import { Ladder } from "./components/Ladder";
import { MessageDetail } from "./components/MessageDetail";
import { TabBar } from "./components/TabBar";
import { ThemeToggle } from "./components/ThemeToggle";
import { fetchPreloadSessionId, fetchSession, PCAP_FILE_TYPES, uploadPcap } from "./api";
import { useKeyboardNav } from "./hooks/useKeyboardNav";
import { useWindowFileDrop } from "./hooks/useWindowFileDrop";
import type { ParseResult, SipMessage } from "./types";

interface Tab {
  sessionId: string;
  result: ParseResult;
  // selected-call-id and selected-message-index remembered per tab
  selectedCallId: string | null;
  selectedMessageIndex: number | null;
}

export function App() {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeIdx, setActiveIdx] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const openButtonRef = useRef<HTMLButtonElement>(null);

  // One-time: if URL says ?preload=1, ask the server for the CLI-injected session.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("preload") !== "1") return;
    (async () => {
      try {
        const sid = await fetchPreloadSessionId();
        if (!sid) return;
        const result = await fetchSession(sid);
        setTabs((ts) => [...ts, makeTab(sid, result)]);
      } catch (e: unknown) {
        setError(String(e));
      }
    })();
  }, []);

  const windowDragging = useWindowFileDrop({ enabled: tabs.length > 0, onFile: handleFile });

  const active = tabs[activeIdx] ?? null;

  useKeyboardNav({
    calls: active?.result.calls ?? [],
    selectedCallId: active?.selectedCallId ?? null,
    selectedMessageIndex: active?.selectedMessageIndex ?? null,
    onSelectCall: (callId) => updateActive({ selectedCallId: callId, selectedMessageIndex: null }),
    onSelectMessage: (idx) => updateActive({ selectedMessageIndex: idx }),
  });

  const activeCall =
    active?.result.calls.find((c) => c.call_id === active.selectedCallId) ?? null;
  const activeMessage: SipMessage | null =
    activeCall && active?.selectedMessageIndex !== null
      ? activeCall.messages.find((m) => m.index === active!.selectedMessageIndex) ?? null
      : null;

  async function handleFile(file: File) {
    setError(null);
    setLoading(true);
    try {
      const { session_id, result } = await uploadPcap(file);
      setTabs((ts) => {
        const next = [...ts, makeTab(session_id, result)];
        setActiveIdx(next.length - 1);
        return next;
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
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

  return (
    <div className={`app${windowDragging ? " window-drag-active" : ""}`}>
      {windowDragging && (
        <div className="window-drag-overlay" aria-hidden="true">
          <div className="window-drag-hint">Drop to add another pcap</div>
        </div>
      )}
      <div className="topbar">
        <span className="title">pcap-viz</span>
        <TabBar
          tabs={tabs.map((t) => ({ id: t.sessionId, label: t.result.filename }))}
          activeIdx={activeIdx}
          onSelect={setActiveIdx}
          onClose={closeTab}
          fallbackFocusRef={openButtonRef}
        />
        <OpenPcapButton ref={openButtonRef} onFile={handleFile} loading={loading} />
        <ThemeToggle />
      </div>

      {error && <div className="error-banner">{error}</div>}

      {tabs.length === 0 ? (
        <div className="empty-state">
          <DropZone onFile={handleFile} />
        </div>
      ) : (
        <div className="main">
          <aside className="panel">
            <div className="panel-header">
              Calls ({active?.result.calls.length ?? 0})
            </div>
            <CallList
              calls={active?.result.calls ?? []}
              selectedCallId={active?.selectedCallId ?? null}
              onSelect={(call_id) =>
                updateActive({ selectedCallId: call_id, selectedMessageIndex: null })
              }
            />
          </aside>
          <section className="panel">
            <div className="panel-header">
              {activeCall
                ? `Ladder · ${activeCall.message_count} messages · ${activeCall.endpoints.length} endpoints`
                : "Ladder"}
            </div>
            <Ladder
              call={activeCall}
              selectedIndex={active?.selectedMessageIndex ?? null}
              onSelect={(idx) => updateActive({ selectedMessageIndex: idx })}
            />
          </section>
          <aside className="panel">
            <div className="panel-header">Message</div>
            <MessageDetail message={activeMessage} />
          </aside>
        </div>
      )}
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

const OpenPcapButton = forwardRef<HTMLButtonElement, { onFile: (f: File) => void; loading: boolean }>(
  function OpenPcapButton({ onFile, loading }, ref) {
    const inputRef = useRef<HTMLInputElement>(null);
    return (
      <>
        <button
          ref={ref}
          type="button"
          className="open-pcap"
          onClick={() => inputRef.current?.click()}
        >
          {loading ? "Parsing…" : "Open pcap"}
        </button>
        <input
          ref={inputRef}
          type="file"
          accept={PCAP_FILE_TYPES}
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) onFile(f);
            e.target.value = "";
          }}
        />
      </>
    );
  },
);
