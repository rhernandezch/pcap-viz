import { useEffect, useState } from "react";
import { CallList } from "./components/CallList";
import { DropZone } from "./components/DropZone";
import { Ladder } from "./components/Ladder";
import { MessageDetail } from "./components/MessageDetail";
import { fetchPreloadSessionId, fetchSession, uploadPcap } from "./api";
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

  const active = tabs[activeIdx] ?? null;
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
    setTabs((ts) => {
      const next = ts.filter((_, i) => i !== idx);
      if (activeIdx >= next.length) setActiveIdx(Math.max(0, next.length - 1));
      return next;
    });
  }

  function updateActive(patch: Partial<Tab>) {
    setTabs((ts) => ts.map((t, i) => (i === activeIdx ? { ...t, ...patch } : t)));
  }

  return (
    <div className="app">
      <div className="topbar">
        <span className="title">pcap-viz</span>
        <div className="tabs">
          {tabs.map((t, i) => (
            <span
              key={t.sessionId}
              className={`tab${i === activeIdx ? " active" : ""}`}
              onClick={() => setActiveIdx(i)}
              title={t.result.filename}
            >
              <span>{t.result.filename}</span>
              <span
                className="close"
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(i);
                }}
              >
                ×
              </span>
            </span>
          ))}
        </div>
        {tabs.length > 0 && <LabelledFilePicker onFile={handleFile} loading={loading} />}
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

function LabelledFilePicker({
  onFile,
  loading,
}: {
  onFile: (f: File) => void;
  loading: boolean;
}) {
  return (
    <label style={{ fontSize: 12, color: "var(--text-dim)", cursor: "pointer" }}>
      {loading ? "parsing…" : "+ add pcap"}
      <input
        type="file"
        accept=".pcap,.pcapng"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
    </label>
  );
}
