import { useEffect, useRef, useState } from "react";
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
  const [windowDragging, setWindowDragging] = useState(false);

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

  // Keep a ref to handleFile so the window drop listener calls the fresh
  // closure without re-binding every render.
  const handleFileRef = useRef<(f: File) => void>(() => {});

  // Full-window drag-and-drop once at least one tab is open.
  // (The empty state already has its own DropZone.)
  useEffect(() => {
    if (tabs.length === 0) return;

    const hasFiles = (e: DragEvent) =>
      Array.from(e.dataTransfer?.types ?? []).includes("Files");

    const onDragOver = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      setWindowDragging(true);
    };
    const onDragLeave = (e: DragEvent) => {
      // dragleave fires at every child boundary — only act when the cursor
      // actually leaves the window (relatedTarget is null in that case).
      if (e.relatedTarget === null) setWindowDragging(false);
    };
    const onDrop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      setWindowDragging(false);
      const file = e.dataTransfer?.files?.[0];
      if (file) handleFileRef.current(file);
    };

    window.addEventListener("dragover", onDragOver);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("drop", onDrop);
    };
  }, [tabs.length]);

  // Keyboard navigation: ↑/↓ step through messages in the active call,
  // ←/→ switch between calls. Ignored while typing in a form field.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable)
      ) {
        return;
      }

      const activeTab = tabs[activeIdx];
      if (!activeTab) return;
      const calls = activeTab.result.calls;
      if (calls.length === 0) return;

      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const call = calls.find((c) => c.call_id === activeTab.selectedCallId);
        if (!call || call.messages.length === 0) return;
        const pos = call.messages.findIndex(
          (m) => m.index === activeTab.selectedMessageIndex,
        );
        const delta = e.key === "ArrowDown" ? 1 : -1;
        const next =
          pos < 0
            ? e.key === "ArrowDown"
              ? 0
              : call.messages.length - 1
            : Math.max(0, Math.min(call.messages.length - 1, pos + delta));
        updateActive({ selectedMessageIndex: call.messages[next].index });
        e.preventDefault();
      } else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        const pos = calls.findIndex((c) => c.call_id === activeTab.selectedCallId);
        const delta = e.key === "ArrowRight" ? 1 : -1;
        const next =
          pos < 0 ? 0 : Math.max(0, Math.min(calls.length - 1, pos + delta));
        updateActive({
          selectedCallId: calls[next].call_id,
          selectedMessageIndex: null,
        });
        e.preventDefault();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // updateActive closes over activeIdx, so re-bind when tabs/activeIdx change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabs, activeIdx]);

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

  handleFileRef.current = handleFile;

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
    <div className={`app${windowDragging ? " window-drag-active" : ""}`}>
      {windowDragging && (
        <div className="window-drag-overlay" aria-hidden="true">
          <div className="window-drag-hint">Drop to add another pcap</div>
        </div>
      )}
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
