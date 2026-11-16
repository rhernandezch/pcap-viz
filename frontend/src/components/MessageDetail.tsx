import { useEffect, useMemo, useRef, useState, type SyntheticEvent } from "react";
import { laneLabel } from "../laneNames";
import type { Call, Sdp, SdpMedia, SipMessage } from "../types";
import { arrowClass, formatDelta, formatOffset, formatUtc } from "../util";

interface Props {
  message: SipMessage | null;
  call: Call | null;
  aliases: Record<string, string>;
}

type Section = "headers" | "sdp" | "body";

const CALLOUT_HEADERS = ["reason", "warning"];
const COPY_FEEDBACK_MS = 1500;
const RAW_KEY = "raw";

export function MessageDetail({ message, call, aliases }: Props) {
  // Lives above the message so open/closed survives switching messages.
  const [open, setOpen] = useState<Record<Section, boolean>>({
    headers: true,
    sdp: true,
    body: true,
  });
  const [filter, setFilter] = useState("");
  const [copy, onCopy] = useCopyFeedback();

  const raw = useMemo(() => {
    if (!message) return "";
    const firstLine = message.request_line ?? message.status_line ?? "";
    const headerLines = Object.entries(message.headers).map(([k, v]) => `${k}: ${v}`);
    return [firstLine, ...headerLines, "", message.body ?? ""].join("\r\n");
  }, [message]);

  if (!message) {
    return <div className="detail-empty">Select a message in the ladder, or press ↓.</div>;
  }

  const headers = Object.entries(message.headers);
  const q = filter.trim().toLowerCase();
  const shownHeaders = q
    ? headers.filter(([k, v]) => k.toLowerCase().includes(q) || v.toLowerCase().includes(q))
    : headers;
  const callouts = headers.filter(([k]) => CALLOUT_HEADERS.includes(k.toLowerCase()));
  const hasMedia = (message.sdp?.media.length ?? 0) > 0;

  const nameOf = (ep: string) => (call ? `${laneLabel(aliases, call, ep)} (${ep})` : ep);
  const pos = call ? call.messages.findIndex((m) => m.index === message.index) : -1;
  const times = [formatUtc(message.timestamp)];
  if (call && pos >= 0) {
    times.push(formatOffset(message.timestamp - call.started_at));
    if (pos > 0) times.push(formatDelta(message.timestamp - call.messages[pos - 1].timestamp));
  }

  const section = (key: Section) => ({
    open: open[key],
    onToggle: (e: SyntheticEvent<HTMLDetailsElement>) => {
      const isOpen = e.currentTarget.open;
      setOpen((o) => (o[key] === isOpen ? o : { ...o, [key]: isOpen }));
    },
  });

  return (
    <div className="detail">
      <button className="copy" onClick={() => onCopy(RAW_KEY, raw)}>
        {copyLabel(copy, RAW_KEY, "Copy raw")}
      </button>
      <span className="visually-hidden" role="status">
        {copy ? (copy.ok ? `Copied ${copy.key === RAW_KEY ? "message" : copy.key}` : "Copy failed") : ""}
      </span>
      <div className={`first-line ${arrowClass(message)}`}>
        {message.request_line ?? message.status_line}
      </div>
      <div className="endpoint">
        {`${nameOf(message.src)} → ${nameOf(message.dst)} · ${message.transport}`}
      </div>
      <div className="endpoint">{times.join(" · ")}</div>

      {callouts.length > 0 && (
        <div className="callout" role="note">
          {callouts.map(([k, v]) => (
            <div key={k}>{`${k}: ${v}`}</div>
          ))}
        </div>
      )}

      <details className="section section-headers" {...section("headers")}>
        <summary>Headers ({headers.length})</summary>
        <input
          type="search"
          className="header-filter"
          aria-label="Filter headers"
          placeholder="Filter headers"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <ul className="headers" aria-label="Headers">
          {shownHeaders.map(([k, v]) => (
            <li key={k}>
              <span className="header-name">{k}</span>
              <span className="header-value">{v}</span>
              <button className="header-copy" aria-label={`Copy ${k}`} onClick={() => onCopy(k, v)}>
                {copyLabel(copy, k, "Copy")}
              </button>
            </li>
          ))}
        </ul>
      </details>

      {hasMedia && (
        <details className="section" {...section("sdp")}>
          <summary>SDP</summary>
          <SdpSummary sdp={message.sdp!} />
        </details>
      )}

      {message.body && (
        <details className="section" {...section("body")}>
          <summary>Body</summary>
          <pre className="body">{message.body}</pre>
        </details>
      )}
    </div>
  );
}

interface CopyResult {
  key: string;
  ok: boolean;
}

function copyLabel(copy: CopyResult | null, key: string, idle: string): string {
  if (copy?.key !== key) return idle;
  return copy.ok ? "Copied" : "Copy failed";
}

function useCopyFeedback(): [CopyResult | null, (key: string, text: string) => Promise<void>] {
  const [result, setResult] = useState<CopyResult | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async (key: string, text: string) => {
    let ok = true;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      ok = false;
    }
    setResult({ key, ok });
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setResult(null), COPY_FEEDBACK_MS);
  };
  return [result, copy];
}

function SdpSummary({ sdp }: { sdp: Sdp }) {
  return (
    <section className="sdp" aria-label="Parsed SDP">
      <ul className="sdp-media-list">
        {sdp.media.map((m, i) => (
          <SdpMediaItem key={i} media={m} fallbackAddr={sdp.connection_addr} />
        ))}
      </ul>
    </section>
  );
}

function SdpMediaItem({
  media,
  fallbackAddr,
}: {
  media: SdpMedia;
  fallbackAddr: string | null;
}) {
  const addr = media.connection_addr ?? fallbackAddr;
  return (
    <li className="sdp-media">
      <div className="sdp-media-summary">
        <span className="sdp-kind">{media.kind}</span>
        {addr && (
          <>
            {" · "}
            <span className="sdp-endpoint">
              {addr}:{media.port}
            </span>
          </>
        )}
        {!addr && (
          <>
            {" · :"}
            <span className="sdp-endpoint">{media.port}</span>
          </>
        )}
        {" · "}
        <span className="sdp-proto">{media.proto}</span>
      </div>
      {media.formats.length > 0 && (
        <ul className="sdp-formats">
          {media.formats.map((pt) => (
            <li key={pt}>
              <span className="sdp-pt">{pt}</span>{" "}
              <span className="sdp-codec">{media.rtpmaps[String(pt)] ?? "—"}</span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}
