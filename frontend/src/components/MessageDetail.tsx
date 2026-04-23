import { useMemo, useState } from "react";
import type { Sdp, SdpMedia, SipMessage } from "../types";

interface Props {
  message: SipMessage | null;
}

export function MessageDetail({ message }: Props) {
  const [copied, setCopied] = useState(false);

  const raw = useMemo(() => {
    if (!message) return "";
    const firstLine = message.request_line ?? message.status_line ?? "";
    const headerLines = Object.entries(message.headers).map(([k, v]) => `${k}: ${v}`);
    return [firstLine, ...headerLines, "", message.body ?? ""].join("\r\n");
  }, [message]);

  if (!message) {
    return <div className="detail-empty">Click a message on the ladder to see its headers.</div>;
  }

  return (
    <div className="detail">
      <button
        className="copy"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(raw);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          } catch {
            // ignore
          }
        }}
      >
        {copied ? "copied" : "copy raw"}
      </button>
      {message.request_line && <div className="request-line">{message.request_line}</div>}
      {message.status_line && <div className="status-line">{message.status_line}</div>}
      <div className="endpoint">
        {message.src} → {message.dst} ({message.transport})
        <br />
        t = {message.timestamp.toFixed(3)}s
      </div>
      <dl className="headers">
        {Object.entries(message.headers).map(([k, v]) => (
          <FragmentRow key={k} name={k} value={v} />
        ))}
      </dl>
      {message.sdp && <SdpSummary sdp={message.sdp} />}
      {message.body && <pre className="body">{message.body}</pre>}
    </div>
  );
}

function SdpSummary({ sdp }: { sdp: Sdp }) {
  if (sdp.media.length === 0) return null;
  return (
    <section className="sdp" aria-label="Parsed SDP">
      <div className="sdp-header">SDP</div>
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

function FragmentRow({ name, value }: { name: string; value: string }) {
  return (
    <>
      <dt>{name}</dt>
      <dd>{value}</dd>
    </>
  );
}
