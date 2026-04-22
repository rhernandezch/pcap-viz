import type { Call } from "../types";
import { finalStatusOf, formatDuration, shortUri } from "../util";

interface Props {
  calls: Call[];
  selectedCallId: string | null;
  onSelect: (callId: string) => void;
}

export function CallList({ calls, selectedCallId, onSelect }: Props) {
  if (calls.length === 0) {
    return (
      <div className="detail-empty">No SIP calls found in this pcap.</div>
    );
  }
  return (
    <div className="call-list">
      {calls.map((call) => {
        const dur = call.ended_at - call.started_at;
        const status = finalStatusOf(call);
        return (
          <button
            key={call.call_id}
            className={`call-card${selectedCallId === call.call_id ? " active" : ""}`}
            onClick={() => onSelect(call.call_id)}
          >
            <div className="row1">
              <span>{shortUri(call.from_uri)}</span>
              <span>→</span>
              <span>{shortUri(call.to_uri)}</span>
            </div>
            <div className="from-to" title={call.call_id}>
              {call.call_id}
            </div>
            <div className="meta">
              {call.message_count} msgs · {formatDuration(dur)} · {status}
            </div>
          </button>
        );
      })}
    </div>
  );
}
