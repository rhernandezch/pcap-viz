import type { Ref } from "react";
import type { Call } from "../types";
import { callStateOf, formatClock, formatDuration, shortUri } from "../util";

interface Props {
  calls: Call[];
  totalCount: number;
  query: string;
  onQueryChange: (query: string) => void;
  selectedCallId: string | null;
  onSelect: (callId: string) => void;
  filterRef?: Ref<HTMLInputElement>;
}

export function CallList({
  calls,
  totalCount,
  query,
  onQueryChange,
  selectedCallId,
  onSelect,
  filterRef,
}: Props) {
  return (
    <div className="call-list">
      <div className="call-filter">
        <input
          ref={filterRef}
          type="search"
          aria-label="Filter calls"
          placeholder="Filter calls (/)"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onQueryChange("");
          }}
        />
        {query.trim() && (
          <span className="call-filter-count">
            {calls.length} of {totalCount} calls
          </span>
        )}
      </div>
      {calls.length === 0 && (
        <div className="detail-empty">
          <span>No calls match "{query.trim()}"</span>{" "}
          <button type="button" onClick={() => onQueryChange("")}>
            Clear
          </button>
        </div>
      )}
      {calls.map((call) => {
        const state = callStateOf(call);
        const route = `${shortUri(call.from_uri)} → ${shortUri(call.to_uri)}`;
        return (
          <button
            key={call.call_id}
            className={`call-card${selectedCallId === call.call_id ? " active" : ""}`}
            onClick={() => onSelect(call.call_id)}
          >
            <div className="row1">
              <span className="route" title={route}>
                {route}
              </span>
              <span className={`badge tone-${state.tone}`} title={state.title}>
                {state.label}
              </span>
            </div>
            <div className="from-to" title={call.call_id}>
              {call.call_id}
            </div>
            <div className="meta">
              {formatClock(call.started_at)} UTC · {call.message_count} msgs ·{" "}
              {formatDuration(call.ended_at - call.started_at)}
            </div>
          </button>
        );
      })}
    </div>
  );
}
