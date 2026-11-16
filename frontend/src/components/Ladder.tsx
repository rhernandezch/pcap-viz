import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useElementWidth } from "../hooks/useElementWidth";
import { laneLabel } from "../laneNames";
import type { Call, SipMessage } from "../types";
import { arrowClass, formatDelta, formatOffset, labelOf } from "../util";

// Wide enough for the offset and delta lines of the time column.
const LEFT_MARGIN = 110;
const RIGHT_PAD = 120;
const TOP_MARGIN = 28;
const LANE_SPACING_MIN = 200;
const LANE_SPACING_MAX = 420;
const LANE_SPACING_FALLBACK = 240;
const ROW_HEIGHT = 56;
// Self-loop rows need extra vertical space for the U-curve (28px drop)
// plus clearance before the next row's hit area.
const SELF_LOOP_ROW_HEIGHT = 80;
const BOTTOM_PAD = 24;

interface Props {
  call: Call | null;
  selectedIndex: number | null;
  onSelect: (msgIndex: number) => void;
  aliases: Record<string, string>;
  onRename: (endpoint: string, name: string) => void;
}

interface Row {
  y: number;
  height: number;
}

function rowHeightFor(m: SipMessage): number {
  return m.src === m.dst ? SELF_LOOP_ROW_HEIGHT : ROW_HEIGHT;
}

function laneSpacing(paneWidth: number | null, laneCount: number): number {
  if (paneWidth === null || laneCount < 2) return LANE_SPACING_FALLBACK;
  const fill = (paneWidth - LEFT_MARGIN - RIGHT_PAD) / (laneCount - 1);
  return Math.min(LANE_SPACING_MAX, Math.max(LANE_SPACING_MIN, fill));
}

export function Ladder({ call, selectedIndex, onSelect, aliases, onRename }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const rowRefs = useRef(new Map<number, SVGGElement>());
  const paneWidth = useElementWidth(wrapRef);

  const layout = useMemo(() => {
    if (!call) return null;
    const spacing = laneSpacing(paneWidth, call.endpoints.length);
    const laneX: Record<string, number> = {};
    call.endpoints.forEach((ep, i) => {
      laneX[ep] = LEFT_MARGIN + i * spacing;
    });

    const rows: Row[] = [];
    let cursor = TOP_MARGIN;
    for (const m of call.messages) {
      const h = rowHeightFor(m);
      rows.push({ y: cursor, height: h });
      cursor += h;
    }

    const contentWidth = LEFT_MARGIN + Math.max(1, call.endpoints.length - 1) * spacing + RIGHT_PAD;
    const width = Math.max(contentWidth, paneWidth ?? 0);
    const height = cursor + BOTTOM_PAD;
    return { laneX, width, height, rows };
  }, [call, paneWidth]);

  // Keep the selected row visible when it moves via keyboard, and keep focus
  // on it while focus is inside the ladder.
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap || !call || !layout || selectedIndex === null) return;
    const pos = call.messages.findIndex((m) => m.index === selectedIndex);
    if (pos < 0) return;
    const row = layout.rows[pos];
    const visibleTop = wrap.scrollTop;
    const visibleBottom = visibleTop + wrap.clientHeight;
    if (row.y < visibleTop + row.height) {
      wrap.scrollTop = Math.max(0, row.y - row.height);
    } else if (row.y + row.height * 2 > visibleBottom) {
      wrap.scrollTop = row.y + row.height * 2 - wrap.clientHeight;
    }
    if (wrap.contains(document.activeElement)) rowRefs.current.get(selectedIndex)?.focus();
  }, [call, layout, selectedIndex]);

  if (!call) {
    return <div className="ladder-empty">Select a call on the left to view its ladder.</div>;
  }

  const { laneX, width, height, rows } = layout!;
  const t0 = call.started_at;
  const tabStop = call.messages.some((m) => m.index === selectedIndex)
    ? selectedIndex
    : call.messages[0]?.index;
  const endpointName = (ep: string) => aliases[ep] ?? ep;

  return (
    <div className="ladder-wrap" ref={wrapRef}>
      <div className="lane-header" style={{ width }}>
        {call.endpoints.map((ep) => (
          <LaneHead
            key={ep}
            endpoint={ep}
            name={laneLabel(aliases, call, ep)}
            x={laneX[ep]}
            onRename={onRename}
          />
        ))}
      </div>
      <div className="ladder">
        <svg width={width} height={height} role="group" aria-label="SIP ladder">
          {call.endpoints.map((ep) => (
            <line
              key={ep}
              className="lane-line"
              x1={laneX[ep]}
              x2={laneX[ep]}
              y1={TOP_MARGIN - 18}
              y2={height - 8}
            />
          ))}

          {call.messages.map((m, i) => {
            const row = rows[i];
            const x1 = laneX[m.src];
            const x2 = laneX[m.dst];
            if (x1 === undefined || x2 === undefined) return null;
            const offset = formatOffset(m.timestamp - t0);
            return (
              <Arrow
                key={m.index}
                rowRef={(el) => {
                  if (el) rowRefs.current.set(m.index, el);
                  else rowRefs.current.delete(m.index);
                }}
                message={m}
                x1={x1}
                x2={x2}
                y={row.y}
                rowHeight={row.height}
                width={width}
                offset={offset}
                delta={i > 0 ? formatDelta(m.timestamp - call.messages[i - 1].timestamp) : null}
                label={`${labelOf(m)}, ${endpointName(m.src)} to ${endpointName(m.dst)}, ${offset}`}
                selected={selectedIndex === m.index}
                tabbable={tabStop === m.index}
                onSelect={() => onSelect(m.index)}
              />
            );
          })}
        </svg>
      </div>
    </div>
  );
}

interface LaneHeadProps {
  endpoint: string;
  name: string;
  x: number;
  onRename: (endpoint: string, name: string) => void;
}

function LaneHead({ endpoint, name, x, onRename }: LaneHeadProps) {
  const [draft, setDraft] = useState<string | null>(null);
  // Escape unmounts the input, which can still fire blur; don't save then.
  const cancelled = useRef(false);

  const save = () => {
    if (!cancelled.current && draft !== null) onRename(endpoint, draft);
    setDraft(null);
  };

  return (
    <div className="lane-head" style={{ left: x }} title={`${name} (${endpoint})`}>
      {draft === null ? (
        <button
          type="button"
          className="lane-name"
          aria-label={`Rename lane ${name} (${endpoint})`}
          onClick={() => {
            cancelled.current = false;
            setDraft(name);
          }}
        >
          {name}
        </button>
      ) : (
        <input
          className="lane-name-input"
          aria-label={`Lane name for ${endpoint}`}
          value={draft}
          autoFocus
          onChange={(e) => setDraft(e.target.value)}
          onBlur={save}
          onKeyDown={(e) => {
            if (e.key === "Enter") save();
            if (e.key === "Escape") {
              cancelled.current = true;
              setDraft(null);
            }
          }}
        />
      )}
      <span className="lane-ip">{endpoint}</span>
    </div>
  );
}

interface ArrowProps {
  message: SipMessage;
  x1: number;
  x2: number;
  y: number;
  rowHeight: number;
  width: number;
  offset: string;
  delta: string | null;
  label: string;
  selected: boolean;
  tabbable: boolean;
  onSelect: () => void;
  rowRef: (el: SVGGElement | null) => void;
}

function Arrow({
  message,
  x1,
  x2,
  y,
  rowHeight,
  width,
  offset,
  delta,
  label,
  selected,
  tabbable,
  onSelect,
  rowRef,
}: ArrowProps) {
  const rightward = x2 > x1;
  const arrowY = y + 22;
  const labelY = y + 12;
  const arrowHeadSize = 8;

  // Self-loop (src === dst) — render a U that fits within this row only.
  const isSelfLoop = x1 === x2;
  const loopDrop = isSelfLoop ? rowHeight - 32 : 0;
  const pathD = isSelfLoop
    ? `M ${x1} ${arrowY} c 40 0, 40 ${loopDrop}, 0 ${loopDrop}`
    : `M ${x1} ${arrowY} L ${x2} ${arrowY}`;
  const tipX = isSelfLoop ? x1 : x2;
  const tipY = isSelfLoop ? arrowY + loopDrop : arrowY;
  const tipDir = isSelfLoop ? -1 : rightward ? 1 : -1;

  const onKeyDown = (e: KeyboardEvent<SVGGElement>) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    onSelect();
  };

  return (
    <g
      ref={rowRef}
      className={`row${selected ? " selected" : ""}`}
      role="button"
      aria-pressed={selected}
      aria-label={label}
      tabIndex={tabbable ? 0 : -1}
      onClick={onSelect}
      onKeyDown={onKeyDown}
    >
      <rect className="row-bg" x={0} y={y} width={width} height={rowHeight} />
      <rect className="hit" x={0} y={y} width={width} height={rowHeight} />
      <text className="time-label" x={LEFT_MARGIN - 12} y={arrowY + 4} textAnchor="end">
        {offset}
      </text>
      {delta && (
        <text className="time-delta" x={LEFT_MARGIN - 12} y={arrowY + 17} textAnchor="end">
          {delta}
        </text>
      )}
      <g className="arrow-group">
        <path className={`arrow-line ${arrowClass(message)}`} d={pathD} />
        <polygon
          className={`arrow-line ${arrowClass(message)}`}
          points={`${tipX},${tipY} ${tipX - tipDir * arrowHeadSize},${tipY - 4} ${tipX - tipDir * arrowHeadSize},${tipY + 4}`}
          fill="currentColor"
          stroke="none"
          style={{ fill: "currentColor" }}
        />
        <text
          className="arrow-label"
          x={isSelfLoop ? x1 + 50 : (x1 + x2) / 2}
          y={labelY}
          textAnchor="middle"
        >
          {labelOf(message)}
        </text>
      </g>
    </g>
  );
}
