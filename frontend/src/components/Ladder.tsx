import { useEffect, useMemo, useRef } from "react";
import type { Call, SipMessage } from "../types";
import { arrowClass, labelOf } from "../util";

const LEFT_MARGIN = 90;
const TOP_MARGIN = 60;
const LANE_SPACING = 240;
const ROW_HEIGHT = 56;
const LANE_MIN_WIDTH = 160;
const BOTTOM_PAD = 24;

interface Props {
  call: Call | null;
  selectedIndex: number | null;
  onSelect: (msgIndex: number) => void;
}

export function Ladder({ call, selectedIndex, onSelect }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);

  const layout = useMemo(() => {
    if (!call) return null;
    const laneX: Record<string, number> = {};
    call.endpoints.forEach((ep, i) => {
      laneX[ep] = LEFT_MARGIN + i * LANE_SPACING;
    });
    const width = Math.max(
      LEFT_MARGIN + (call.endpoints.length - 1) * LANE_SPACING + LANE_MIN_WIDTH,
      LEFT_MARGIN + LANE_SPACING,
    );
    const height = TOP_MARGIN + call.messages.length * ROW_HEIGHT + BOTTOM_PAD;
    return { laneX, width, height };
  }, [call]);

  // Keep the selected row visible when it moves via keyboard.
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap || !call || selectedIndex === null) return;
    const pos = call.messages.findIndex((m) => m.index === selectedIndex);
    if (pos < 0) return;
    const y = TOP_MARGIN + pos * ROW_HEIGHT;
    const visibleTop = wrap.scrollTop;
    const visibleBottom = visibleTop + wrap.clientHeight;
    if (y < visibleTop + ROW_HEIGHT) {
      wrap.scrollTop = Math.max(0, y - ROW_HEIGHT);
    } else if (y + ROW_HEIGHT * 2 > visibleBottom) {
      wrap.scrollTop = y + ROW_HEIGHT * 2 - wrap.clientHeight;
    }
  }, [call, selectedIndex]);

  if (!call) {
    return <div className="ladder-empty">Select a call on the left to view its ladder.</div>;
  }

  const { laneX, width, height } = layout!;
  const t0 = call.started_at;

  return (
    <div className="ladder-wrap" ref={wrapRef}>
      <div className="ladder">
        <svg width={width} height={height} role="img" aria-label="SIP ladder">
          {/* Lane lines + endpoint headers */}
          {call.endpoints.map((ep) => (
            <g key={ep}>
              <line
                className="lane-line"
                x1={laneX[ep]}
                x2={laneX[ep]}
                y1={TOP_MARGIN - 18}
                y2={height - 8}
              />
              <text
                className="lane-label"
                x={laneX[ep]}
                y={TOP_MARGIN - 26}
                textAnchor="middle"
              >
                {ep}
              </text>
            </g>
          ))}

          {/* Arrow rows */}
          {call.messages.map((m, i) => {
            const y = TOP_MARGIN + i * ROW_HEIGHT;
            const x1 = laneX[m.src];
            const x2 = laneX[m.dst];
            if (x1 === undefined || x2 === undefined) return null;
            const isSelected = selectedIndex === m.index;
            return (
              <Arrow
                key={m.index}
                message={m}
                x1={x1}
                x2={x2}
                y={y}
                width={width}
                t0={t0}
                selected={isSelected}
                onClick={() => onSelect(m.index)}
              />
            );
          })}
        </svg>
      </div>
    </div>
  );
}

interface ArrowProps {
  message: SipMessage;
  x1: number;
  x2: number;
  y: number;
  width: number;
  t0: number;
  selected: boolean;
  onClick: () => void;
}

function Arrow({ message, x1, x2, y, width, t0, selected, onClick }: ArrowProps) {
  const rightward = x2 > x1;
  const arrowY = y + 22;
  const labelY = y + 12;
  const arrowHeadSize = 8;

  // Self-loop (src === dst) — render a small U
  const isSelfLoop = x1 === x2;
  const pathD = isSelfLoop
    ? `M ${x1} ${arrowY} c 40 0, 40 28, 0 28`
    : `M ${x1} ${arrowY} L ${x2} ${arrowY}`;
  const tipX = isSelfLoop ? x1 : x2;
  const tipY = isSelfLoop ? arrowY + 28 : arrowY;
  const tipDir = isSelfLoop ? -1 : rightward ? 1 : -1;

  const elapsed = message.timestamp - t0;
  const timeText =
    elapsed < 1
      ? `+${Math.round(elapsed * 1000)}ms`
      : `+${elapsed.toFixed(2)}s`;

  return (
    <g className={`row${selected ? " selected" : ""}`} onClick={onClick}>
      <rect className="row-bg" x={0} y={y} width={width} height={ROW_HEIGHT} />
      <rect className="hit" x={0} y={y} width={width} height={ROW_HEIGHT} />
      <text className="time-label" x={LEFT_MARGIN - 12} y={arrowY + 4} textAnchor="end">
        {timeText}
      </text>
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
