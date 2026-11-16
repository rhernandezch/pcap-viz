import type { PointerEvent } from "react";
import type { Call } from "../types";
import { arrowClass } from "../util";

// Ticks sit on a 0..1000 scale; the viewBox adds room above and below so the
// first and last ticks aren't cut in half.
const SCALE = 1000;
const PAD = 6;
const VIEW_HEIGHT = SCALE + 2 * PAD;
const VIEW_WIDTH = 10;

interface Props {
  call: Call;
  visibleRange: { start: number; end: number } | null;
  selectedIndex: number | null;
  onJump: (messageIndex: number) => void;
}

export function Minimap({ call, visibleRange, selectedIndex, onJump }: Props) {
  if (call.messages.length < 2) return null;
  const t0 = call.started_at;
  const duration = call.ended_at - t0;
  const yOf = (t: number) => (duration > 0 ? Math.round(((t - t0) / duration) * SCALE) : 0);

  const jumpTo = (e: PointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    if (rect.height === 0) return;
    const y = ((e.clientY - rect.top) / rect.height) * VIEW_HEIGHT - PAD;
    const t = t0 + Math.min(1, Math.max(0, y / SCALE)) * duration;
    const nearest = call.messages.reduce((best, m) =>
      Math.abs(m.timestamp - t) < Math.abs(best.timestamp - t) ? m : best,
    );
    onJump(nearest.index);
  };

  return (
    <svg
      className="minimap"
      viewBox={`0 ${-PAD} ${VIEW_WIDTH} ${VIEW_HEIGHT}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture?.(e.pointerId);
        jumpTo(e);
      }}
      onPointerMove={(e) => {
        if (e.buttons === 1) jumpTo(e);
      }}
    >
      {visibleRange && (
        <rect
          className="viewport"
          x={0}
          y={yOf(visibleRange.start)}
          width={VIEW_WIDTH}
          height={yOf(visibleRange.end) - yOf(visibleRange.start)}
        />
      )}
      {call.messages.map((m) => (
        <line
          key={m.index}
          className={`tick ${arrowClass(m)}${m.index === selectedIndex ? " selected" : ""}`}
          x1={0}
          x2={VIEW_WIDTH}
          y1={yOf(m.timestamp)}
          y2={yOf(m.timestamp)}
        />
      ))}
    </svg>
  );
}
