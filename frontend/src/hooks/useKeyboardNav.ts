import { useEffect, useRef } from "react";
import type { Call } from "../types";

interface Options {
  calls: Call[];
  selectedCallId: string | null;
  selectedMessageIndex: number | null;
  onSelectCall: (callId: string) => void;
  onSelectMessage: (messageIndex: number) => void;
  onToggleHelp: () => void;
  // While a dialog is open, only the help key stays active.
  paused: boolean;
}

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable;
}

export function useKeyboardNav(options: Options): void {
  // Read through a ref so the window listener is bound once and always sees
  // the latest selection.
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      // A focused control that handled the key (a pane separator resizing)
      // marks it defaultPrevented; don't also move the selection.
      if (e.defaultPrevented || isTyping(e.target)) return;
      const { calls, selectedCallId, selectedMessageIndex, onSelectCall, onSelectMessage } =
        optionsRef.current;
      if (e.key === "?") {
        optionsRef.current.onToggleHelp();
        e.preventDefault();
        return;
      }
      if (optionsRef.current.paused || calls.length === 0) return;

      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const call = calls.find((c) => c.call_id === selectedCallId);
        if (!call || call.messages.length === 0) return;
        const pos = call.messages.findIndex((m) => m.index === selectedMessageIndex);
        const down = e.key === "ArrowDown";
        const next =
          pos < 0
            ? down
              ? 0
              : call.messages.length - 1
            : Math.max(0, Math.min(call.messages.length - 1, pos + (down ? 1 : -1)));
        onSelectMessage(call.messages[next].index);
        e.preventDefault();
      } else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        const pos = calls.findIndex((c) => c.call_id === selectedCallId);
        const delta = e.key === "ArrowRight" ? 1 : -1;
        const next = pos < 0 ? 0 : Math.max(0, Math.min(calls.length - 1, pos + delta));
        onSelectCall(calls[next].call_id);
        e.preventDefault();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}
