import { useEffect, useRef, type KeyboardEvent, type RefObject } from "react";

interface TabItem {
  id: string;
  label: string;
}

interface Props {
  tabs: TabItem[];
  activeIdx: number;
  onSelect: (idx: number) => void;
  onClose: (idx: number) => void;
  fallbackFocusRef?: RefObject<HTMLElement>;
}

const CLOSE_KEYS = ["Delete", "Backspace"];

export function TabBar({ tabs, activeIdx, onSelect, onClose, fallbackFocusRef }: Props) {
  const listRef = useRef<HTMLDivElement>(null);
  const focusAfterClose = useRef(false);

  const tabButtons = () =>
    Array.from(listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]') ?? []);

  useEffect(() => {
    if (!focusAfterClose.current) return;
    focusAfterClose.current = false;
    (tabButtons()[activeIdx] ?? fallbackFocusRef?.current)?.focus();
  }, [tabs, activeIdx, fallbackFocusRef]);

  function close(idx: number) {
    // Only keyboard closes (focus already in the tablist) and closing the last
    // tab move focus; a mouse close of a background tab leaves it alone.
    focusAfterClose.current =
      tabs.length === 1 || !!listRef.current?.contains(document.activeElement);
    onClose(idx);
  }

  function onTabKeyDown(e: KeyboardEvent, idx: number) {
    if (CLOSE_KEYS.includes(e.key)) {
      close(idx);
      return;
    }
    const last = tabs.length - 1;
    const next =
      e.key === "ArrowRight" ? (idx === last ? 0 : idx + 1)
      : e.key === "ArrowLeft" ? (idx === 0 ? last : idx - 1)
      : e.key === "Home" ? 0
      : e.key === "End" ? last
      : null;
    if (next === null) return;
    e.preventDefault();
    onSelect(next);
    tabButtons()[next]?.focus();
  }

  // The tablist may own only tabs, so the mouse close control is decorative and
  // keyboard users close the focused tab with Delete or Backspace.
  return (
    <div className="tabs" role="tablist" aria-label="Open captures" ref={listRef}>
      {tabs.map((t, i) => (
        <div key={t.id} role="presentation" className={`tab${i === activeIdx ? " active" : ""}`}>
          <button
            type="button"
            role="tab"
            className="tab-label"
            aria-selected={i === activeIdx}
            aria-keyshortcuts={CLOSE_KEYS.join(" ")}
            tabIndex={i === activeIdx ? 0 : -1}
            title={t.label}
            onClick={() => onSelect(i)}
            onKeyDown={(e) => onTabKeyDown(e, i)}
          >
            {t.label}
          </button>
          <span className="close" aria-hidden="true" title={`Close ${t.label}`} onClick={() => close(i)}>
            ×
          </span>
        </div>
      ))}
    </div>
  );
}
