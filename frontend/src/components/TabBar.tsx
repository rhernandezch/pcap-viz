import { useEffect, useRef, type RefObject } from "react";

interface TabItem {
  id: string;
  label: string;
  title?: string;
}

interface Props {
  tabs: TabItem[];
  activeIdx: number;
  onSelect: (idx: number) => void;
  onClose: (idx: number) => void;
  fallbackFocusRef?: RefObject<HTMLElement>;
}

export function TabBar({ tabs, activeIdx, onSelect, onClose, fallbackFocusRef }: Props) {
  const listRef = useRef<HTMLDivElement>(null);
  const focusAfterClose = useRef(false);

  useEffect(() => {
    if (!focusAfterClose.current) return;
    focusAfterClose.current = false;
    const activeTab = listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]')[activeIdx];
    (activeTab ?? fallbackFocusRef?.current)?.focus();
  }, [tabs, activeIdx, fallbackFocusRef]);

  function close(idx: number) {
    focusAfterClose.current = true;
    onClose(idx);
  }

  // The tablist may own only tabs, so the mouse close control is decorative and
  // keyboard users close the focused tab with Delete.
  return (
    <div className="tabs" role="tablist" aria-label="Open captures" ref={listRef}>
      {tabs.map((t, i) => (
        <div key={t.id} role="presentation" className={`tab${i === activeIdx ? " active" : ""}`}>
          <button
            type="button"
            role="tab"
            className="tab-label"
            aria-selected={i === activeIdx}
            aria-keyshortcuts="Delete"
            title={t.title ?? t.label}
            onClick={() => onSelect(i)}
            onKeyDown={(e) => {
              if (e.key === "Delete") close(i);
            }}
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
