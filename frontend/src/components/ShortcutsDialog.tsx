import { useEffect, useRef } from "react";
import { SHORTCUTS } from "../shortcuts";

export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  // Escape is handled on window because focus can leave the dialog.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCloseRef.current();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      opener?.focus();
    };
  }, []);

  return (
    <div className="dialog-backdrop" data-testid="dialog-backdrop" onClick={onClose}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="shortcuts-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="shortcuts-title">Keyboard shortcuts</h2>
        <dl className="shortcut-list">
          {SHORTCUTS.map((s) => (
            <div key={s.keys}>
              <dt>
                <kbd>{s.keys}</kbd>
              </dt>
              <dd>{s.description}</dd>
            </div>
          ))}
        </dl>
        <button ref={closeRef} type="button" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}
