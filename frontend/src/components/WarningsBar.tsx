import { useState } from "react";

export function WarningsBar({ warnings }: { warnings: string[] }) {
  const [open, setOpen] = useState(false);
  if (warnings.length === 0) return null;
  const count = `${warnings.length} parser warning${warnings.length === 1 ? "" : "s"}`;
  return (
    <section className="warnings-bar" aria-label="Parser warnings">
      <div className="warnings-summary">
        <span>{count}: some SIP messages may be missing from the ladder.</span>
        <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? "Hide" : "Show"}
        </button>
      </div>
      {open && (
        <ul className="warnings-list">
          {warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
