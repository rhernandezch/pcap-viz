import { useState } from "react";
import { plural } from "../util";

export function WarningsBar({ warnings }: { warnings: string[] }) {
  const [open, setOpen] = useState(false);
  if (warnings.length === 0) return null;
  return (
    <section className="warnings-bar" aria-label="Parser warnings">
      <div className="warnings-summary">
        <span>{plural(warnings.length, "parser warning")}</span>
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
