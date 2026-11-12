const ENTRIES: { label: string; arrowClass: string }[] = [
  { label: "Request", arrowClass: "request" },
  { label: "1xx", arrowClass: "response-1xx" },
  { label: "2xx", arrowClass: "response-2xx" },
  { label: "3xx", arrowClass: "response-3xx" },
  { label: "4xx", arrowClass: "response-4xx" },
  { label: "5xx/6xx", arrowClass: "response-5xx" },
];

export function Legend() {
  return (
    <ul className="legend" aria-label="Arrow colors">
      {ENTRIES.map((e) => (
        <li key={e.label}>
          <span className={`legend-swatch ${e.arrowClass}`} aria-hidden="true" />
          <span>{e.label}</span>
        </li>
      ))}
    </ul>
  );
}
