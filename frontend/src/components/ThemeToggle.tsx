import { useThemePreference, type ThemePreference } from "../theme";

const LABELS: Record<ThemePreference, string> = { system: "System", light: "Light", dark: "Dark" };

export function ThemeToggle() {
  const [preference, cycle] = useThemePreference();
  const label = LABELS[preference];
  return (
    <button type="button" className="theme-toggle" aria-label={`Theme: ${label}`} onClick={cycle}>
      {label}
    </button>
  );
}
