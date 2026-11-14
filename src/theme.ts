// Themes are sets of CSS custom properties (styles.css), selected via <html data-theme>.
import type { ThemeName } from "./api";
import type { MessageKey } from "./i18n";

export const THEMES: readonly { id: ThemeName; label: MessageKey }[] = [
  { id: "dark", label: "theme.dark" },
  { id: "light", label: "theme.light" },
  { id: "blue", label: "theme.blue" },
  { id: "terminal", label: "theme.terminal" },
  { id: "purple", label: "theme.purple" },
];

export function applyTheme(theme: ThemeName): void {
  document.documentElement.dataset.theme = theme;
}
