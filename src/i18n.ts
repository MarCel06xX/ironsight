// Minimal self-written i18n: flat JSON catalogs, English as fallback.
import de from "./locales/de.json";
import en from "./locales/en.json";

export type MessageKey = keyof typeof en;
export type Language = "en" | "de";

// Typing `de` against the English keys makes a missing translation a compile error.
const catalogs: Record<Language, Record<MessageKey, string>> = { en, de };

let current: Language = detectLanguage(navigator.language);

export function detectLanguage(tag: string): Language {
  return tag.toLowerCase().startsWith("de") ? "de" : "en";
}

/** Translates `key`, replacing `{name}` placeholders with `params`. */
export function t(key: MessageKey, params: Record<string, string | number> = {}): string {
  const template = catalogs[current][key];
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

/** Fills elements marked with `data-i18n`, `data-i18n-placeholder` or `data-i18n-title`. */
export function applyTranslations(root: ParentNode): void {
  document.documentElement.lang = current;
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n as MessageKey);
  }
  for (const el of root.querySelectorAll<HTMLInputElement>("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder as MessageKey);
  }
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n-title]")) {
    el.title = t(el.dataset.i18nTitle as MessageKey);
  }
}

/** Switches the language at runtime (used by the settings dialog from phase 3 on). */
export function setLanguage(language: Language): void {
  current = language;
  applyTranslations(document);
}
