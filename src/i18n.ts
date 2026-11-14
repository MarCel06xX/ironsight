// Minimal self-written i18n: flat JSON catalogs, English as fallback, switchable at runtime.
import de from "./locales/de.json";
import en from "./locales/en.json";

export type MessageKey = keyof typeof en;
export type Language = "en" | "de";

// Typing `de` against the English keys makes a missing translation a compile error.
const catalogs: Record<Language, Record<MessageKey, string>> = { en, de };
const listeners: Array<() => void> = [];

let current: Language = detectLanguage(navigator.language);
let numberFormat = new Intl.NumberFormat(current);
let dateTimeFormat = makeDateTimeFormat(current);

function makeDateTimeFormat(language: Language): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "medium" });
}

export function detectLanguage(tag: string): Language {
  return tag.toLowerCase().startsWith("de") ? "de" : "en";
}

export function currentLanguage(): Language {
  return current;
}

export function isMessageKey(key: string): key is MessageKey {
  return Object.hasOwn(catalogs.en, key);
}

/** Translates `key`, replacing `{name}` placeholders with `params`. */
export function t(key: MessageKey, params: Record<string, string | number> = {}): string {
  return catalogs[current][key].replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

export function formatNumber(value: number): string {
  return numberFormat.format(value);
}

export function formatDateTime(ms: number): string {
  return dateTimeFormat.format(new Date(ms));
}

function translateAttribute(key: string | undefined): string {
  if (key !== undefined && isMessageKey(key)) return t(key);
  console.warn(`unknown i18n key: ${key}`);
  return key ?? "";
}

/** Fills elements marked with `data-i18n`, `-placeholder`, `-title` or `-aria-label`. */
export function applyTranslations(root: ParentNode): void {
  document.documentElement.lang = current;
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    el.textContent = translateAttribute(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll<HTMLInputElement>("[data-i18n-placeholder]")) {
    el.placeholder = translateAttribute(el.dataset.i18nPlaceholder);
  }
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n-title]")) {
    el.title = translateAttribute(el.dataset.i18nTitle);
  }
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n-aria-label]")) {
    el.setAttribute("aria-label", translateAttribute(el.dataset.i18nAriaLabel));
  }
}

/** Switches the language without a restart; dynamic content re-renders via listeners. */
export function setLanguage(language: Language): void {
  if (language === current) return;
  current = language;
  numberFormat = new Intl.NumberFormat(language);
  dateTimeFormat = makeDateTimeFormat(language);
  applyTranslations(document);
  for (const listener of listeners) listener();
}

export function onLanguageChange(listener: () => void): void {
  listeners.push(listener);
}
