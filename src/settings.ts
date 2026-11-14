// Settings dialog. Values are checked here for quick feedback and again in Rust on save.
import { type LanguageSetting, type Settings, type ThemeName, saveSettings } from "./api";
import { type MessageKey, t } from "./i18n";
import { THEMES, applyTheme } from "./theme";

const LANGUAGES: readonly { id: LanguageSetting; label: MessageKey }[] = [
  { id: "system", label: "language.system" },
  { id: "en", label: "language.en" },
  { id: "de", label: "language.de" },
];

const CONCURRENCY = { min: 1, max: 256 };
const TIMEOUT_MS = { min: 100, max: 10_000 };

function query<T extends Element>(root: ParentNode, selector: string): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`missing element ${selector}`);
  return el;
}

function fillSelect<T extends string>(
  select: HTMLSelectElement,
  options: readonly { id: T; label: MessageKey }[],
  value: T,
): void {
  select.replaceChildren(
    ...options.map(({ id, label }) => {
      const option = document.createElement("option");
      option.value = id;
      option.textContent = t(label);
      return option;
    }),
  );
  select.value = value;
}

/** Integer within `range`, or `null`. */
function readInteger(input: HTMLInputElement, range: { min: number; max: number }): number | null {
  const value = Number(input.value);
  const valid = input.value.trim() !== "" && Number.isInteger(value);
  const ok = valid && value >= range.min && value <= range.max;
  input.setAttribute("aria-invalid", String(!ok));
  return ok ? value : null;
}

export class SettingsDialog {
  private current: Settings | null = null;
  private readonly theme: HTMLSelectElement;
  private readonly language: HTMLSelectElement;
  private readonly concurrency: HTMLInputElement;
  private readonly timeout: HTMLInputElement;
  private readonly error: HTMLElement;

  constructor(
    private readonly dialog: HTMLDialogElement,
    private readonly onSaved: (settings: Settings) => void,
    private readonly describeError: (error: unknown) => string,
  ) {
    this.theme = query(dialog, "#set-theme");
    this.language = query(dialog, "#set-language");
    this.concurrency = query(dialog, "#set-concurrency");
    this.timeout = query(dialog, "#set-timeout");
    this.error = query(dialog, "#settings-error");

    // Live preview; reverted on cancel.
    this.theme.addEventListener("change", () => applyTheme(this.theme.value as ThemeName));
    query<HTMLFormElement>(dialog, "#settings-form").addEventListener("submit", (event) => {
      event.preventDefault();
      void this.save();
    });
    query<HTMLButtonElement>(dialog, "#settings-cancel").addEventListener("click", () =>
      this.cancel(),
    );
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      this.cancel();
    });
  }

  open(current: Settings): void {
    this.current = current;
    fillSelect(this.theme, THEMES, current.theme);
    fillSelect(this.language, LANGUAGES, current.language);
    this.concurrency.value = String(current.concurrency);
    this.timeout.value = String(current.timeoutMs);
    this.concurrency.removeAttribute("aria-invalid");
    this.timeout.removeAttribute("aria-invalid");
    this.error.hidden = true;
    this.dialog.showModal();
  }

  private cancel(): void {
    if (this.current) applyTheme(this.current.theme);
    this.dialog.close();
  }

  private showError(text: string): void {
    this.error.textContent = text;
    this.error.hidden = false;
  }

  private async save(): Promise<void> {
    const concurrency = readInteger(this.concurrency, CONCURRENCY);
    const timeoutMs = readInteger(this.timeout, TIMEOUT_MS);
    if (concurrency === null || timeoutMs === null) {
      this.showError(t("settings.invalid"));
      return;
    }
    const next: Settings = {
      theme: this.theme.value as ThemeName,
      language: this.language.value as LanguageSetting,
      concurrency,
      timeoutMs,
    };
    try {
      await saveSettings(next);
      this.current = next;
      this.dialog.close();
      this.onSaved(next);
    } catch (error) {
      this.showError(this.describeError(error));
    }
  }
}
