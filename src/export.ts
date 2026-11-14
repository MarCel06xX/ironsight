// Export dialog: format, CSV delimiter and rows. The file itself is chosen in the native
// save dialog and written by the backend from its own copy of the scan results.
import { type CsvDelimiter, type ExportFormat, exportResults } from "./api";
import { type MessageKey, currentLanguage, formatNumber, t } from "./i18n";

const DELIMITERS: readonly { id: CsvDelimiter; label: MessageKey }[] = [
  { id: ";", label: "export.delimiterSemicolon" },
  { id: ",", label: "export.delimiterComma" },
];

export interface ExportContext {
  /** Every scanned address. */
  allCount: number;
  /** Rows of the current filtered view, in display order. */
  viewIps: string[];
  delimiter: CsvDelimiter;
}

function query<T extends Element>(root: ParentNode, selector: string): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`missing element ${selector}`);
  return el;
}

export class ExportDialog {
  private context: ExportContext | null = null;
  private readonly form: HTMLFormElement;
  private readonly delimiter: HTMLSelectElement;
  private readonly delimiterField: HTMLElement;
  private readonly viewOption: HTMLInputElement;

  constructor(
    private readonly dialog: HTMLDialogElement,
    /** `delimiter` is `null` for non-CSV exports. */
    private readonly onDone: (path: string, delimiter: CsvDelimiter | null) => void,
    private readonly onError: (error: unknown) => void,
  ) {
    this.form = query(dialog, "#export-form");
    this.delimiter = query(dialog, "#export-delimiter");
    this.delimiterField = query(dialog, "#export-delimiter-field");
    this.viewOption = query(dialog, 'input[name="export-scope"][value="view"]');

    this.form.addEventListener("change", () => this.updateDelimiterField());
    this.form.addEventListener("submit", (event) => {
      event.preventDefault();
      void this.submit();
    });
    query<HTMLButtonElement>(dialog, "#export-cancel").addEventListener("click", () =>
      dialog.close(),
    );
  }

  open(context: ExportContext): void {
    this.context = context;
    this.delimiter.replaceChildren(
      ...DELIMITERS.map(({ id, label }) => {
        const option = document.createElement("option");
        option.value = id;
        option.textContent = t(label);
        return option;
      }),
    );
    this.delimiter.value = context.delimiter;
    query(this.dialog, "#export-scope-all").textContent = t("export.scopeAll", {
      count: formatNumber(context.allCount),
    });
    query(this.dialog, "#export-scope-view").textContent = t("export.scopeView", {
      count: formatNumber(context.viewIps.length),
    });
    this.viewOption.disabled = context.viewIps.length === 0;
    if (this.viewOption.disabled) this.radio("export-scope", "all");
    this.updateDelimiterField();
    this.dialog.showModal();
  }

  private value(name: string): string {
    const item = this.form.elements.namedItem(name);
    return item instanceof RadioNodeList ? item.value : "";
  }

  private radio(name: string, value: string): void {
    const item = this.form.elements.namedItem(name);
    if (item instanceof RadioNodeList) item.value = value;
  }

  private updateDelimiterField(): void {
    this.delimiterField.hidden = this.value("export-format") !== "csv";
  }

  private async submit(): Promise<void> {
    const context = this.context;
    if (!context) return;
    const format = this.value("export-format") as ExportFormat;
    const delimiter = format === "csv" ? (this.delimiter.value as CsvDelimiter) : null;
    const ips = this.value("export-scope") === "view" ? context.viewIps : null;
    this.dialog.close();
    try {
      const path = await exportResults({
        format,
        delimiter,
        ips,
        language: currentLanguage(),
        utcOffsetMinutes: -new Date().getTimezoneOffset(),
      });
      if (path !== null) this.onDone(path, delimiter);
    } catch (error) {
      this.onError(error);
    }
  }
}
