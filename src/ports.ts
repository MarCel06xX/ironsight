// Port scan UI pieces: the port list choice, the custom list field (checked by the Rust
// parser, so the rules are the same as for the scan), the "Scan ports…" dialog and the
// one-time notice to scan only networks one may scan.
import {
  type PortChoice,
  type PortScanOptions,
  type PortSelection,
  type Settings,
  checkPortList,
} from "./api";
import { portChoiceLabel } from "./format";
import { formatNumber, t } from "./i18n";

const PORT_CHOICES: readonly PortChoice[] = ["common", "top100", "top1000", "all", "custom"];
/** Pause after typing before the list is checked. */
const CHECK_DELAY_MS = 250;

function query<T extends Element>(root: ParentNode, selector: string): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`missing element ${selector}`);
  return el;
}

/** Fills a select with the presets and "Custom …". */
export function fillPortChoices(select: HTMLSelectElement, value: PortChoice): void {
  select.replaceChildren(
    ...PORT_CHOICES.map((choice) => {
      const option = document.createElement("option");
      option.value = choice;
      option.textContent = portChoiceLabel(choice);
      return option;
    }),
  );
  select.value = value;
}

/** The port list chosen in the settings. */
export function settingsSelection(settings: Settings): PortSelection {
  return settings.portPreset === "custom"
    ? { custom: settings.portCustom }
    : { preset: settings.portPreset };
}

/** Port scan request with the limits from the settings. */
export function portOptions(settings: Settings, selection: PortSelection): PortScanOptions {
  return {
    selection,
    timeoutMs: settings.portTimeoutMs,
    concurrency: settings.portConcurrency,
    maxProbes: settings.portMaxProbes,
  };
}

/** Text input for a custom port list with inline feedback ("42 ports" or the error). */
export class PortListField {
  private timer = 0;
  /** Only the answer to the latest check is shown. */
  private sequence = 0;

  constructor(
    private readonly input: HTMLInputElement,
    private readonly message: HTMLElement,
    private readonly describeError: (error: unknown) => string,
  ) {
    input.addEventListener("input", () => {
      window.clearTimeout(this.timer);
      this.timer = window.setTimeout(() => void this.check(), CHECK_DELAY_MS);
    });
  }

  get value(): string {
    return this.input.value;
  }

  reset(value: string): void {
    window.clearTimeout(this.timer);
    this.sequence++;
    this.input.value = value;
    this.input.removeAttribute("aria-invalid");
    this.show("", false);
  }

  /** Checks the list now: its normalized form, or `null` with the error shown. */
  async check(): Promise<string | null> {
    window.clearTimeout(this.timer);
    const sequence = ++this.sequence;
    try {
      const info = await checkPortList(this.input.value);
      if (sequence === this.sequence) {
        this.input.setAttribute("aria-invalid", "false");
        this.show(t("ports.listCount", { count: formatNumber(info.count) }), false);
      }
      return info.normalized;
    } catch (error) {
      if (sequence === this.sequence) {
        this.input.setAttribute("aria-invalid", "true");
        this.show(this.describeError(error), true);
      }
      return null;
    }
  }

  private show(text: string, isError: boolean): void {
    this.message.textContent = text;
    this.message.dataset.kind = isError ? "error" : "info";
  }
}

/** Shows the custom list field only while "Custom …" is selected. */
function linkCustomField(select: HTMLSelectElement, field: HTMLElement, list: PortListField): void {
  select.addEventListener("change", () => {
    field.hidden = select.value !== "custom";
    if (!field.hidden && list.value.trim() !== "") void list.check();
  });
}

/** Settings part of the port list: the choice and, for "Custom …", the list. */
export class PortChoiceInput {
  readonly list: PortListField;

  constructor(
    private readonly select: HTMLSelectElement,
    private readonly customField: HTMLElement,
    input: HTMLInputElement,
    message: HTMLElement,
    describeError: (error: unknown) => string,
  ) {
    this.list = new PortListField(input, message, describeError);
    linkCustomField(select, customField, this.list);
  }

  set(choice: PortChoice, custom: string): void {
    fillPortChoices(this.select, choice);
    this.list.reset(custom);
    this.customField.hidden = choice !== "custom";
  }

  get choice(): PortChoice {
    return this.select.value as PortChoice;
  }

  /** The selection, or `null` if the custom list is invalid (the error is shown). */
  async read(): Promise<{ choice: PortChoice; custom: string; selection: PortSelection } | null> {
    const choice = this.choice;
    if (choice !== "custom") {
      return { choice, custom: this.list.value, selection: { preset: choice } };
    }
    const normalized = await this.list.check();
    if (normalized === null) return null;
    return { choice, custom: normalized, selection: { custom: normalized } };
  }
}

/** "Scan ports…" for one host: the settings' port list, or another one just for this scan. */
export class HostPortsDialog {
  private readonly title: HTMLElement;
  private readonly ports: PortChoiceInput;
  private resolve: ((selection: PortSelection | null) => void) | null = null;

  constructor(
    private readonly dialog: HTMLDialogElement,
    describeError: (error: unknown) => string,
  ) {
    this.title = query(dialog, "#host-ports-title");
    this.ports = new PortChoiceInput(
      query(dialog, "#host-ports-choice"),
      query(dialog, "#host-ports-custom-field"),
      query(dialog, "#host-ports-custom"),
      query(dialog, "#host-ports-custom-msg"),
      describeError,
    );
    query<HTMLFormElement>(dialog, "#host-ports-form").addEventListener("submit", (event) => {
      event.preventDefault();
      void this.submit();
    });
    query<HTMLButtonElement>(dialog, "#host-ports-cancel").addEventListener("click", () =>
      this.finish(null),
    );
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      this.finish(null);
    });
  }

  /** Resolves to the chosen port list, or `null` if the dialog was cancelled. */
  open(ip: string, settings: Settings): Promise<PortSelection | null> {
    this.finish(null);
    this.title.textContent = t("hostPorts.title", { ip });
    this.ports.set(settings.portPreset, settings.portCustom);
    this.dialog.showModal();
    return new Promise((resolve) => {
      this.resolve = resolve;
    });
  }

  private async submit(): Promise<void> {
    const read = await this.ports.read();
    if (read !== null) this.finish(read.selection);
  }

  private finish(selection: PortSelection | null): void {
    if (this.dialog.open) this.dialog.close();
    const resolve = this.resolve;
    this.resolve = null;
    resolve?.(selection);
  }
}

/** One-time notice before the first port scan. */
export class NoticeDialog {
  private resolve: ((accepted: boolean) => void) | null = null;

  constructor(private readonly dialog: HTMLDialogElement) {
    query<HTMLButtonElement>(dialog, "#notice-accept").addEventListener("click", () =>
      this.finish(true),
    );
    query<HTMLButtonElement>(dialog, "#notice-cancel").addEventListener("click", () =>
      this.finish(false),
    );
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      this.finish(false);
    });
  }

  ask(): Promise<boolean> {
    this.finish(false);
    this.dialog.showModal();
    query<HTMLButtonElement>(this.dialog, "#notice-cancel").focus();
    return new Promise((resolve) => {
      this.resolve = resolve;
    });
  }

  private finish(accepted: boolean): void {
    if (this.dialog.open) this.dialog.close();
    const resolve = this.resolve;
    this.resolve = null;
    resolve?.(accepted);
  }
}
