// Update check and update dialog. Download, signature verification and installation are done
// by the official updater plugin; this file only drives it and shows the progress.
import { relaunch } from "@tauri-apps/plugin-process";
import { type DownloadEvent, type Update, check } from "@tauri-apps/plugin-updater";
import { type AppInfo, openReleasePage } from "./api";
import { formatNumber, t } from "./i18n";

/** Keep the startup check short; it runs in the background. */
const CHECK_TIMEOUT_MS = 8000;

/** The newer release, or `null` if this version is current. Throws on network errors. */
export async function findUpdate(): Promise<Update | null> {
  return check({ timeout: CHECK_TIMEOUT_MS });
}

export interface UpdateHooks {
  isScanning(): boolean;
  stopScan(): Promise<void>;
  /** Remember "Skip this version". */
  skip(version: string): void;
  describeError(error: unknown): string;
}

function query<T extends Element>(root: ParentNode, selector: string): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`missing element ${selector}`);
  return el;
}

export class UpdateDialog {
  private update: Update | null = null;
  /** The user was warned about the running scan and may now confirm. */
  private scanConfirmed = false;
  private busy = false;
  private readonly text: HTMLElement;
  private readonly notesBlock: HTMLElement;
  private readonly notes: HTMLElement;
  private readonly hint: HTMLElement;
  private readonly progressBlock: HTMLElement;
  private readonly progress: HTMLProgressElement;
  private readonly progressText: HTMLElement;
  private readonly error: HTMLElement;
  private readonly installButton: HTMLButtonElement;
  private readonly laterButton: HTMLButtonElement;
  private readonly skipButton: HTMLButtonElement;

  constructor(
    private readonly dialog: HTMLDialogElement,
    private readonly info: AppInfo,
    private readonly hooks: UpdateHooks,
  ) {
    this.text = query(dialog, "#update-text");
    this.notesBlock = query(dialog, "#update-notes-block");
    this.notes = query(dialog, "#update-notes");
    this.hint = query(dialog, "#update-hint");
    this.progressBlock = query(dialog, "#update-progress-block");
    this.progress = query(dialog, "#update-progress");
    this.progressText = query(dialog, "#update-progress-text");
    this.error = query(dialog, "#update-error");
    this.installButton = query(dialog, "#update-install");
    this.laterButton = query(dialog, "#update-later");
    this.skipButton = query(dialog, "#update-skip");

    this.installButton.addEventListener("click", () => void this.accept());
    this.laterButton.addEventListener("click", () => this.dialog.close());
    this.skipButton.addEventListener("click", () => {
      if (this.update) this.hooks.skip(this.update.version);
      this.dialog.close();
    });
    // Esc must not hide a running installation.
    dialog.addEventListener("cancel", (event) => {
      if (this.busy) event.preventDefault();
    });
  }

  show(update: Update): void {
    this.update = update;
    this.scanConfirmed = false;
    this.busy = false;
    this.text.textContent = t("update.available", {
      version: update.version,
      current: this.info.version,
    });
    // Release notes come from latest.json: plain text only.
    const notes = update.body?.trim() ?? "";
    this.notes.textContent = notes;
    this.notesBlock.hidden = notes === "";
    this.hint.textContent = this.info.portable ? t("update.portableHint") : "";
    this.hint.hidden = !this.info.portable;
    this.installButton.textContent = t(this.info.portable ? "update.openPage" : "update.install");
    this.progressBlock.hidden = true;
    this.error.hidden = true;
    this.setButtonsDisabled(false);
    if (!this.dialog.open) this.dialog.showModal();
  }

  private setButtonsDisabled(disabled: boolean): void {
    this.installButton.disabled = disabled;
    this.laterButton.disabled = disabled;
    this.skipButton.disabled = disabled;
  }

  private showError(text: string): void {
    this.error.textContent = text;
    this.error.hidden = false;
  }

  private async accept(): Promise<void> {
    const update = this.update;
    if (!update) return;
    if (this.info.portable) {
      try {
        await openReleasePage();
        this.dialog.close();
      } catch (error) {
        this.showError(this.hooks.describeError(error));
      }
      return;
    }
    if (this.hooks.isScanning() && !this.scanConfirmed) {
      this.scanConfirmed = true;
      this.hint.textContent = t("update.scanRunning");
      this.hint.hidden = false;
      this.installButton.textContent = t("update.installAnyway");
      return;
    }

    this.busy = true;
    this.setButtonsDisabled(true);
    this.error.hidden = true;
    this.progressBlock.hidden = false;
    this.renderProgress(0, 0);
    try {
      if (this.hooks.isScanning()) await this.hooks.stopScan();
      let total = 0;
      let received = 0;
      await update.downloadAndInstall((event: DownloadEvent) => {
        switch (event.event) {
          case "Started":
            total = event.data.contentLength ?? 0;
            this.renderProgress(0, total);
            break;
          case "Progress":
            received += event.data.chunkLength;
            this.renderProgress(received, total);
            break;
          case "Finished":
            this.renderInstalling();
            break;
        }
      });
      // On Windows the installer usually ends the app before this point.
      this.renderInstalling();
      await relaunch();
    } catch (error) {
      console.warn("update failed", error);
      this.busy = false;
      this.progressBlock.hidden = true;
      this.setButtonsDisabled(false);
      this.showError(t("update.failed", { detail: this.hooks.describeError(error) }));
    }
  }

  private renderProgress(received: number, total: number): void {
    if (total > 0) {
      this.progress.max = total;
      this.progress.value = Math.min(received, total);
      const percent = Math.floor((Math.min(received, total) / total) * 100);
      this.progressText.textContent = t("update.downloading", { percent: formatNumber(percent) });
    } else {
      this.progress.removeAttribute("value"); // indeterminate
      this.progressText.textContent = t("update.downloadingUnknown");
    }
  }

  private renderInstalling(): void {
    this.progress.removeAttribute("value");
    this.progressText.textContent = t("update.installing");
  }
}
