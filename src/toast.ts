// Short status messages in the corner (copied, packet sent, action failed).

export class Toast {
  private timer = 0;

  constructor(private readonly el: HTMLElement) {}

  show(text: string, kind: "info" | "error" = "info"): void {
    this.el.textContent = text;
    this.el.dataset.kind = kind;
    this.el.hidden = false;
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(
      () => {
        this.el.hidden = true;
      },
      kind === "error" ? 6000 : 2500,
    );
  }
}
