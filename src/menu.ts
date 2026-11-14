// Self-written context menu with keyboard support (arrows, Home/End, Escape).

export interface MenuItem {
  label: string;
  disabled?: boolean;
  /** Draws a separator line above this item. */
  separatorBefore?: boolean;
  run(): void | Promise<void>;
}

export class ContextMenu {
  private returnFocus: HTMLElement | null = null;

  constructor(private readonly el: HTMLElement) {
    el.setAttribute("role", "menu");
    const closeIfOutside = (event: Event): void => {
      if (this.isOpen && !(event.target instanceof Node && el.contains(event.target))) {
        this.close();
      }
    };
    document.addEventListener("pointerdown", closeIfOutside, true);
    document.addEventListener("wheel", closeIfOutside, { capture: true, passive: true });
    window.addEventListener("blur", () => this.close(false));
    window.addEventListener("resize", () => this.close());
    el.addEventListener("keydown", (event) => this.onKey(event));
  }

  get isOpen(): boolean {
    return !this.el.hidden;
  }

  open(items: readonly MenuItem[], x: number, y: number, label: string): void {
    this.close(false);
    this.returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    this.el.setAttribute("aria-label", label);
    const nodes: HTMLElement[] = [];
    for (const item of items) {
      if (item.separatorBefore && nodes.length > 0) {
        const separator = document.createElement("div");
        separator.className = "menu-separator";
        separator.setAttribute("role", "separator");
        nodes.push(separator);
      }
      const button = document.createElement("button");
      button.type = "button";
      button.setAttribute("role", "menuitem");
      button.textContent = item.label;
      button.disabled = item.disabled ?? false;
      button.addEventListener("click", () => {
        this.close();
        void item.run();
      });
      nodes.push(button);
    }
    this.el.replaceChildren(...nodes);
    this.el.hidden = false;

    // Keep the menu inside the window.
    const { width, height } = this.el.getBoundingClientRect();
    const left = Math.max(4, Math.min(x, window.innerWidth - width - 4));
    const top = Math.max(4, Math.min(y, window.innerHeight - height - 4));
    this.el.style.left = `${left}px`;
    this.el.style.top = `${top}px`;
    this.buttons()[0]?.focus();
  }

  close(restoreFocus = true): void {
    if (!this.isOpen) return;
    this.el.hidden = true;
    this.el.replaceChildren();
    if (restoreFocus) this.returnFocus?.focus({ preventScroll: true });
    this.returnFocus = null;
  }

  private buttons(): HTMLButtonElement[] {
    return [...this.el.querySelectorAll<HTMLButtonElement>("button:not(:disabled)")];
  }

  private onKey(event: KeyboardEvent): void {
    const buttons = this.buttons();
    const index = buttons.findIndex((button) => button === document.activeElement);
    let next: number;
    switch (event.key) {
      case "Escape":
      case "Tab":
        event.preventDefault();
        this.close();
        return;
      case "ArrowDown":
        next = (index + 1) % buttons.length;
        break;
      case "ArrowUp":
        next = (index - 1 + buttons.length) % buttons.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = buttons.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    buttons[next]?.focus();
  }
}
