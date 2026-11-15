// Self-written virtual table: only the visible rows exist in the DOM, so it stays smooth
// with 65k hosts. Row elements come from a pool and are positioned with transforms.
import type { HostResult } from "./api";
import { type MessageKey, t } from "./i18n";
import type { SortKey } from "./store";

/** Must match `--row-height` in styles.css. */
export const ROW_HEIGHT = 28;
/** Extra rows rendered above and below the viewport. */
const OVERSCAN = 6;

export interface Column {
  key: SortKey;
  label: MessageKey;
  /** Fills an empty cell. DOM APIs / textContent only - never HTML strings. */
  render(cell: HTMLElement, host: HostResult): void;
}

export interface TableEvents {
  select(ip: string): void;
  contextMenu(ip: string, x: number, y: number): void;
  sort(key: SortKey): void;
}

interface PooledRow {
  el: HTMLDivElement;
  cells: HTMLDivElement[];
  /** Host and translation generation the cells were rendered for. */
  host: HostResult | null;
  generation: number;
  /** Row index the element is positioned at; -1 while unused. */
  index: number;
}

function div(className: string): HTMLDivElement {
  const el = document.createElement("div");
  el.className = className;
  return el;
}

export class VirtualTable {
  private readonly header = div("vt-header vt-grid");
  private readonly body = div("vt-body");
  private readonly empty = div("vt-empty");
  private readonly pool: PooledRow[] = [];
  private rows: readonly HostResult[] = [];
  private selected: string | null = null;
  private sortKey: SortKey | null = null;
  private ascending = true;
  private generation = 0;
  private frame = 0;

  constructor(
    private readonly root: HTMLElement,
    private readonly columns: readonly Column[],
    private readonly events: TableEvents,
  ) {
    root.classList.add("vtable");
    root.setAttribute("role", "grid");
    this.header.setAttribute("role", "row");
    this.header.setAttribute("aria-rowindex", "1");
    this.body.setAttribute("role", "rowgroup");
    root.append(this.header, this.body, this.empty);
    this.renderHeader();

    root.addEventListener("scroll", () => this.schedule(), { passive: true });
    new ResizeObserver(() => this.schedule()).observe(root);
    this.header.addEventListener("click", (event) => {
      const button = (event.target as Element).closest<HTMLButtonElement>("button[data-key]");
      if (button?.dataset.key) this.events.sort(button.dataset.key as SortKey);
    });
    this.body.addEventListener("click", (event) => {
      const ip = this.ipAt(event);
      if (ip === null) return;
      this.events.select(ip);
      root.focus({ preventScroll: true });
    });
    root.addEventListener("contextmenu", (event) => this.onContextMenu(event));
    root.addEventListener("keydown", (event) => this.onKey(event));
  }

  setRows(rows: readonly HostResult[], emptyText: string): void {
    this.rows = rows;
    this.body.style.height = `${rows.length * ROW_HEIGHT}px`;
    this.root.setAttribute("aria-rowcount", String(rows.length + 1));
    this.empty.textContent = emptyText;
    this.empty.hidden = rows.length > 0;
    this.schedule();
  }

  setSelected(ip: string | null): void {
    this.selected = ip;
    this.schedule();
  }

  setSort(key: SortKey, ascending: boolean): void {
    this.sortKey = key;
    this.ascending = ascending;
    this.updateSortIndicator();
  }

  /** Re-renders the header and every cell, e.g. after a language change. */
  invalidate(): void {
    this.generation++;
    this.renderHeader();
    this.schedule();
  }

  scrollToRow(index: number): void {
    const top = index * ROW_HEIGHT;
    const visible = this.root.clientHeight - this.header.offsetHeight;
    if (top < this.root.scrollTop) {
      this.root.scrollTop = top;
    } else if (top + ROW_HEIGHT > this.root.scrollTop + visible) {
      this.root.scrollTop = top + ROW_HEIGHT - visible;
    }
  }

  private schedule(): void {
    if (this.frame !== 0) return;
    this.frame = requestAnimationFrame(() => {
      this.frame = 0;
      this.render();
    });
  }

  private render(): void {
    const scrollTop = this.root.scrollTop;
    const height = this.root.clientHeight;
    const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
    const last = Math.min(this.rows.length, Math.ceil((scrollTop + height) / ROW_HEIGHT) + OVERSCAN);
    const needed = Math.ceil(height / ROW_HEIGHT) + 2 * OVERSCAN + 1;
    while (this.pool.length < needed) this.pool.push(this.createRow());

    // Row i always uses slot i % size, so rows that stay visible keep their element.
    const size = this.pool.length;
    for (let slot = 0; slot < size; slot++) {
      const row = this.pool[slot];
      if (!row) continue;
      const index = first + ((slot - (first % size) + size) % size);
      if (index < last) {
        this.fill(row, index);
      } else if (row.index !== -1) {
        row.el.hidden = true;
        row.index = -1;
      }
    }
  }

  private createRow(): PooledRow {
    const el = div("vt-row vt-grid");
    el.setAttribute("role", "row");
    el.hidden = true;
    const cells = this.columns.map(() => {
      const cell = div("vt-cell");
      cell.setAttribute("role", "gridcell");
      return cell;
    });
    el.append(...cells);
    this.body.append(el);
    return { el, cells, host: null, generation: -1, index: -1 };
  }

  private fill(row: PooledRow, index: number): void {
    const host = this.rows[index];
    if (!host) return;
    if (row.index !== index) {
      row.index = index;
      row.el.style.transform = `translateY(${index * ROW_HEIGHT}px)`;
      row.el.setAttribute("aria-rowindex", String(index + 2));
    }
    if (row.host !== host || row.generation !== this.generation) {
      row.host = host;
      row.generation = this.generation;
      row.el.dataset.ip = host.ip;
      row.el.classList.toggle("offline", host.status === "offline");
      row.el.classList.toggle("unused", host.status === "unused");
      this.columns.forEach((column, i) => {
        const cell = row.cells[i];
        if (!cell) return;
        cell.replaceChildren();
        column.render(cell, host);
        cell.title = cell.textContent ?? "";
      });
    }
    const selected = host.ip === this.selected;
    row.el.classList.toggle("selected", selected);
    row.el.setAttribute("aria-selected", String(selected));
    row.el.hidden = false;
  }

  private renderHeader(): void {
    const cells = this.columns.map((column) => {
      const cell = div("vt-th");
      cell.setAttribute("role", "columnheader");
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.key = column.key;
      const label = document.createElement("span");
      label.className = "vt-th-label";
      label.textContent = t(column.label);
      const arrow = document.createElement("span");
      arrow.className = "vt-sort";
      arrow.setAttribute("aria-hidden", "true");
      button.append(label, arrow);
      cell.append(button);
      return cell;
    });
    this.header.replaceChildren(...cells);
    this.updateSortIndicator();
  }

  private updateSortIndicator(): void {
    for (const cell of this.header.querySelectorAll<HTMLElement>(".vt-th")) {
      const key = cell.querySelector<HTMLButtonElement>("button")?.dataset.key;
      const order = this.ascending ? "ascending" : "descending";
      cell.setAttribute("aria-sort", key === this.sortKey ? order : "none");
    }
  }

  private ipAt(event: Event): string | null {
    const target = event.target instanceof Element ? event.target : null;
    return target?.closest<HTMLElement>(".vt-row")?.dataset.ip ?? null;
  }

  private indexOf(ip: string | null): number {
    return ip === null ? -1 : this.rows.findIndex((host) => host.ip === ip);
  }

  private onContextMenu(event: MouseEvent): void {
    event.preventDefault();
    const ip = this.ipAt(event);
    if (ip !== null) {
      this.events.select(ip);
      this.events.contextMenu(ip, event.clientX, event.clientY);
      return;
    }
    // Context-menu key or Shift+F10: open it at the selected row.
    const index = this.indexOf(this.selected);
    if (event.target !== this.root || this.selected === null || index < 0) return;
    this.scrollToRow(index);
    const rect = this.root.getBoundingClientRect();
    const y = rect.top + this.header.offsetHeight + (index + 1) * ROW_HEIGHT - this.root.scrollTop;
    this.events.contextMenu(this.selected, rect.left + 24, y);
  }

  private onKey(event: KeyboardEvent): void {
    const count = this.rows.length;
    if (count === 0 || event.target !== this.root) return;
    const current = this.indexOf(this.selected);
    const page = Math.max(
      1,
      Math.floor((this.root.clientHeight - this.header.offsetHeight) / ROW_HEIGHT) - 1,
    );
    let next: number;
    switch (event.key) {
      case "ArrowDown":
        next = current + 1;
        break;
      case "ArrowUp":
        next = current < 0 ? 0 : current - 1;
        break;
      case "PageDown":
        next = Math.max(current, 0) + page;
        break;
      case "PageUp":
        next = current - page;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = count - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    next = Math.min(count - 1, Math.max(0, next));
    const host = this.rows[next];
    if (!host) return;
    this.events.select(host.ip);
    this.scrollToRow(next);
  }
}
