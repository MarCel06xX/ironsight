# Ironsight – session notes

Desktop network scanner (Rust + Tauri 2, vanilla TS). v1 = host discovery + device info + export,
Windows only. Port scanning / packet capture / Linux come later – keep platform code behind
`NetBackend`.

## Current phase

**Phase 0 done** (scaffold, licenses, repo). Next: **Phase 1** – range parser, adapter listing,
ARP + ICMP discovery, live event streaming, minimal table UI.

Phases: 0 scaffold · 1 backend core · 2 enrichment · 3 UI · 4 export · 5 polish/release.
After each phase: fmt + clippy + tests, commit, push, short summary, **wait for the user's OK**.

## Rules

- Allowed crates: `tauri`, `tauri-build`, `tauri-plugin-dialog`, `tauri-plugin-opener`, `serde`,
  `serde_json`, `tokio`, `windows`, `thiserror`. Anything else: ask first (one-line justification).
  HTTPS title grabbing needs a TLS crate → ask before adding.
- Frontend: vanilla TS strict, no UI/CSS framework. No hard-coded UI strings (i18n: `locales/en.json`,
  `locales/de.json`). Never insert scanned strings as HTML (`textContent` only).
- Never print or read the raw IEEE OUI CSV into context (several MB). Converter script produces a
  compact file embedded with `include_bytes!`; no runtime downloads.
- Launch processes (mstsc, explorer, browser) only from Rust with a validated `IpAddr`.
- Scan results are never persisted automatically; only settings go to the app config dir.
- The user tests the GUI themselves (`npm run tauri dev`). Don't try to view the window.
- Prefer `cargo check` / `cargo test`; `npm run tauri build` only in phase 5.
- Don't install global tools or change the git identity.

## Key decisions

- Repo root = this folder; GitHub `MarCel06xX/ironsight` (public), dual MIT OR Apache-2.0.
- Tauri identifier `io.github.marcel06xx.ironsight` (login lowercased, reverse-DNS convention).
- `withGlobalTauri: false`; strict CSP in `tauri.conf.json` (`devCsp` relaxed only for Vite HMR).
  No inline styles/scripts – themes via `<html data-theme>` + CSS custom properties.
- Capability `default`: only `core:event:allow-listen/unlisten`. No shell plugin. Opener/dialog
  plugins get added (Rust side) in phases 3/4 and are called from Rust, not exposed to the webview
  unless needed.
- Lib crate has no mobile crate-types (desktop only). Bundle target: NSIS only.
- Data types use `IpAddr` (IPv4 only in v1, IPv6 not blocked by design).
- Online = ARP answers OR ICMP answers OR any TCP probe connects.
- Icons are still the Tauri template defaults → replace in phase 5.

## Planned layout (`src-tauri/src/`)

`scan/{range,engine}.rs` · `platform/{mod,windows}.rs` · `enrich/{dns,netbios,mdns,oui,services}.rs`
· `export/` · `commands.rs`. OUI converter: `tools/oui/` (raw CSV is git-ignored).

## Commands

```
npm run typecheck                                   # tsc strict
cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
npm run tauri dev                                   # user runs this
```
