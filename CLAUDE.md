# Ironsight – session notes

Desktop network scanner (Rust + Tauri 2, vanilla TS). v1 = host discovery + device info + export,
Windows only. Port scanning / packet capture / Linux come later – keep platform code behind
`NetBackend`.

## Current phase

**All 5 phases done - v0.1.0 released** (README en/de, app icon, NSIS installer, GitHub release).
Next: whatever the user asks for (ideas: screenshots in `docs/`, code signing, HTTPS titles
(needs a TLS crate - ask), port scanning, packet capture, Linux backend).

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
- GitHub blocks pushes exposing the private email: this repo has a *local* `user.email`
  (`199737179+MarCel06xX@users.noreply.github.com`). A fresh clone needs the same local setting.
- Tauri identifier `io.github.marcel06xx.ironsight` (login lowercased, reverse-DNS convention).
- `withGlobalTauri: false`; strict CSP in `tauri.conf.json` (`devCsp` relaxed only for Vite HMR).
  No inline styles/scripts – themes via `<html data-theme>` + CSS custom properties.
- Capability `default`: only `core:event:allow-listen/unlisten` plus the app's own commands. No
  shell plugin. `tauri-plugin-opener` is used only through its free function
  `tauri_plugin_opener::open_url` from Rust - the plugin is *not* registered, so the webview has
  no opener API at all. Do the same with the dialog plugin if possible (phase 4).
- Settings (`settings.rs`): `%APPDATA%\io.github.marcel06xx.ironsight\settings.json`, `{theme,
  language, concurrency, timeoutMs}`; missing/corrupt file -> defaults, out-of-range numbers reset
  per field, atomic write via `.tmp` + rename, 64 KiB read limit. Validated again on save.
- Lib crate has no mobile crate-types (desktop only). Bundle target: NSIS only.
- Data types use `IpAddr` (IPv4 only in v1, IPv6 not blocked by design).
- Online = ARP answers OR ICMP answers OR any TCP probe connects.
- App icon source: `app-icon.svg` (self-made). Regenerate with `npx tauri icon app-icon.svg`,
  then delete `src-tauri/icons/android` and `src-tauri/icons/ios` (desktop only).

## Releasing

Bump the version in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` (+ `Cargo.lock` via
`cargo check`) and `package.json` (`npm version X.Y.Z --no-git-tag-version`), commit, push, then
run `.\scripts\release.ps1` (`-NoPublish` = build into `release/` only). It builds the portable
exe, then the NSIS installer + `.sig` (signing key `%USERPROFILE%\.tauri\ironsight.key`, empty
password; the script only passes the path - never read/print/commit the private key), writes
`SHA256SUMS.txt` and `latest.json`, tags `vX.Y.Z` and creates a normal (latest) GitHub release.

## Portable build and updater

- Cargo feature `portable` (`npm run tauri build -- --no-bundle --features portable`): settings in
  `ironsight-settings.json`, WebView2 profile in `ironsight-webview\` next to the exe; AppData if
  the exe folder is not writable (`portable.rs`). The window is created in `lib.rs` setup via
  `WebviewWindowBuilder::from_config` + `data_directory` (config window has `create: false`).
  Installed build: settings `%APPDATA%\<id>\`, WebView2 `%LOCALAPPDATA%\<id>\EBWebView`.
- Updater: `tauri-plugin-updater` + `tauri-plugin-process`, used from the webview (`src/update.ts`;
  capabilities `updater:default`, `process:allow-restart`). Endpoint
  `https://github.com/MarCel06xX/ironsight/releases/latest/download/latest.json`, install mode
  `passive`, `plugins.updater.pubkey` = content of `ironsight.key.pub`. Startup check 1.5 s after
  launch, 8 s timeout, silent on errors; settings `checkUpdates` / `skippedVersion`. Portable
  build (`app_info().portable`) only opens the release page (`open_release_page`).

## Backend design (phase 1)

- `scan/range.rs`: `TargetSet` = merged inclusive `u32` ranges; CIDR /16-/32 (network/broadcast
  skipped up to /30), `a.b.c.d-e[.f[.g]]` suffix ranges, full ranges, comma lists; max 65,536 hosts.
- `platform/`: sync, blocking `NetBackend` trait (`list_adapters`, `arp_resolve`, `icmp_ping`);
  `windows.rs` = IP Helper (`GetAdaptersAddresses`, `SendARP`, `IcmpSendEcho`), `windows` crate 0.62
  (same version Tauri pulls in). `unsupported.rs` keeps other OSes compiling.
- `scan/engine.rs`: `run_scan(backend, probes, targets, config, cancel: watch::Receiver<bool>, id,
  on_batch)`; Tauri-free, tested with `MockBackend` + `MockProbes`. Host slots = concurrency
  semaphore (held through enrichment). ARP only for on-link targets (own address: no ARP, MAC from
  adapter). SendARP blocks ~1-3 s and cannot be aborted: the first report comes after `timeout`,
  the still-running ARP call is awaited afterwards (adds the MAC, or revives a host first reported
  offline). Stop drops all pending lookups via `tokio::select!` on the watch channel.
- `HostProbes` trait (engine) = socket-based TCP probe + enrichment, implemented by
  `enrich::NetEnricher` (DNS servers per adapter from `GetAdaptersAddresses`).
- Events: `scan:batch` (`ScanBatch`: host upserts keyed by IP + totals, flushed every 100 ms or 512
  hosts; offline hosts are sent too; online hosts come again with `complete: true`) and `scan:finished` (`ScanSummary`). One scan at a time.
- IPC JSON is camelCase. Command errors are `{ code, message, detail }`; the frontend shows
  `error.<code>` from the locale files with `{detail}` filled in, falling back to `message`.
  New error codes need an `error.*` key in both locale files.
- Host actions (`actions.rs`, `platform::open_*`): browser URL built from `IpAddr` + bool + `u16`;
  `mstsc.exe /v:<ip>` and `explorer.exe \\<ip>` started by absolute path from
  `GetSystemDirectoryW` / `GetSystemWindowsDirectoryW` (no PATH search, IPv4 only for now);
  WoL magic packet = 6x FF + 16x MAC to UDP 9, directed + limited broadcast from the adapter of
  the host's subnet (all adapters if unknown/off-link; plus unicast if off-link).
- App commands are listed in `build.rs` (`AppManifest::commands`) and must also be allowed in
  `capabilities/default.json` (`allow-<command-name>`). Add new commands in both places plus
  `generate_handler!`.
- Limits: concurrency 1-256 (default 64), timeout 100-10,000 ms (default 1000).

## Frontend (`src/`)

- `api.ts` typed invoke/listen wrappers + IPC types · `export.ts` export dialog · `main.ts` wiring (scan flow, menu actions,
  error/toast, settings, language listener).
- `store.ts` `HostStore`: Map ip -> host + precomputed search text/IP key; `rows()` = filtered +
  sorted view, cached until a change. Empty values sort last in both directions. 65,536 hosts:
  3-52 ms per re-sort (Node bench); refreshes are coalesced to >= 200 ms while scanning.
- `table.ts` `VirtualTable`: sticky header + absolutely positioned pooled rows (`translateY`,
  slot = row index % pool size), fixed `ROW_HEIGHT` 28 px = CSS `--row-height`; grid columns via
  `--vt-columns`. Keyboard: arrows/Page/Home/End, context-menu key / Shift+F10.
- `details.ts` panel, `menu.ts` context menu, `toast.ts`, `settings.ts` dialog (theme preview,
  revert on cancel), `theme.ts` (5 themes = `[data-theme]` blocks in `styles.css`, colors only),
  `format.ts` display helpers.
- `i18n.ts`: flat keys, `data-i18n`, `-placeholder`, `-title`, `-aria-label`; `de` type-checked
  against `en`; `setLanguage` + `onLanguageChange` for runtime switching; `Intl` number/date formats.
- CSS changes go through CSSOM (`el.style.x = ...`), never `style` attributes (CSP).
- Browser context menu is suppressed outside inputs; Ctrl+F focuses the filter.

## Enrichment (phase 2, `src-tauri/src/enrich/`)

- `wire.rs` DNS message builder/parser (PTR only; compression with backward-only pointers, jump
  limit, RDATA bounds) shared by `dns.rs` (system DNS servers, max 2) and `mdns.rs` (unicast
  one-shot query to `<ip>:5353`, on-link hosts only). `netbios.rs` NBSTAT `*` query on UDP 137.
- `services.rs`: TCP connect on 21,22,23,80,443,445,3389,8080,8443; HTTP/1.0 `GET /` on 80/8080
  only, max 64 KiB, max 3 redirects and only same host+port (never follow to other hosts).
  HTTPS titles need a TLS crate -> not added, ask the user first.
- `oui.rs`: binary table `src-tauri/data/oui.bin` (`IOUI` v1, sorted 3-byte prefixes + u24 name
  offsets, ~700 KB), built by `npm run update-oui` (`tools/oui/update-oui.mjs`; raw CSV never in
  context). Locally administered MACs (bit 0x02) get `macLocal: true` and no vendor.
- All network strings go through `clean_text` (controls -> space, bidi/zero-width removed,
  length cap). Hostname priority: DNS > mDNS > NetBIOS (`hostnameSource`).
- Lookup timeout = scan timeout clamped to 500-3000 ms.

## Export (phase 4, `src-tauri/src/export/`)

- The backend keeps the last scan in memory (`commands::ScanRecord`, filled from the batch
  callback, cleared when a new scan starts). `export_results` writes from that copy; the
  frontend only sends the format, delimiter, language, UTC offset and - for "current view" - the
  ordered IP list. No export while a scan runs.
- Save dialog: `tauri-plugin-dialog` is registered (needed for the Rust API) but the webview has
  no `dialog:*` permission. Non-blocking `save_file` + oneshot; missing extension is added.
- `csv.rs`: BOM, CRLF, `;`/`,`, RFC 4180 quoting; network text starting with `= + - @ \t \r`
  gets a leading `'` (formula injection). Timestamps local RFC 3339 with offset.
- `json.rs`: own snake_case schema (`schema_version` 1, generator, exported_at, scope, scan
  metadata, hosts with all names/services); UTC timestamps. Bump the version on breaking changes.
- `html.rs`: one file, inline CSS, `<meta>` CSP `default-src 'none'`, everything escaped, A4
  landscape print styles.
- `labels.rs`: texts come from `src/locales/*.json` via `include_str!` (one catalog for UI and
  exports); a test renders every format in both languages and fails on raw keys/placeholders.
- `time.rs`: self-written civil-date conversion (no chrono). Settings now also store
  `csvDelimiter` (remembered from the last CSV export).

## Commands

```
npm run typecheck                                   # tsc strict
cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
cargo test live_scan -- --ignored --nocapture       # real scan of the local /24 (manual)
npm run update-oui                                  # refresh the embedded IEEE OUI table
npm run tauri dev                                   # user runs this
```
