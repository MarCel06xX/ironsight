# Ironsight – session notes

Desktop network scanner (Rust + Tauri 2, vanilla TS). v1 = host discovery + device info + export,
Windows only. Port scanning / packet capture / Linux come later – keep platform code behind
`NetBackend`.

## Current phase

**Phase 2 done** (enrichment: DNS PTR, mDNS, NetBIOS NBSTAT, OUI vendor, TCP service probes,
HTTP Server/title; extra columns in the provisional table).
Next: **Phase 3** - UI: virtual table, sort/filter, details panel, context menu (copy, browser,
RDP, Explorer, WoL), settings dialog, 5 themes, i18n switch, localized backend error codes.

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
  shell plugin. Opener/dialog
  plugins get added (Rust side) in phases 3/4 and are called from Rust, not exposed to the webview
  unless needed.
- Lib crate has no mobile crate-types (desktop only). Bundle target: NSIS only.
- Data types use `IpAddr` (IPv4 only in v1, IPv6 not blocked by design).
- Online = ARP answers OR ICMP answers OR any TCP probe connects.
- Icons are still the Tauri template defaults → replace in phase 5.

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
- IPC JSON is camelCase. Command errors are `{ code, message }`; `code` is meant for i18n
  (frontend still shows the English `message` - localize in phase 3).
- App commands are listed in `build.rs` (`AppManifest::commands`) and must also be allowed in
  `capabilities/default.json` (`allow-<command-name>`). Add new commands in both places plus
  `generate_handler!`.
- Limits: concurrency 1-256 (default 64), timeout 100-10,000 ms (default 1000).

## Frontend (phase 1, provisional)

`src/api.ts` typed invoke/listen wrappers · `src/i18n.ts` + `src/locales/{en,de}.json` (flat keys,
`data-i18n*` attributes, `de` is type-checked against `en`) · `src/main.ts` simple online-only table,
to be replaced by the virtual table in phase 3.

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

## Still planned

`src-tauri/src/export/` (phase 4).

## Commands

```
npm run typecheck                                   # tsc strict
cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
cargo test live_scan -- --ignored --nocapture       # real scan of the local /24 (manual)
npm run update-oui                                  # refresh the embedded IEEE OUI table
npm run tauri dev                                   # user runs this
```
