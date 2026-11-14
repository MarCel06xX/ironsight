<p align="center">
  <img src="app-icon.svg" width="96" height="96" alt="Ironsight icon">
</p>

<h1 align="center">Ironsight</h1>

<p align="center">
  Open-source desktop network scanner for Windows – host discovery, device information and export.<br>
  Built with Rust and Tauri 2. <a href="#deutsch">Deutsche Version weiter unten.</a>
</p>

> [!IMPORTANT]
> **Only scan networks you own or are explicitly authorized to scan.** Scanning other people's
> networks can be illegal in your country and may violate terms of service. You are responsible
> for how you use this tool.

## Screenshots

_Screenshots will follow._

<!-- ![Ironsight main window](docs/screenshot.png) -->

## Features

- **Host discovery** with ARP (local segment), ICMP echo and TCP connect probes. A host counts as
  online if any of them gets an answer. No administrator rights and no Npcap needed.
- **Flexible targets:** single addresses, ranges like `192.168.1.10-50` or
  `192.168.1.1-192.168.2.20`, CIDR blocks from `/16` to `/32`, and comma-separated lists –
  up to 65,536 addresses per scan. Picking a network adapter fills in its subnet.
- **Device information:** hostname from reverse DNS, mDNS and NetBIOS (the source is shown), MAC
  address and vendor (embedded IEEE OUI table, randomized/private MACs are labeled), response
  time, NetBIOS workgroup, open services from a small port list (FTP, SSH, Telnet, HTTP, HTTPS,
  SMB, RDP, 8080, 8443), and HTTP `Server` header and page title.
- **Live results** in a fast virtual table that stays smooth with 65,536 rows: sortable columns
  (IP addresses sort numerically), text filter, "show only online", details panel.
- **Actions per host:** copy IP or MAC, open in the browser (HTTP/HTTPS), connect with Remote
  Desktop, show file shares in Explorer, Wake-on-LAN.
- **Export:** CSV (Excel-friendly, `;` or `,` as delimiter), JSON (all data, versioned schema)
  and a printable, self-contained HTML report – for all scanned addresses or just the filtered
  view.
- **Themes and languages:** five color themes (dark, light, deep blue, terminal green, purple),
  English and German, switchable without a restart.
- **Privacy:** no telemetry, no update checks, no network traffic except the scan itself. Scan
  results are only written to disk when you export them; only the settings are saved.

## Download

Get the files from the [releases page](https://github.com/MarCel06xX/ironsight/releases):

| File | Description |
| --- | --- |
| `Ironsight_<version>_x64-setup.exe` | **Installer.** Installs for the current user (no administrator rights) with a Start menu entry. Downloads the WebView2 runtime if it is missing. |
| `Ironsight_<version>_x64-portable.zip` | **Portable.** Unzip anywhere and run `Ironsight.exe`. Because of the included `portable` marker file, settings and the WebView2 profile are stored in a `data` folder next to the exe instead of AppData. |
| `SHA256SUMS.txt` | SHA-256 checksums of both files. |

Requirements: Windows 10 or 11 (x64) with the Microsoft Edge WebView2 runtime. It is part of
Windows 11. The portable version does not install it; on Windows 10, get it from
[Microsoft](https://developer.microsoft.com/microsoft-edge/webview2/) if needed.

**The binaries are not code-signed**, so Windows SmartScreen may warn about an unknown
publisher. Verify the download first:

```
Get-FileHash .\Ironsight_<version>_x64-setup.exe -Algorithm SHA256
```

The hash must match the line for that file in `SHA256SUMS.txt` (upper/lower case does not
matter). Then choose **More info → Run anyway**.

## How it works

| Step | Method | Notes |
| --- | --- | --- |
| Discovery | `SendARP`, `IcmpSendEcho`, TCP connect | ARP only works inside the local network segment, so MAC address and vendor stay empty for hosts behind a router. That is expected. |
| Names | Reverse DNS (PTR), mDNS, NetBIOS node status | Hand-written packet builders and parsers; all received data is bounds-checked and treated as untrusted. |
| Vendor | IEEE MA-L registry | Converted into a compact table and embedded in the program – no downloads at runtime. |
| Services | TCP connect, HTTP/1.0 `GET /` | Page titles are read on ports 80 and 8080. Redirects are only followed on the same host and port. |

## Build from source

Requirements: Windows 10/11, [Rust](https://rustup.rs) (stable, MSVC toolchain), Visual Studio
Build Tools with the "Desktop development with C++" workload, and [Node.js](https://nodejs.org)
LTS.

```
git clone https://github.com/MarCel06xX/ironsight.git
cd ironsight
npm install
npm run tauri dev      # development build with live reload
npm run tauri build    # release build; installer in src-tauri/target/release/bundle/nsis/
```

Checks:

```
npm run typecheck
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Releases are made with `.\scripts\release.ps1`: it checks, builds the installer and the
portable zip, writes `SHA256SUMS.txt` and publishes a GitHub release for the version in
`src-tauri/tauri.conf.json` (`-NoPublish` only builds into `release/`).

To refresh the vendor table, run `npm run update-oui`. It downloads the IEEE MA-L list and writes
`src-tauri/data/oui.bin`, which is committed to the repository.

### Project layout

```
src/                  Frontend (TypeScript, no framework): table, dialogs, i18n, themes
src/locales/          English and German texts (also used for exports)
src-tauri/src/
  scan/               Target parsing and the scan engine
  platform/           OS-specific code behind a trait (Windows: IP Helper API)
  enrich/             DNS, mDNS, NetBIOS, vendor lookup, service probes
  export/             CSV, JSON and HTML writers
  commands.rs         Tauri commands; every input is validated here
tools/oui/            Converter for the IEEE vendor list
```

## Roadmap

Ideas for later versions: port scanning, packet capture and Linux support.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Vendor names come from the public
[IEEE Registration Authority MA-L listing](https://standards.ieee.org/products-programs/regauth/).

---

<a id="deutsch"></a>

## Deutsch

Ironsight ist ein quelloffener Netzwerkscanner für Windows. Er findet Geräte im Netzwerk, zeigt
Informationen zu ihnen an und exportiert die Ergebnisse.

> [!IMPORTANT]
> **Scanne nur Netzwerke, die dir gehören oder für die du ausdrücklich eine Erlaubnis hast.**
> Das Scannen fremder Netzwerke kann strafbar sein (in Deutschland u. a. nach § 202c StGB) und
> gegen Nutzungsbedingungen verstoßen. Für den Einsatz bist du selbst verantwortlich.

### Funktionen

- **Geräteerkennung** über ARP (lokales Segment), ICMP-Echo und TCP-Verbindungstests – ohne
  Administratorrechte und ohne Npcap.
- **Ziele:** einzelne Adressen, Bereiche wie `192.168.1.10-50`, CIDR von `/16` bis `/32` und
  Listen mit Kommas; bis zu 65.536 Adressen pro Scan.
- **Geräteinfos:** Hostname aus DNS, mDNS und NetBIOS (mit Quelle), MAC-Adresse und Hersteller,
  Antwortzeit, Arbeitsgruppe, offene Dienste sowie Webserver und Seitentitel.
- **Live-Ergebnisse** in einer schnellen Tabelle mit Sortierung, Filter, „Nur online anzeigen“ und
  Detailansicht.
- **Aktionen:** IP/MAC kopieren, im Browser öffnen, Remotedesktop, Freigaben im Explorer,
  Wake-on-LAN.
- **Export** als CSV (für deutsches Excel mit `;`), JSON oder druckbarer HTML-Bericht.
- **Fünf Farbdesigns**, Deutsch und Englisch, Umschalten ohne Neustart.
- **Datenschutz:** keine Telemetrie, kein Netzwerkverkehr außer dem Scan. Ergebnisse werden nur
  beim Export gespeichert.

### Download

Auf der [Release-Seite](https://github.com/MarCel06xX/ironsight/releases) gibt es:

- **Installer** (`…_x64-setup.exe`): Installation für den aktuellen Benutzer, ohne
  Administratorrechte. Lädt die WebView2 Runtime nach, falls sie fehlt.
- **Portable** (`…_x64-portable.zip`): entpacken und `Ironsight.exe` starten. Einstellungen und
  WebView2-Profil liegen im Ordner `data` neben der exe statt in AppData.
- **`SHA256SUMS.txt`** mit den Prüfsummen.

Voraussetzung ist Windows 10/11 (x64) mit der Microsoft Edge WebView2 Runtime (in Windows 11
enthalten). **Die Dateien sind nicht signiert**, daher kann SmartScreen warnen. Vorher prüfen mit
`Get-FileHash .\<Datei> -Algorithm SHA256` und mit `SHA256SUMS.txt` vergleichen, dann
**Weitere Informationen → Trotzdem ausführen**.

Außerhalb des eigenen Netzwerksegments (hinter einem Router) funktioniert ARP nicht. MAC-Adresse
und Hersteller bleiben dort leer – das ist normal.

### Selbst bauen

Voraussetzungen: Windows 10/11, Rust (stable, MSVC), Visual Studio Build Tools mit
„Desktopentwicklung mit C++“ und Node.js LTS. Danach `npm install` und `npm run tauri dev` bzw.
`npm run tauri build` (Befehle siehe oben).

### Lizenz

Wahlweise [Apache-2.0](LICENSE-APACHE) oder [MIT](LICENSE-MIT).
