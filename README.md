<p align="center">
  <img src="app-icon.svg" width="96" height="96" alt="Ironsight icon">
</p>

<h1 align="center">Ironsight</h1>

<p align="center">
  Open-source desktop network scanner for Windows – host discovery, port scanning, device information and export.<br>
  Built with Rust and Tauri 2. <a href="#deutsch">Deutsche Version weiter unten.</a>
</p>

> [!IMPORTANT]
> **Only scan networks you own or are explicitly authorized to scan.** Scanning other people's
> networks can be illegal in your country and may violate terms of service. Port scans in
> particular are often treated as an attack. You are responsible for how you use this tool;
> Ironsight shows this notice once more before your first port scan.

## Screenshots

_Screenshots will follow._

<!-- ![Ironsight main window](docs/screenshot.png) -->
<!-- ![Port scan results in the details panel](docs/screenshot-ports.png) -->

## Features

- **Host discovery** with ARP (local segment), ICMP echo and TCP connect probes. A host counts as
  online if any of them gets an answer. No administrator rights and no Npcap needed.
- **Flexible targets:** single addresses, ranges like `192.168.1.10-50` or
  `192.168.1.1-192.168.2.20`, CIDR blocks from `/16` to `/32`, and comma-separated lists –
  up to 65,536 addresses per scan. Picking a network adapter fills in its subnet.
- **Device information:** hostname from reverse DNS, mDNS and NetBIOS (the source is shown), MAC
  address and vendor (embedded IEEE OUI table, randomized/private MACs are labeled), response
  time, NetBIOS workgroup, open services from a quick check of 9 common ports (FTP, SSH,
  Telnet, HTTP, HTTPS, SMB, RDP, 8080, 8443), and HTTP `Server` header and page title.
- **Port scanning (TCP connect):** optional after host discovery for every device that answered,
  or for a single device ("Scan ports …" in the context menu). Choose *Common* (22 ports),
  *Top 100*, *Top 1000*, *All* (1–65,535) or your own list like `22,80,443,8000-8100`. Every port
  is *open*, *closed* (connection refused) or *filtered* (no answer). Plain sockets only: no
  administrator rights, no raw sockets, no Npcap. Limits for parallel checks (overall and per
  device) and a cap on the number of checks (devices × ports, 1,000,000 by default) – larger
  scans are refused, never silently cut short. Stop works at any time.
- **Service banners:** optionally reads what services send by themselves (SSH, FTP, SMTP, POP3,
  IMAP, VNC, …) and the title of web pages. Nothing is sent to other ports. Banners are treated
  as untrusted: control and invisible characters are removed and the length is limited.
- **Port results everywhere:** an "Open ports" column (sortable, filter with `port:22`), a port
  table with service, state and banner in the details panel, and port results in all exports.
- **Offline devices:** addresses that do not answer still show what is known – reverse DNS names
  (the router often knows them from DHCP), MAC and vendor from the Windows ARP cache, and devices
  seen earlier: in this session, saved between sessions (opt-in) or loaded from a previous JSON
  export ("Load previous scan…"). Every value shows where it came from (live, DNS, ARP cache,
  remembered, imported), and each address is *online*, *offline* (silent, but data exists) or
  *unused*.
- **Live results** in a fast virtual table that stays smooth with 65,536 rows: sortable columns
  (IP addresses sort numerically), text filter, filters for online / offline / unused, "Last
  seen" column, details panel.
- **Actions per host:** copy IP or MAC, open in the browser (HTTP/HTTPS), connect with Remote
  Desktop, show file shares in Explorer, Wake-on-LAN.
- **Export:** CSV (Excel-friendly, `;` or `,` as delimiter), JSON (all data, versioned schema)
  and a printable, self-contained HTML report with a ports section per device – for all scanned
  addresses or just the filtered view. Exports of every earlier version can still be loaded as a
  previous scan.
- **Themes and languages:** five color themes (dark, light, deep blue, terminal green, purple),
  English and German, switchable without a restart.
- **Updates:** the installed version looks for a new release on startup and, after you confirm,
  downloads and installs it (update packages are signed and verified). The portable version
  opens the download page instead.
- **Privacy:** no telemetry. Besides the scan itself, Ironsight only contacts github.com once per
  start to check for a new version (it downloads `latest.json`; you can turn this off in the
  settings). Nothing else is sent. Nothing is written to disk except the settings, unless you ask
  for it: scan results only when you export them, known devices only if you switch on "Remember
  devices between sessions" (off by default; "Forget all known devices" deletes the file).

## Download

Get the files from the [releases page](https://github.com/MarCel06xX/ironsight/releases):

| File | Description |
| --- | --- |
| `Ironsight_<version>_x64-setup.exe` | **Installer.** Installs for the current user (no administrator rights) with a Start menu entry. Downloads the WebView2 runtime if it is missing. |
| `Ironsight_<version>_x64-portable.exe` | **Portable.** A single exe, no installation. Settings are stored in `ironsight-settings.json` and the WebView2 profile in `ironsight-webview\` next to the exe (in AppData if that folder is not writable). Updates are not installed automatically; the update dialog opens the download page. |
| `SHA256SUMS.txt` | SHA-256 checksums of both files. |
| `latest.json`, `*.sig` | Used by the in-app updater. |

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
| Services | TCP connect on 9 common ports, HTTP/1.0 `GET /` | Part of host discovery. Page titles are read on HTTP ports; redirects are only followed on the same host and port. |
| Port scan | TCP connect, passive banner read | Answers from host discovery are reused, so no port is checked twice. On Windows a refused connection is normally retried for about 2 seconds; Ironsight switches these retries off per socket (`SIO_TCP_INITIAL_RTO`), so closed ports are reported at once and the timeout applies exactly. Connections to open ports are reset when closed, which leaves no `TIME_WAIT` entries behind on large scans. |
| Silent addresses | Reverse DNS for every address (automatic up to 1,024 addresses, configurable), `GetIpNetTable2` neighbor cache, known devices | Matched by MAC, or by IP when no MAC is known. If an address answers with a different MAC, the live device wins. |

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

Releases are made with `.\scripts\release.ps1`: it runs the checks, builds the portable exe
(cargo feature `portable`) and the signed installer, writes `SHA256SUMS.txt` and `latest.json`,
and publishes a GitHub release for the version in `src-tauri/tauri.conf.json` (`-NoPublish`
only builds into `release/`). It needs the updater signing key at
`%USERPROFILE%\.tauri\ironsight.key`.

To refresh the vendor table, run `npm run update-oui`. It downloads the IEEE MA-L list and writes
`src-tauri/data/oui.bin`, which is committed to the repository.

### Project layout

```
src/                  Frontend (TypeScript, no framework): table, dialogs, i18n, themes
src/locales/          English and German texts (also used for exports)
src-tauri/src/
  scan/               Target parsing and the scan engine
  ports/              Port scan: port lists and presets, probe, banners, scan engine
  platform/           OS-specific code behind a trait (Windows: IP Helper API)
  enrich/             DNS, mDNS, NetBIOS, vendor lookup, service probes
  export/             CSV, JSON and HTML writers
  commands.rs         Tauri commands; every input is validated here
tools/oui/            Converter for the IEEE vendor list
```

## Roadmap

Ideas for later versions: HTTPS page titles, packet capture and Linux support.

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
> gegen Nutzungsbedingungen verstoßen. Gerade Port-Scans werden oft als Angriff gewertet. Für den
> Einsatz bist du selbst verantwortlich; Ironsight zeigt diesen Hinweis vor dem ersten Port-Scan
> noch einmal an.

### Funktionen

- **Geräteerkennung** über ARP (lokales Segment), ICMP-Echo und TCP-Verbindungstests – ohne
  Administratorrechte und ohne Npcap.
- **Ziele:** einzelne Adressen, Bereiche wie `192.168.1.10-50`, CIDR von `/16` bis `/32` und
  Listen mit Kommas; bis zu 65.536 Adressen pro Scan.
- **Geräteinfos:** Hostname aus DNS, mDNS und NetBIOS (mit Quelle), MAC-Adresse und Hersteller,
  Antwortzeit, Arbeitsgruppe, offene Dienste aus einer Schnellprüfung von 9 häufigen Ports sowie
  Webserver und Seitentitel.
- **Port-Scan (TCP-Connect):** optional nach der Gerätesuche für alle Geräte, die antworten, oder
  für ein einzelnes Gerät („Ports scannen …“ im Kontextmenü). Auswahl *Häufige* (22 Ports),
  *Top 100*, *Top 1000*, *Alle* (1–65.535) oder eine eigene Liste wie `22,80,443,8000-8100`. Jeder
  Port ist *offen*, *geschlossen* (Verbindung abgelehnt) oder *gefiltert* (keine Antwort). Nur
  normale Sockets: keine Administratorrechte, keine Raw Sockets, kein Npcap. Limits für parallele
  Prüfungen (gesamt und pro Gerät) und eine Obergrenze für die Zahl der Prüfungen (Geräte × Ports,
  standardmäßig 1.000.000) – größere Scans werden abgelehnt, nie stillschweigend gekürzt.
- **Dienst-Banner:** liest optional, was Dienste von sich aus senden (SSH, FTP, SMTP, POP3, IMAP,
  VNC, …), und den Titel von Webseiten. An andere Ports wird nichts gesendet. Banner gelten als
  nicht vertrauenswürdig: Steuer- und unsichtbare Zeichen werden entfernt, die Länge begrenzt.
- **Port-Ergebnisse überall:** Spalte „Offene Ports“ (sortierbar, Filter mit `port:22`),
  Port-Tabelle mit Dienst, Zustand und Banner in der Detailansicht und in allen Exporten.
- **Offline-Geräte:** Auch Adressen ohne Antwort zeigen, was bekannt ist: Namen per Reverse-DNS,
  MAC und Hersteller aus dem ARP-Cache sowie früher gesehene Geräte (aus dieser Sitzung, optional
  gespeichert oder aus einem früheren JSON-Export über „Vorherigen Scan laden …“). Zu jedem Wert
  steht die Quelle; jede Adresse ist *online*, *offline* (stumm, aber Daten vorhanden) oder
  *unbelegt*.
- **Live-Ergebnisse** in einer schnellen Tabelle mit Sortierung, Filter, Schaltern für
  online / offline / unbelegt, Spalte „Zuletzt gesehen“ und Detailansicht.
- **Aktionen:** IP/MAC kopieren, im Browser öffnen, Remotedesktop, Freigaben im Explorer,
  Wake-on-LAN.
- **Export** als CSV (für deutsches Excel mit `;`), JSON oder druckbarer HTML-Bericht mit
  Port-Abschnitt pro Gerät. Exporte aller früheren Versionen lassen sich weiterhin als vorheriger
  Scan laden.
- **Fünf Farbdesigns**, Deutsch und Englisch, Umschalten ohne Neustart.
- **Updates:** Die installierte Version sucht beim Start nach einer neuen Version und installiert
  sie nach Bestätigung (signierte Update-Pakete). Die portable Version öffnet die Download-Seite.
- **Datenschutz:** keine Telemetrie. Außer dem Scan kontaktiert Ironsight nur einmal pro Start
  github.com, um nach Updates zu suchen (lädt `latest.json`; in den Einstellungen abschaltbar).
  Sonst wird nichts gesendet. Außer den Einstellungen landet nichts auf der Festplatte, solange du
  es nicht willst: Ergebnisse nur beim Export, bekannte Geräte nur mit „Geräte zwischen Sitzungen
  merken“ (standardmäßig aus; „Alle bekannten Geräte vergessen“ löscht die Datei).

### Download

Auf der [Release-Seite](https://github.com/MarCel06xX/ironsight/releases) gibt es:

- **Installer** (`…_x64-setup.exe`): Installation für den aktuellen Benutzer, ohne
  Administratorrechte. Lädt die WebView2 Runtime nach, falls sie fehlt.
- **Portable** (`…_x64-portable.exe`): eine einzelne exe ohne Installation. Einstellungen liegen in
  `ironsight-settings.json`, das WebView2-Profil in `ironsight-webview\` neben der exe (in AppData,
  falls der Ordner nicht beschreibbar ist).
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
