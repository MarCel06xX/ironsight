# Changelog

## 0.4.0 – 2026-11-18

- Port scanning (TCP connect, no administrator rights, no Npcap): optionally after host discovery
  for every device that answered, or for a single device with "Scan ports …" in the context
  menu. Port lists: Common (22 ports), Top 100, Top 1000, All (1–65,535) or a custom list like
  `22,80,443,8000-8100`, checked as you type. Every port is open, closed or filtered.
- Settings for the port scan: timeout, parallel checks and a limit for the number of checks
  (devices × ports, 1,000,000 by default) – larger scans are refused instead of cut short.
  Stop ends a port scan at once.
- Service banners (on by default): reads what services such as SSH, FTP, SMTP or VNC send by
  themselves, and web page titles on more HTTP ports. Banners are cleaned and length-limited.
- "Open ports" column (sortable), filter `port:22`, a port table with service, state and banner
  in the details panel, and progress for port scans.
- A one-time notice before the first port scan: only scan networks you own or may scan.
- Host discovery now tells closed ports apart from silent ones (Windows normally retries a
  refused connection for about two seconds), and the port scan reuses these answers instead of
  checking those ports again.
- Exports include the port results: CSV columns for the port scan, closed and filtered ports and
  banners, JSON `schema_version` 3, and a ports section per device in the HTML report. Exports
  of all earlier versions can still be loaded as a previous scan.

## 0.2.0 – 2026-11-15

- Data for devices that do not answer: reverse DNS for all addresses (automatic up to 1,024,
  configurable), MAC and vendor from the Windows ARP cache, and known devices.
- Known devices: remembered for the session; optionally saved between sessions (off by default,
  "Forget all known devices"); "Load previous scan…" imports a JSON export as a baseline.
- Three states – online, offline, unused – with filters, a "Last seen" column and the source of
  every value (live, DNS, ARP cache, remembered, imported).
- Wake-on-LAN for offline devices with a known MAC address.
- Exports contain status, last seen and data sources; JSON `schema_version` 2 (version 1 can
  still be imported).

## 0.1.3 – 2026-11-15

- Test release for the in-app updater. No functional changes.

## 0.1.2 – 2026-11-15

- Update check on startup with an in-app update dialog (English/German): release notes,
  download progress, "Later" and "Skip this version". Signed update packages.
- Settings: "Check for updates on startup", "Check now" and the installed version.
- Portable version is now a single exe; settings are stored in `ironsight-settings.json` next to it.

## 0.1.1 – 2026-11-15

- Portable zip and `SHA256SUMS.txt` in the releases; release script.

## 0.1.0 – 2026-11-14

- First release: host discovery, device information, export (CSV, JSON, HTML), themes, English/German.
