# Changelog

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
