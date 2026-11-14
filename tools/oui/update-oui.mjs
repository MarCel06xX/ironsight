#!/usr/bin/env node
// Downloads the IEEE MA-L (OUI) registry and converts it into the compact binary that the
// backend embeds with `include_bytes!` (src-tauri/data/oui.bin). No dependencies.
//
//   npm run update-oui                    download from IEEE and convert
//   npm run update-oui -- path/to/oui.csv convert a CSV that was downloaded manually
//
// File format (integers little-endian):
//   "IOUI", version u8 (= 1), 3 reserved bytes, record count u32, names length u32
//   records: count x [prefix: 3 bytes, ascending, unique][name offset: u24]
//   names:   [length u8][UTF-8 bytes] ... (each vendor name stored once)
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const OUTPUT = resolve(ROOT, "src-tauri/data/oui.bin");
/** Fewer entries than this means the input is not the real registry (e.g. an error page). */
const MIN_ENTRIES = 20_000;
const MAX_NAME_BYTES = 120;

async function download() {
  const response = await fetch(SOURCE_URL, {
    headers: { "User-Agent": "ironsight-oui-updater" },
    redirect: "follow",
  });
  if (!response.ok) {
    throw new Error(`download failed: HTTP ${response.status} from ${SOURCE_URL}`);
  }
  return response.text();
}

/** RFC 4180 CSV: quoted fields may contain commas, doubled quotes and line breaks. */
function* parseCsv(text) {
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch !== '"') field += ch;
      else if (text[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      yield row;
      row = [];
    } else {
      field += ch;
    }
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    yield row;
  }
}

/** Single-line, trimmed vendor name of at most MAX_NAME_BYTES UTF-8 bytes. */
function cleanName(raw) {
  const collapsed = raw.replace(/[\s\u0000-\u001f\u007f]+/g, " ").trim();
  let name = "";
  let bytes = 0;
  for (const ch of collapsed) {
    bytes += Buffer.byteLength(ch, "utf8");
    if (bytes > MAX_NAME_BYTES) break;
    name += ch;
  }
  return name.trim();
}

function convert(text) {
  const rows = parseCsv(text.replace(/^﻿/, ""));
  const header = rows.next().value ?? [];
  if (header[0] !== "Registry" || header[1] !== "Assignment" || header[2] !== "Organization Name") {
    throw new Error("unexpected CSV header - is this the IEEE MA-L oui.csv?");
  }

  /** prefix (24-bit number) -> vendor name; the first assignment wins on duplicates. */
  const vendors = new Map();
  for (const row of rows) {
    if (row[0] !== "MA-L") continue;
    const assignment = (row[1] ?? "").trim();
    const name = cleanName(row[2] ?? "");
    if (!/^[0-9A-Fa-f]{6}$/.test(assignment) || name === "") continue;
    const prefix = Number.parseInt(assignment, 16);
    if (!vendors.has(prefix)) vendors.set(prefix, name);
  }
  if (vendors.size < MIN_ENTRIES) {
    throw new Error(`only ${vendors.size} entries found, expected at least ${MIN_ENTRIES}`);
  }

  const prefixes = [...vendors.keys()].sort((a, b) => a - b);
  const nameOffsets = new Map();
  const nameChunks = [];
  let namesLength = 0;
  const records = Buffer.alloc(prefixes.length * 6);
  prefixes.forEach((prefix, index) => {
    const name = vendors.get(prefix);
    let offset = nameOffsets.get(name);
    if (offset === undefined) {
      offset = namesLength;
      nameOffsets.set(name, offset);
      const bytes = Buffer.from(name, "utf8");
      nameChunks.push(Buffer.from([bytes.length]), bytes);
      namesLength += 1 + bytes.length;
    }
    records.writeUIntBE(prefix, index * 6, 3);
    records.writeUIntLE(offset, index * 6 + 3, 3);
  });
  if (namesLength > 0xffffff) throw new Error("name table too large for 24-bit offsets");

  const header16 = Buffer.alloc(16);
  header16.write("IOUI", 0, "ascii");
  header16.writeUInt8(1, 4);
  header16.writeUInt32LE(prefixes.length, 8);
  header16.writeUInt32LE(namesLength, 12);
  return {
    data: Buffer.concat([header16, records, ...nameChunks]),
    prefixes: prefixes.length,
    names: nameOffsets.size,
  };
}

const input = process.argv[2];
const text = input ? await readFile(input, "utf8") : await download();
const { data, prefixes, names } = convert(text);
await mkdir(dirname(OUTPUT), { recursive: true });
await writeFile(OUTPUT, data);
// Summary only - never dump registry contents to the console.
console.log(
  `${prefixes} prefixes, ${names} vendor names, ${data.length} bytes -> ${relative(ROOT, OUTPUT)}`,
);
