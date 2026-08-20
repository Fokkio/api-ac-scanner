import fs from "fs";
import path from "path";
import { ScanRecord } from "./types";

const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "..", "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ scans: [] }, null, 2));
}

export function getAll(): ScanRecord[] {
  ensure();
  const raw = JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
  return raw.scans as ScanRecord[];
}

export function getById(id: string): ScanRecord | undefined {
  return getAll().find((s) => s.id === id);
}

export function save(rec: ScanRecord) {
  ensure();
  const all = getAll();
  const idx = all.findIndex((s) => s.id === rec.id);
  if (idx >= 0) all[idx] = rec;
  else all.unshift(rec);
  fs.writeFileSync(DB_FILE, JSON.stringify({ scans: all }, null, 2));
}
