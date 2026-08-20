import express, { Request, Response } from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import multer from "multer";
import path from "path";
import fs from "fs";
import os from "os";
import { v4 as uuid } from "./uuid";

import { getAll, getById, save } from "./db";
import { scanSource, scanDomain, fix_for_source } from "./scannerAgent";
import { apply_fix } from "./fixerClient";
import { FixPreview } from "./types";

const app = express();
const PORT = Number(process.env.PORT || 3000);

// Refuse to start without a real session secret. The old fallback
// ("dev-local-only-secret") let anyone forge sessions if the env was missing.
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set (use a long random value in production)");
}

app.set("view engine", "ejs");
app.set("views", path.resolve(__dirname, "..", "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(express.static(path.resolve(__dirname, "..", "public")));

// ---- Upload handling for source scan ----
const UPLOAD_ROOT = process.env.UPLOAD_ROOT || path.resolve(__dirname, "..", "uploads");
if (!fs.existsSync(UPLOAD_ROOT)) fs.mkdirSync(UPLOAD_ROOT, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const id = uuid();
    const dir = path.join(UPLOAD_ROOT, id);
    fs.mkdirSync(dir, { recursive: true });
    (req as any)._uploadDir = dir;
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

// ---- Helper: severity ordering ----
function sevRank(s: string): number {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }[s] ?? 0;
}
function summarize(findings: any[]) {
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

// ---- Routes ----
app.get("/", (req: Request, res: Response) => {
  const scans = getAll().slice(0, 12);
  res.render("index", { scans, summarize });
});

app.get("/scan/source", (req, res) => res.render("source_form", {}));
app.get("/scan/domain", (req, res) => res.render("domain_form", {}));

app.post(
  "/scan/source/run",
  upload.array("sources"),
  async (req: Request, res: Response) => {
    try {
      const dir = (req as any)._uploadDir as string;
      const id = path.basename(dir);
      const rec = await scanSource(id, dir);
      save(rec);
      res.redirect(`/scan/${id}`);
    } catch (e: any) {
      res.status(500).render("error", { message: e.message || "source scan failed" });
    }
  }
);

app.post("/scan/domain/run", async (req: Request, res: Response) => {
  try {
    const { target, authToken, altToken, objectUrls, mode } = req.body as any;
    const id = uuid();
    const rec = await scanDomain(id, target, authToken || "", altToken || "", objectUrls || "", mode || "read-only");
    save(rec);
    res.redirect(`/scan/${id}`);
  } catch (e: any) {
    res.status(500).render("error", { message: e.message || "domain scan failed" });
  }
});

app.get("/scan/:id", (req, res) => {
  const rec = getById(req.params.id);
  if (!rec) return res.status(404).render("error", { message: "scan not found" });
  rec.findings = [...rec.findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  res.render("report", { rec, summarize, sevRank });
});

app.post("/api/fix/preview", async (req, res) => {
  const { scanId, ruleId, file } = req.body as any;
  const preview: FixPreview | { error: string } = await fix_for_source(scanId, ruleId, file);
  res.json(preview);
});

app.post("/api/fix/apply", async (req, res) => {
  const { scanId, ruleId, file } = req.body as any;
  const preview = await fix_for_source(scanId, ruleId, file);
  if ("error" in preview) return res.json(preview);
  const ok = await apply_fix(preview as FixPreview);
  res.json({ ok });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[web] API AC Scanner UI listening on :${PORT}`);
});
