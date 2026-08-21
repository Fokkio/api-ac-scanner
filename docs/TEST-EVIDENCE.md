# Verified test evidence — V3.1

วันที่ตรวจ: 2026-08-20

| Check | Result |
|---|---:|
| TypeScript typecheck + unit tests + build in final image | PASS, 21/21 |
| Python scanner tests in final image | PASS, 30/30 |
| Docker web + scanner build | PASS |
| Compose config with demo profile | PASS |
| Semgrep validation | PASS, 12 rules |
| Vulnerable / safe fixtures | 12 / 0 findings |
| Code-quality checker | TypeScript A 96.5; Python B 89.4 |

Final cumulative E2E จาก state ว่าง: login PASS, Discovery 2 endpoints, Source 3 findings, Deep 8 findings, Matrix 6 rows, Verified 2, Correlation 1, Mutation POST 201, cleanup DELETE 204 และ secret-persistence PASS

ผลนี้ยืนยัน flow ที่ระบุ ไม่ได้พิสูจน์ coverage ทุก framework/workflow หรือความพร้อม production SaaS

## Incremental verification — 2026-08-21

| Check | Result |
|---|---:|
| TypeScript typecheck + unit tests + build | PASS, 34/34 |
| Python scanner unit tests with pinned runtime dependencies | PASS, 39/39 |
| Guarded workflow localhost HTTP E2E | PASS, 5 matrix rows; POST/PUT/PATCH/GET/DELETE |
| Stop-on-mismatch HTTP E2E | PASS, downstream step marked skipped and was not used as verified evidence |
| Reverse cleanup | PASS, resource returned 404 after both happy and mismatch workflows |
| JSON-login adapter localhost HTTP E2E | PASS, adapter-only identity with empty base headers |
| Ambiguous cleanup regression | PASS, confirmed mutation + cleanup 404 returns needs-verification |
| Aggregate workflow form body regression | PASS, individually valid 32+ KiB form accepted by configured parser limit |
| HTML export escaping + evidence redaction | PASS |
| PDF generation + evidence redaction | PASS |
| EJS template compilation | PASS, 12/12 |
| Production dependency audit | PASS, 0 vulnerabilities |
| Docker Compose config with demo profile | PASS |
| Docker image rebuild | NOT RUN — Docker Desktop daemon was not available |

Python unit tests ใช้ dependency versions ตาม `scanner/requirements.txt` ที่ติดตั้งชั่วคราว ยกเว้น Semgrep/uvicorn extras; HTTP E2E ใช้ Uvicorn 0.30.6 และ local demo fixture โดยไม่มี Docker ผลนี้ยังไม่แทน Docker image build, Semgrep validation หรือ full UI browser E2E รอบใหม่
