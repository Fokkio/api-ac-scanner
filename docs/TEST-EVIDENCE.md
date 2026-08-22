# Verified test evidence — historical V3.1/V3.2 snapshots and current local no-login build

## Current local no-login verification — 2026-08-22

| Check | Result |
|---|---:|
| TypeScript typecheck + unit/integration tests + build | PASS, 55/55 |
| Same checks inside final Web image build | PASS, 55/55 |
| Compose Web + Scanner health | PASS, 2/2 healthy |
| Published ports | PASS, Web only on `127.0.0.1:3000`; Scanner internal `8001/tcp` only |
| Dashboard without login | PASS, HTTP 200 |
| Removed login route | PASS, `/login` HTTP 404 |
| Non-loopback Host / cross-origin mutation / missing CSRF | PASS, HTTP 403 |
| Valid no-login CSRF mutation regression | PASS |
| Multipart pre-write CSRF, partial-upload cleanup and oversized-file handling | PASS |
| Persisted state v1-to-v2 migration without `ownerScope` | PASS |
| Launcher migration of obsolete admin environment variables | PASS |

The local no-login build trusts software and users that can already reach the host loopback interface. This evidence does not authorize LAN or public exposure.

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

Historical V3.1 cumulative E2E ก่อนถอด Scanner login จาก state ว่าง: login PASS, Discovery 2 endpoints, Source 3 findings, Deep 8 findings, Matrix 6 rows, Verified 2, Correlation 1, Mutation POST 201, cleanup DELETE 204 และ secret-persistence PASS

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

## Historical V3.2 Remote Safe Mutation verification before Scanner login removal — 2026-08-22

| Check | Result |
|---|---:|
| TypeScript typecheck + unit/integration tests + build | PASS, 43/43 |
| Same checks inside final Web image build | PASS, 43/43 |
| Python scanner tests inside final Scanner image | PASS, 49/49 |
| Disposable API contract tests | PASS, 9/9 |
| Compose config + Web/Scanner/API/PostgreSQL health | PASS, 4/4 healthy |
| Scanner-to-disposable-API workflow | PASS, POST 201; PUT 200; PATCH 200; GET 200; DELETE 204 |
| Workflow policy expectations | PASS, 5/5 rows matched |
| Workflow reverse cleanup | PASS, `cleanupSucceeded=true`; PostgreSQL resource count 0 |
| Historical Web runtime smoke | PASS, HTTP 200; the then-current V3.2 login rendered |
| Remote default-deny probe against `https://www.f0kki0.me` | PASS, HTTP 400 `Remote safe mutation is disabled` before mutation |
| Remote live success E2E | NOT RUN — target has no deployed V3.2 challenge plus disposable `/__ac_test__/` API in this test |

Remote unit/integration coverage includes disabled flag, exact-origin allowlist, HTTPS/port/path rejection, missing or stale proof, live proof before login/mutation, persisted verification-method propagation and proof serialization across the Web-to-Scanner boundary. These tests demonstrate fail-closed policy behavior; they do not substitute for one authorized remote staging deployment with observable server logs and database cleanup.

## Historical V3.2 Source Scan E2E before Scanner login removal — 2026-08-22

This pre-removal test used the then-current Web and Scanner Docker images, an authenticated Web session, multipart uploads and the real Semgrep executable. Vulnerable and safe fixtures were uploaded as separate scans across JavaScript, Python, Java and PHP.

| Check | Result |
|---|---:|
| Historical authenticated Web login and source upload | PASS before Scanner login removal |
| Semgrep configuration validation | PASS, 12/12 rules |
| Vulnerable fixture scan | PASS, 12 findings |
| Finding distribution | BOLA 4; BFLA 4; property authorization 4 |
| Finding state | 12/12 `needs-verification` |
| Safe fixture scan | PASS, 0 findings |
| Standalone HTML export | PASS, HTTP 200; 8,781 bytes |
| PDF export | PASS, HTTP 200; 5,708 bytes; valid `%PDF-` header |
| Historical anonymous access to administrator report | PASS, HTTP 403 before Scanner login removal |
| Temporary upload cleanup | PASS, 0 new upload directories remained |
| Historical credential/source persistence check | PASS, the former administrator password and tested source snippet were absent from `state.json` |

Evidence scan IDs: vulnerable `8c91d9c43d57a53a9c869ad833d0bfbe24976b1653a2d745`; safe `9a02e344a80be909e22ab754e45a36576f740f73bb52254e`. Static matches remain review guidance and are not automatically confirmed vulnerabilities.
