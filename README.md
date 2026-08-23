# API Access-Control Scanner V3.2

[![CI](https://github.com/Fokkio/api-ac-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Fokkio/api-ac-scanner/actions/workflows/ci.yml)

เครื่องมือ local-first สำหรับช่วยตรวจ Authorization / Access Control ของ API ที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบ โดยเน้น BOLA, BFLA, anonymous access, object-property exposure และ resource/account enumeration

V3.2 เพิ่ม Remote Safe Mutation บน Guarded Workflow เดิม โดย remote target ต้องเป็น exact HTTPS origin ที่ผ่าน ownership verification, เปิด feature flag, อยู่ใน allowlist และ re-verify challenge แบบสดก่อน authentication หรือ mutation ทุกครั้ง เครื่องมือนี้ยังเป็น single-node authorized test tool ไม่ใช่ production SaaS

Web UI ไม่มีหน้า login และเชื่อถือผู้ใช้ที่เข้าถึงเครื่อง local โดยตรง จึงต้องรันผ่าน Compose ที่ให้มาและคง port mapping เป็น `127.0.0.1:3000:3000` เท่านั้น Web ปฏิเสธ Host ที่ไม่ใช่ loopback ส่วน state-changing route และ upload ยังคงบังคับ session-backed CSRF token พร้อม cookie แบบ `SameSite=Strict`; `SESSION_SECRET` จึงยังจำเป็น ตัว Web ไม่บล็อกคำขอด้วย `Origin` หรือ `Sec-Fetch-Site` แล้ว การรัน `npm start` ตรง ๆ bind เฉพาะ `127.0.0.1`; Compose เท่านั้นที่ตั้ง `LISTEN_HOST=0.0.0.0` ภายใน container แล้วจำกัด host-side port ที่ loopback ห้าม publish UI ไปยัง LAN, reverse proxy หรืออินเทอร์เน็ตโดยไม่มี authentication/authorization ชุดใหม่

คู่มือใช้งานภาษาไทยแบบทีละขั้น: [docs/USER-GUIDE-TH.md](docs/USER-GUIDE-TH.md)

Web UI ใช้ภาษาไทยเป็นหลักตั้งแต่ V3.2 โดยคงชื่อมาตรฐาน คำเทคนิค ค่า JSON และ confirmation phrase ภาษาอังกฤษไว้ในวงเล็บหรือรูปแบบเดิม เพื่อให้อ่านเข้าใจง่ายโดยไม่ทำให้ protocol การทดสอบเปลี่ยนความหมาย

## สถานะที่ยืนยันกับ build ปัจจุบัน

ผลด้านล่างมาจาก clean clone และ Docker Compose runtime test เมื่อ 2026-08-23 ไม่ใช่การรับรองว่า API เป้าหมายทุกระบบจะสแกนได้ครบหรือปราศจากช่องโหว่:

| รายการ | ผลที่ยืนยันแล้ว |
| --- | --- |
| Web typecheck, unit tests และ production build | PASS, 56/56 tests |
| Scanner unit tests | PASS, 69/69 tests |
| Semgrep configuration | PASS, 12 rules valid |
| Compose runtime | PASS, 4/4 services healthy |
| Web / Demo Portal / removed login route | HTTP 200 / HTTP 200 / HTTP 404 |
| Demo API contract | PASS, 9/9 tests |
| Runtime flows บน Demo Lab | Quick, BOLA, BFLA, Mutation และ Workflow ทำงานครบ |
| Source fixtures | vulnerable 12 findings, safe 0 findings |

Remote Safe Mutation ผ่าน unit/integration guard checks แต่ยังไม่ได้ยืนยัน success path กับ external HTTPS staging target จริง เพราะต้องมี target ที่วาง ownership challenge และ disposable `/__ac_test__/` API โดยเจ้าของระบบก่อน

## สิ่งที่ตรวจได้

- Quick scan: ตรวจการตอบสนองแบบไม่ส่ง token, route ลักษณะ object/admin, `OPTIONS` และ security headers เบื้องต้น
- Authorized scan: เปรียบเทียบ owner/privileged, alternate/lower-role และ anonymous บน path ที่ผู้ใช้กำหนด
- Enumeration: เปรียบเทียบ path ที่ทราบว่ามีจริงกับ path ที่ไม่มีจริงโดยดู status, ขนาด response และเวลาหนึ่งตัวอย่าง
- Source scan: ใช้ Semgrep หา pattern เสี่ยงด้าน BOLA/BFLA/property authorization ใน JavaScript, TypeScript, Python, Java และ PHP
- Target verification: รองรับไฟล์ `/.well-known/`, HTTP response header และ DNS TXT โดยผูกกับ exact origin
- API Discovery: import OpenAPI/Swagger, HAR, Postman และ route declarations จาก source ที่รองรับ แล้วสร้าง Endpoint Inventory
- Identity Profiles: กำหนด label, role, tenant และ credential แบบ Bearer, Cookie, API key หรือ custom headers JSON สำหรับ baseline/alternate identity
- Authorization Matrix: แสดง Expected/Actual ของ baseline, alternate และ anonymous ต่อ endpoint
- Correlation: จับคู่ static finding กับ runtime finding เมื่อ category และ normalized route template ตรงกัน แล้วเพิ่ม confidence โดยยังคงสถานะ `suspected`
- Verification Engine: ออกสถานะ `verified` เฉพาะ allow/deny ที่ขัดกับ explicit policy rule และ response ไม่ใช่สถานะคลุมเครือ
- Safe Mutation: POST resource ที่มี `apiAcScannerTest: true` ใต้ `/__ac_test__/` แล้ว DELETE path เดิมทันที สำหรับ verified local asset หรือ verified-remote exact origin ที่เปิดใช้อย่างชัดเจน
- Guarded Workflow: รัน GET/POST/PUT/PATCH/DELETE ตามลำดับได้สูงสุด 8 ขั้น เฉพาะ path ใต้ `/__ac_test__/` พร้อม expected allow/deny ต่อขั้น หยุด step ที่เหลือเมื่อผลก่อนหน้าไม่น่าเชื่อถือ และ reverse cleanup ใน `finally`
- Remote ownership re-check: verified-remote mutation ใช้ HTTPS port 443 เท่านั้น ตรวจ file/header challenge ซ้ำผ่าน pinned client หรือ DNS TXT บน exact hostname ก่อนส่ง credential หรือ state-changing request
- Authentication adapters: รองรับ Bearer, HTTP Basic, Cookie, API key, custom headers และ JSON login แบบ same-origin โดย token ที่ได้จาก adapter จะแทนที่ base credential ทั้งหมด
- Report export: ดาวน์โหลดรายงาน self-contained HTML และ PDF โดย redaction evidence ที่มีชื่อหรือค่าเข้าข่าย credential ซ้ำอีกชั้น
- Report states: `detected`, `suspected`, `needs-verification`, `verified`, `passed`, `not-tested`, `error`

คำว่า `suspected` ไม่ใช่การยืนยันช่องโหว่ ต้องเทียบ ownership, tenant และ role policy ของระบบจริงก่อนรายงาน

Deep Scan ของ V3.2 ต้องใส่ policy JSON ให้ครบ baseline, alternate และ `Anonymous` สำหรับทุก object/function path หากขาดหรือซ้ำ scanner จะปฏิเสธก่อนยิง request

Mutation Scan แบบ local ต้องพิมพ์ `MUTATE TEST RESOURCE`; แบบ verified remote ต้องพิมพ์ `MUTATE VERIFIED REMOTE TEST RESOURCE` ทุก path ต้องขึ้นต้นด้วย `/__ac_test__/` หลัง create สำเร็จ cleanup ต้องคืน 200/202/204; ค่า 404 ยอมรับได้เฉพาะเมื่อ create ไม่สำเร็จหรือผลไม่ทราบแน่ชัด

Workflow Scan แบบ local ต้องพิมพ์ `RUN DISPOSABLE WORKFLOW`; แบบ verified remote ต้องพิมพ์ `RUN VERIFIED REMOTE DISPOSABLE WORKFLOW` ระบบจำกัด 8 ขั้น, request body 4 KiB ต่อขั้น และยิง cleanup แบบ DELETE ย้อนลำดับให้ทุก path ที่ถูก POST/PUT/PATCH แม้ขั้นกลางล้มเหลว เมื่อ step ใด mismatch หรือ indeterminate ระบบจะไม่ยิง step ถัดไปและบันทึกเป็น `skipped`

## Remote Safe Mutation (ปิดไว้โดยค่าเริ่มต้น)

ใช้กับ staging/test API ที่มีฐานข้อมูลและบัญชีทดสอบแยกจาก production เท่านั้น:

```dotenv
REMOTE_SAFE_MUTATION_ENABLED=true
REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS=https://staging-api.example.com
```

ข้อบังคับทั้งหมดต้องผ่านพร้อมกัน:

- exact origin ต้องใช้ HTTPS port 443 และไม่มี path/query/credential
- asset ต้องผ่าน file, header หรือ DNS ownership verification; asset เก่าที่ไม่มี verification method ต้อง re-verify
- challenge ต้องยังตอบตรงค่าที่บันทึกไว้ในขณะเริ่มแต่ละ job
- ทุก request ต้องเป็น same-origin และอยู่ใต้ `/__ac_test__/`
- POST/PUT/PATCH body ต้องมี `apiAcScannerTest: true`; cleanup failure จะเป็น `needs-verification`
- allowlist ถูกตรวจซ้ำทั้ง Web และ Scanner; การเปิด flag อย่างเดียวไม่พอ

JSON-login adapter รับเฉพาะ same-origin relative path และ response token แบบ dotted JSON path เช่น `tokens.access` สามารถเลือก `Authentication adapter only` โดยไม่ต้องใส่ base credential ข้อมูล username/password/token อยู่ใน memory ของ queued job เท่านั้น ไม่บันทึกลง state, finding, HTML หรือ PDF

## Guarded Workflow

เข้าเมนู `Workflow` แล้วเลือก eligible local หรือ verified-remote asset จากนั้นกำหนด identity, authentication adapter และ steps JSON ตัวอย่าง:

```json
[
  {"name":"create","method":"POST","path":"/__ac_test__/workflow-resource","body":{"apiAcScannerTest":true,"value":"created"},"expected":"allow"},
  {"name":"replace","method":"PUT","path":"/__ac_test__/workflow-resource","body":{"apiAcScannerTest":true,"value":"replaced"},"expected":"allow"},
  {"name":"patch","method":"PATCH","path":"/__ac_test__/workflow-resource","body":{"apiAcScannerTest":true,"patched":true},"expected":"allow"},
  {"name":"read","method":"GET","path":"/__ac_test__/workflow-resource","expected":"allow"},
  {"name":"delete","method":"DELETE","path":"/__ac_test__/workflow-resource","expected":"allow"}
]
```

ผล allow/deny ที่ขัดกับค่า `expected` และไม่ใช่ response คลุมเครือจะเป็น `verified` ต่อ policy declaration ที่ผู้ใช้ให้มา ไม่ใช่หลักฐานว่าประกาศ business policy ถูกต้อง

เมื่อ report จบหรือ error สามารถดาวน์โหลด `.html` และ `.pdf` จากหน้า report ได้ HTML รองรับ Unicode ผ่าน browser ส่วน PDF ใช้ฟอนต์มาตรฐานและแทนอักขระที่ฟอนต์ไม่รองรับด้วย `?`

## เริ่มใช้งานบน Windows

สิ่งที่ต้องมีสำหรับการใช้งานปกติ:

- Windows 10/11
- Docker Desktop ที่เปิดใช้งานอยู่
- Docker Compose V2 ซึ่งมากับ Docker Desktop รุ่นปัจจุบัน
- Git สำหรับ clone repository

Node.js ไม่จำเป็นสำหรับ Quick Start แต่ต้องมี Node.js 20 พร้อม npm เมื่อต้องการรัน `SelfTest` หรือ Web tests บน host

วิธีเร็วที่สุดจาก PowerShell:

```powershell
git clone https://github.com/Fokkio/api-ac-scanner.git
Set-Location api-ac-scanner
.\run.bat QuickStart
```

Quick Start จะสร้างหรือซ่อม `.env`, สุ่ม `SESSION_SECRET` และ `SCANNER_INTERNAL_TOKEN`, build images, รอ Web/Scanner healthy แล้วเปิด <http://127.0.0.1:3000> ให้อัตโนมัติ ระบบไม่มีหน้า login และต้องเปิดผ่าน loopback address นี้เท่านั้น

เมื่อต้องการหยุดและลบ containers โดยเก็บข้อมูลรายงานไว้:

```powershell
.\run.bat Stop
```

สามารถดับเบิลคลิก [run.bat](run.bat) เพื่อใช้เมนูได้เช่นกัน:

| ปุ่ม | การทำงาน |
| --- | --- |
| `1 Setup` | สร้าง/ซ่อม `.env` แล้วเปิดใน Notepad |
| `2 Quick Start` | build, start, รอ health และเปิด Web UI |
| `3 Start` | start จาก images ที่มีอยู่และรอ health |
| `4 Rebuild` | build ใหม่และ recreate services |
| `5 Stop` | หยุดและลบ containers ของทั้ง normal/demo profile |
| `6 Status` | แสดงสถานะและ health ของ containers |
| `7 Logs` | แสดง log ล่าสุดของ services |
| `8 Open` | เปิด Web UI |
| `9 Demo Lab` | เปิด Scanner, Order Portal และ PostgreSQL fixture |

`run.bat` เป็น launcher ขนาดเล็ก ส่วนเมนูทำงานใน `scripts/run.ps1` ซึ่ง PowerShell โหลดเข้า memory ตั้งแต่เริ่ม จึงไม่มี batch label ที่เสียหายเมื่อไฟล์ถูกอัปเดตระหว่างเปิดหน้าต่าง

หรือใช้ PowerShell:

```powershell
.\run.bat GenerateEnv
docker compose up -d --build --wait --wait-timeout 180
```

ตรวจ runtime แบบเต็มได้ด้วย `.\run.bat SelfTest`; คำสั่งนี้ build Demo profile, รอ 4 services healthy, ตรวจ HTTP/port binding, รัน Demo API contract tests แล้วสั่งปิดและลบ stack ให้อัตโนมัติ คำสั่งนี้ต้องใช้ Node.js/npm บน host สำหรับ contract tests และไม่ควรรันระหว่างที่ต้องการเปิด stack เดิมค้างไว้

Web UI เปิดเฉพาะ `127.0.0.1:3000` และ scanner service ไม่ publish port ออกมาที่ host เมื่อเปิด profile `demo` จะมี Order Portal เพิ่มที่ `127.0.0.1:4100`

Compose project name คือ `api-ac-scanner-v32` เพื่อให้ container/network ของรุ่นนี้มีชื่อคงที่และ cleanup ได้ครบ; ชื่อนี้ตรงกับ product version ที่แสดงใน UI

## ทดลองกับ Demo Lab

Demo Lab เป็น Order Approval Portal แบบ disposable มีหน้าเว็บ, PostgreSQL, ผู้ใช้สาม role และ test resources ใต้ `/__ac_test__/` ใช้ credential ด้านล่างเฉพาะในเครื่องนี้และห้ามนำไปใช้กับระบบจริง

1. รัน `.\run.bat Demo` หรือเปิดเมนูแล้วเลือก `9 Demo Lab`
2. เปิด portal ที่ `http://127.0.0.1:4100` และ scanner ที่ `http://127.0.0.1:3000`
3. เข้า scanner UI แล้วกด `เพิ่ม Demo API อัตโนมัติ` หรือเพิ่ม asset `http://host.docker.internal:4100` ซึ่งจะ verified อัตโนมัติเพราะอยู่ใน local allowlist
4. ใช้บัญชี fixture:

```text
Alice:  alice / alice-password / owner / tenant-a
Bob:    bob / bob-password / viewer / tenant-a
Admin:  admin / admin-password / admin / global

Alice bearer:  alice-bearer-token-1234567890
Bob bearer:    bob-bearer-token-1234567890
Admin bearer:  admin-bearer-token-1234567890
Alice API key: alice-api-key-1234567890 (header x-api-key)
Alice cookie:  portal_session=alice-session-token-1234567890
Alice custom:  {"x-demo-user":"alice","x-demo-secret":"alice-custom-secret-1234567890"}
```

5. Deep Scan สำหรับ BOLA ใช้ `/api/orders/1` และ `/api/owner/summary` กับ Alice/Bob: Alice ต้องได้ `200`, Bob `403`, Anonymous `401`
6. Deep Scan สำหรับ BFLA ใช้ `/api/orders/3` และ `/api/admin/reports` กับ Admin/Alice: Admin ต้องได้ `200`, Alice `403`, Anonymous `401`
7. Mutation ใช้ `/__ac_test__/v3-safe-resource`, body `{"apiAcScannerTest":true}`, Bearer ของ Alice และคำยืนยัน `MUTATE TEST RESOURCE`
8. Workflow ใช้ POST/PUT/PATCH/GET/DELETE ใต้ `/__ac_test__/` และคำยืนยัน `RUN DISPOSABLE WORKFLOW` สามารถเลือก Bearer, Basic (`alice:alice-password`), Cookie, API key, Custom headers หรือ JSON login adapter ที่ path `/__ac_test__/login` และ token path `tokens.access`

หลัง workflow สำเร็จ ตาราง `workflow_resources` ต้องกลับมาเหลือศูนย์แถว เพราะ fixture และ scanner ต่างตรวจ cleanup

## API Discovery

เข้าเมนู `Discovery` เลือก verified asset แล้วอัปโหลดได้สูงสุด 25 ไฟล์ ไฟล์ละไม่เกิน 1 MiB:

- OpenAPI/Swagger: `.json`, `.yaml`, `.yml`
- HAR: `.har` โดยเก็บเฉพาะ request ที่ exact origin ตรงกับ asset
- Postman collection: URL แบบ `{{baseUrl}}/...` หรือ absolute URL ที่ exact origin ตรงกับ asset
- Source route declarations: Express-style JavaScript/TypeScript, FastAPI-style Python, Spring mapping และ Laravel routes

ระบบจัดประเภท candidate เป็น `object`, `function`, `enumeration` หรือ `other` และส่งเฉพาะ concrete `GET` paths ไป prefill Deep Scan เพื่อป้องกันการยิง `{id}` หรือ `:id` แบบเดาสุ่ม

## Local target policy

ค่าปริยายใน `.env.example`:

```text
LOCAL_MODE=true
LOCAL_ALLOWED_HOSTS=host.docker.internal,localhost,127.0.0.1,::1
LOCAL_ALLOWED_PORTS=80,443,3000,4000,4100,5000,8000,8080,8443
REMOTE_SAFE_MUTATION_ENABLED=false
REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS=
```

- API ที่รันบน Windows host ให้ใช้ `http://host.docker.internal:<port>` จาก UI
- Host local ต้องตรงกับ allowlist แบบ exact match; ไม่อนุญาต private IP ทั้ง subnet โดยอัตโนมัติ
- Scanner resolve แล้ว pin IP ไว้ตลอด scan, ไม่ตาม redirect และจำกัด method/count/body/time
- Asset local ที่ allowlist ถูก trusted อัตโนมัติ ส่วน public asset ยังต้องใช้ exact-origin challenge

## ตรวจโค้ดและ test

Launcher regression บน Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run.tests.ps1
```

Web:

```powershell
Set-Location web
npm.cmd ci
npm.cmd run check
Set-Location ..
```

Scanner ใช้ Docker เพื่อให้ dependency ตรงกับ image:

```powershell
docker compose build scanner
docker compose run --rm scanner python -m unittest discover -s tests -v
docker compose run --rm scanner semgrep scan --config semgrep_rules --validate
```

Compose end-to-end smoke test ซึ่งใช้ชุดเดียวกับ CI:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run.compose-smoke.ps1
```

Smoke test จะสร้าง `.env` ที่จำเป็น, build/start Demo profile, ตรวจ 4 services, loopback port binding, HTTP runtime และ contract tests แล้วสั่ง `docker compose down` เสมอ หากต้องการเก็บ containers ไว้ตรวจต่อให้เพิ่ม `-KeepRunning`

GitHub Actions รัน 4 jobs บนทุก push/pull request เข้า `main`: Web บน Node.js 20, launcher บน Windows, Scanner บน Python 3.11 และ Docker Compose runtime smoke บน Ubuntu

## โครงสร้าง

```text
api-ac-scanner/
├── web/                         Express/TypeScript UI, CSRF session, queue, reports
├── scanner/                     FastAPI, bounded HTTP client, Semgrep rules
├── fixtures/                    safe/vulnerable source fixtures and Demo Lab
├── docs/                        architecture, security, guide and test evidence
├── scripts/run.ps1              launcher entrypoint and menu
├── scripts/run.actions.ps1      QuickStart/Demo/Stop/SelfTest actions
├── scripts/run.environment.ps1  safe .env creation and migration
├── scripts/run.tests.ps1        Windows launcher regression
├── scripts/run.compose-smoke.ps1 Compose end-to-end runtime check
├── .github/workflows/ci.yml     Web/Scanner/Windows/Compose CI
├── compose.yaml                 loopback-only local stack and demo profile
└── run.bat                      Windows entrypoint
```

## ข้อจำกัดที่ต้องรู้ตามตรง

- Scanner ไม่มี login: ผู้ใช้หรือโปรแกรมใดก็ตามที่เข้าถึง `127.0.0.1:3000` ภายใต้บัญชีเครื่องนี้สามารถดูรายงานและสั่ง scan ได้ จึงห้ามเปลี่ยน Docker port binding เป็นทุก interface
- Deep scan matrix เดิมยังใช้เฉพาะ `GET`; write/delete authorization อยู่ใน Guarded Workflow ซึ่งจำกัดเฉพาะ disposable namespace และ explicit target authorization
- Identity Profile รองรับการส่ง credential ที่มีอยู่แล้ว แต่ยังไม่ทำ browser login/refresh token/SSO flow ให้อัตโนมัติ
- Label/role/tenant เป็นบริบทที่ผู้ใช้กรอก ไม่ใช่ข้อพิสูจน์ policy; ผู้ใช้ยังต้องเลือก object/path และบัญชีทดสอบให้ถูก
- Secret headers อยู่เฉพาะใน queued job และ scanner request; ไม่บันทึกลง report/state แต่เครื่อง local ที่รัน Docker ยังเป็น trust boundary
- Response ที่เหมือนกันอาจเป็น shared/public object จึงไม่ใช่หลักฐานยืนยัน BOLA โดยลำพัง
- Enumeration timing มีเพียงหนึ่ง sample ต่อ path ใช้เป็นเบาะแส ไม่ใช่ข้อสรุปทางสถิติ
- Source rules เป็น heuristic อาจมีทั้ง false positive และ false negative
- Discovery ไม่ crawl หรือ brute-force endpoint; รูปแบบ source ที่สร้าง route แบบ dynamic, router prefix และ framework ที่ไม่รองรับอาจหาไม่เจอ
- HAR/Postman ที่ใช้ environment variables นอกเหนือจาก `{{baseUrl}}` อาจต้อง export URL ให้ชัดเจนก่อน import
- Endpoint classification เป็น heuristic และไม่รู้ ownership/role policy จนกว่าจะมี test identity กับ expected policy ที่ถูกต้อง
- V3.2 correlation เป็น exact category + route-template match; code ที่ประกอบ route แบบ dynamic หรือแยก router prefix อาจไม่ถูกจับคู่
- Confidence ที่สูงขึ้นจาก correlation ไม่เท่ากับ confirmed vulnerability เพราะ expected business policy ยังไม่ได้ถูกประกาศแบบ machine-readable
- สถานะ `verified` ยืนยันว่า response ขัดกับ policy ที่ผู้ใช้ส่งมา ไม่ได้พิสูจน์ว่าผู้ใช้กรอก policy ทางธุรกิจถูกต้อง จึงต้อง review policy declaration ก่อนรายงานภายนอก
- Guarded Workflow ไม่เปิดให้ยิง arbitrary production path และไม่รับประกัน rollback ของ side effect ที่อยู่นอก resource path หรือทำงาน asynchronous ค่า cleanup 404 หลัง mutation ที่ยืนยันว่าสำเร็จจะถูกจัดเป็น `needs-verification` เว้นแต่มี explicit DELETE สำเร็จก่อนหน้า
- Remote Safe Mutation พิสูจน์การควบคุม exact origin ไม่ได้พิสูจน์ว่า database เป็น test database ผู้ดูแลต้องแยกข้อมูลและตรวจ cleanup เอง
- JSON-login adapter รองรับ JSON token response แบบหนึ่งขั้น ยังไม่รองรับ OAuth authorization-code, PKCE, SAML, MFA, CAPTCHA, browser automation หรือ refresh-token rotation
- PDF ใช้ built-in PDF font จึงเหมาะกับข้อมูล ASCII/Latin; ใช้ HTML export เมื่อต้องรักษาอักขระไทยหรือ Unicode ทั้งหมด
- Property check ดูชื่อ field ระดับบนสุดของ JSON เท่านั้น ไม่ได้วิเคราะห์ nested schema
- Local allowlist ช่วยให้สแกนระบบในเครื่องได้ แต่ก็ให้อำนาจ scanner ติดต่อ service ที่ระบุไว้ จึงควรใส่เฉพาะ host/port ที่ตั้งใจทดสอบ
- Queue, session และ JSON state ใช้ได้กับ process/เครื่องเดียว ไม่รองรับ horizontal scaling
- การไม่พบ finding ไม่ได้พิสูจน์ว่า API ปลอดช่องโหว่ทุกประเภท

อ่านเพิ่มที่ [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md) และ [docs/TEST-EVIDENCE.md](docs/TEST-EVIDENCE.md)
