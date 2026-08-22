# API Access-Control Scanner V3.2

เครื่องมือ local-first สำหรับช่วยตรวจ Authorization / Access Control ของ API ที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบ โดยเน้น BOLA, BFLA, anonymous access, object-property exposure และ resource/account enumeration

V3.2 เพิ่ม Remote Safe Mutation บน Guarded Workflow เดิม โดย remote target ต้องเป็น exact HTTPS origin ที่ผ่าน ownership verification, เปิด feature flag, อยู่ใน allowlist และ re-verify challenge แบบสดก่อน authentication หรือ mutation ทุกครั้ง เครื่องมือนี้ยังเป็น single-node authorized test tool ไม่ใช่ production SaaS

Web UI ไม่มีหน้า login และเชื่อถือผู้ใช้ที่เข้าถึงเครื่อง local โดยตรง จึงต้องรันผ่าน Compose ที่ให้มาและคง port mapping เป็น `127.0.0.1:3000:3000` เท่านั้น Web ปฏิเสธ Host ที่ไม่ใช่ loopback และปฏิเสธ cross-origin mutation ก่อนอ่าน body เพื่อลด CSRF/DNS-rebinding risk ส่วน session ยังถูกใช้สำหรับ CSRF token; `SESSION_SECRET` จึงยังจำเป็น การรัน `npm start` ตรง ๆ bind เฉพาะ `127.0.0.1`; Compose เท่านั้นที่ตั้ง `LISTEN_HOST=0.0.0.0` ภายใน container แล้วจำกัด host-side port ที่ loopback ห้าม publish UI ไปยัง LAN, reverse proxy หรืออินเทอร์เน็ตโดยไม่มี authentication/authorization ชุดใหม่

คู่มือใช้งานภาษาไทยแบบทีละขั้น: [docs/USER-GUIDE-TH.md](docs/USER-GUIDE-TH.md)

Web UI ใช้ภาษาไทยเป็นหลักตั้งแต่ V3.2 โดยคงชื่อมาตรฐาน คำเทคนิค ค่า JSON และ confirmation phrase ภาษาอังกฤษไว้ในวงเล็บหรือรูปแบบเดิม เพื่อให้อ่านเข้าใจง่ายโดยไม่ทำให้ protocol การทดสอบเปลี่ยนความหมาย

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

## วิธีรันบน Windows

ต้องมี Docker Desktop และ Docker Compose V2 จากนั้นดับเบิลคลิก [run.bat](run.bat)

`run.bat` เป็น launcher ขนาดเล็ก ส่วนเมนูทำงานใน `scripts/run.ps1` ซึ่ง PowerShell โหลดเข้า memory ตั้งแต่เริ่ม จึงไม่มี batch label ที่เสียหายเมื่อไฟล์ถูกอัปเดตระหว่างเปิดหน้าต่าง

1. เลือก `2 Build` ได้ทันที ในครั้งแรกระบบจะสร้าง `.env` และสุ่ม secret ให้เอง
2. เลือก `3 Start`
3. เปิด <http://127.0.0.1:3000> แล้วใช้งานได้ทันทีโดยไม่มีหน้า login

เลือก `1 Setup` เมื่อต้องการเปิดดูหรือแก้ `.env` ภายหลัง ถ้ามี placeholder ค้าง ระบบจะเติมเฉพาะค่านั้นและรักษาค่าที่ตั้งไว้แล้วทั้งหมด

หรือใช้ PowerShell:

```powershell
Copy-Item .env.example .env
notepad .env
docker compose up -d --build
```

Web UI เปิดเฉพาะ `127.0.0.1:3000` และ scanner service ไม่ publish port ออกมาที่ host เมื่อเปิด profile `demo` จะมี Order Portal เพิ่มที่ `127.0.0.1:4100`

Compose project name ยังคงเป็น `api-ac-scanner-v31` โดยตั้งใจเพื่อให้ upgrade แทนที่ stack เดิมและไม่ทิ้ง orphan containers; ชื่อนี้ไม่ใช่ product version ที่แสดงใน UI

## ทดลองกับ Demo Lab

Demo Lab เป็น Order Approval Portal แบบ disposable มีหน้าเว็บ, PostgreSQL, ผู้ใช้สาม role และ test resources ใต้ `/__ac_test__/` ใช้ credential ด้านล่างเฉพาะในเครื่องนี้และห้ามนำไปใช้กับระบบจริง

1. ใน `run.bat` เลือก `9 Demo Lab`
2. เปิด portal ที่ `http://127.0.0.1:4100` และ scanner ที่ `http://127.0.0.1:3000`
3. เข้า scanner UI แล้วเพิ่ม asset `http://demo-api:4100` ซึ่งจะ verified อัตโนมัติเพราะอยู่ใน local allowlist
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
LOCAL_ALLOWED_HOSTS=host.docker.internal,localhost,127.0.0.1,::1,demo-api
LOCAL_ALLOWED_PORTS=80,443,3000,4000,4100,5000,8000,8080,8443
REMOTE_SAFE_MUTATION_ENABLED=false
REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS=
```

- API ที่รันบน Windows host ให้ใช้ `http://host.docker.internal:<port>` จาก UI
- Host local ต้องตรงกับ allowlist แบบ exact match; ไม่อนุญาต private IP ทั้ง subnet โดยอัตโนมัติ
- Scanner resolve แล้ว pin IP ไว้ตลอด scan, ไม่ตาม redirect และจำกัด method/count/body/time
- Asset local ที่ allowlist ถูก trusted อัตโนมัติ ส่วน public asset ยังต้องใช้ exact-origin challenge

## ตรวจโค้ดและ test

Web:

```powershell
Set-Location web
npm.cmd ci --ignore-scripts
npm.cmd run check
```

Scanner ใช้ Docker เพื่อให้ dependency ตรงกับ image:

```powershell
docker compose build scanner
docker compose run --rm scanner python -m unittest discover -s tests -v
docker compose run --rm scanner semgrep scan --config semgrep_rules --validate
```

## โครงสร้าง

```text
api-ac-scanner/
├── web/                 Express/TypeScript UI, CSRF session, queue, reports
├── scanner/             FastAPI, bounded HTTP client, Semgrep rules
├── fixtures/            safe/vulnerable source fixtures and local demo API
├── docs/                architecture, security and verified evidence
├── scripts/run.ps1      stable local Docker controller
├── compose.yaml
└── run.bat
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
