# Security boundaries

ใช้กับ API ที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบเท่านั้น

## Controls

- direct Web start bind เฉพาะ loopback; Compose ใช้ container bind ทุก interface แต่ publish host เฉพาะ loopback, ปฏิเสธ non-loopback Host และ scanner port ไม่ถูก publish
- UI ไม่มี login และเชื่อถือ local operator; state-changing route ยังคงใช้ session-backed CSRF และ rate limit ตาม route ที่กำหนด
- Secret มาจาก environment; `.env` ไม่ควร commit
- Web และ scanner ตรวจ exact local hostname/port allowlist แยกกัน
- Public target ต้อง resolve เป็น global address และ public asset ต้องผ่าน exact-origin challenge
- Custom resolver pin IP ที่ผ่าน policy, ปิด redirect และไม่ใช้ proxy จาก environment
- การสแกนทั่วไปอนุญาต outbound เฉพาะ `GET`, `HEAD`, `OPTIONS`; state-changing methods เปิดเฉพาะ guarded local mutation/workflow พร้อม limit ด้านจำนวน request, timeout, body, connection และ concurrency
- Upload จำกัด extension/count/size, ใช้ชื่อสุ่ม และลบ temporary directory ทั้ง success/failure
- Container ใช้ non-root, read-only filesystem, dropped capabilities, `no-new-privileges` และ resource limits
- Demo API อยู่ใน optional profile และ publish เฉพาะ `127.0.0.1:4100`

## Workflow and authentication boundary

- workflow ต้องใช้ CSRF token และ exact confirmation phrase; ไม่มี administrator login gate
- target ต้องเป็น exact local host/port allowlist หรือ exact verified-remote HTTPS origin ที่เปิด flag/allowlist และ re-verify สำเร็จ
- resource path ทุกขั้นต้องอยู่ใต้ `/__ac_test__/` โดยไม่มี query หรือ fragment
- จำกัดสูงสุด 8 ขั้นและ 18 outbound requests รวม authentication และ cleanup
- POST/PUT/PATCH body ต้องมี `apiAcScannerTest: true` และไม่เกิน 4096 bytes
- reverse DELETE cleanup ทำใน `finally`; 404 หลัง mutation ที่ยืนยันว่าสำเร็จจะไม่ถูกนับว่าสำเร็จ เว้นแต่มี explicit DELETE สำเร็จก่อนหน้า
- workflow หยุดส่ง step ที่เหลือหลัง mismatch หรือ indeterminate result เพื่อป้องกัน downstream false positive จาก state ที่สร้างไม่สำเร็จ
- remote mode ปิดโดยค่าเริ่มต้นและต้องมี exact HTTPS origin ใน `REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS`
- remote mode ต้องผ่าน file/header ownership re-verification บน pinned client หรือ DNS TXT ของ exact hostname ก่อน authentication หรือ mutation
- local และ remote ใช้ confirmation phrase คนละชุดเพื่อป้องกันเลือก target ผิดโดยไม่ตั้งใจ
- JSON-login adapter แทนที่ base credential headers และไม่ส่ง credential สองชุดพร้อมกัน
- JSON login เป็น bounded same-origin request หนึ่งครั้ง ไม่รองรับ cross-origin token endpoint
- authentication secrets และ acquired token อยู่ใน memory และไม่ลง persisted report
- HTML/PDF exporters ทำ redaction evidence ที่เข้าข่าย credential ซ้ำอีกชั้น

## Local-mode risk

เมื่อ `LOCAL_MODE=true` scanner สามารถติดต่อ non-public IP ได้เฉพาะเมื่อ hostname และ port ตรง allowlist เท่านั้น นี่เป็นความสามารถที่ตั้งใจเพิ่มเพื่อทดสอบ API ในเครื่อง แต่เพิ่มอำนาจ outbound ด้วย

การไม่มี login ปลอดภัยได้เฉพาะในขอบเขต local เท่านั้น Compose ต้องคง `127.0.0.1:3000:3000`; Web ตรวจ loopback Host และ same-origin mutation ก่อนอ่าน request body เพื่อลด DNS rebinding/CSRF ผู้ใช้หรือ process ในเครื่องที่เข้าถึง loopback ได้ถือว่าอยู่ใน trust boundary การ bind เป็น `0.0.0.0`, เปิดผ่าน reverse proxy หรือ expose ด้วย tunnel ต้องเพิ่ม authentication, authorization และ deployment hardening ก่อน

ลดความเสี่ยงโดย:

- ลบ host/port ที่ไม่ได้ใช้จาก `.env`
- ใช้ `demo-api` สำหรับ fixture หรือ `host.docker.internal` สำหรับ service บน Windows
- อย่าเพิ่ม wildcard, CIDR หรือ hostname ที่ผู้โจมตีควบคุม DNS ได้
- ปิด `LOCAL_MODE=false` เมื่อต้องการกลับไปใช้ public-only policy

## Not implemented

- การแก้ code อัตโนมัติ
- arbitrary state-changing exploitation (V3.2 permits only guarded disposable paths with mandatory cleanup and explicit target authorization)
- browser automation/login flow capture, OAuth authorization-code, PKCE, SAML, MFA หรือ CAPTCHA
- SSO, multi-user authorization, distributed database/queue/session
- production audit shipping, egress firewall orchestration หรือ production SaaS hardening
