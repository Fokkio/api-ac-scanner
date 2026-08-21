# Security boundaries

ใช้กับ API ที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบเท่านั้น

## Controls

- UI bind เฉพาะ loopback และ scanner port ไม่ถูก publish
- Admin route ใช้ session, CSRF และ rate limit
- Secret มาจาก environment; `.env` ไม่ควร commit
- Web และ scanner ตรวจ exact local hostname/port allowlist แยกกัน
- Public target ต้อง resolve เป็น global address และ public asset ต้องผ่าน exact-origin challenge
- Custom resolver pin IP ที่ผ่าน policy, ปิด redirect และไม่ใช้ proxy จาก environment
- การสแกนทั่วไปอนุญาต outbound เฉพาะ `GET`, `HEAD`, `OPTIONS`; state-changing methods เปิดเฉพาะ guarded local mutation/workflow พร้อม limit ด้านจำนวน request, timeout, body, connection และ concurrency
- Upload จำกัด extension/count/size, ใช้ชื่อสุ่ม และลบ temporary directory ทั้ง success/failure
- Container ใช้ non-root, read-only filesystem, dropped capabilities, `no-new-privileges` และ resource limits
- Demo API อยู่ใน optional profile และไม่มี host port mapping

## Workflow and authentication boundary

- workflow ต้องใช้ local administrator session, CSRF token และ exact confirmation phrase
- target ต้องผ่าน verification และอยู่ใน exact local host/port allowlist
- resource path ทุกขั้นต้องอยู่ใต้ `/__ac_test__/` โดยไม่มี query หรือ fragment
- จำกัดสูงสุด 8 ขั้นและ 18 outbound requests รวม authentication และ cleanup
- POST/PUT/PATCH body ต้องมี `apiAcScannerTest: true` และไม่เกิน 4096 bytes
- reverse DELETE cleanup ทำใน `finally`; 404 หลัง mutation ที่ยืนยันว่าสำเร็จจะไม่ถูกนับว่าสำเร็จ เว้นแต่มี explicit DELETE สำเร็จก่อนหน้า
- workflow หยุดส่ง step ที่เหลือหลัง mismatch หรือ indeterminate result เพื่อป้องกัน downstream false positive จาก state ที่สร้างไม่สำเร็จ
- JSON-login adapter แทนที่ base credential headers และไม่ส่ง credential สองชุดพร้อมกัน
- JSON login เป็น bounded same-origin request หนึ่งครั้ง ไม่รองรับ cross-origin token endpoint
- authentication secrets และ acquired token อยู่ใน memory และไม่ลง persisted report
- HTML/PDF exporters ทำ redaction evidence ที่เข้าข่าย credential ซ้ำอีกชั้น

## Local-mode risk

เมื่อ `LOCAL_MODE=true` scanner สามารถติดต่อ non-public IP ได้เฉพาะเมื่อ hostname และ port ตรง allowlist เท่านั้น นี่เป็นความสามารถที่ตั้งใจเพิ่มเพื่อทดสอบ API ในเครื่อง แต่เพิ่มอำนาจ outbound ด้วย

ลดความเสี่ยงโดย:

- ลบ host/port ที่ไม่ได้ใช้จาก `.env`
- ใช้ `demo-api` สำหรับ fixture หรือ `host.docker.internal` สำหรับ service บน Windows
- อย่าเพิ่ม wildcard, CIDR หรือ hostname ที่ผู้โจมตีควบคุม DNS ได้
- ปิด `LOCAL_MODE=false` เมื่อต้องการกลับไปใช้ public-only policy

## Not implemented

- การแก้ code อัตโนมัติ
- arbitrary state-changing exploitation (V3.1 permits only guarded local test paths with mandatory cleanup)
- browser automation/login flow capture, OAuth authorization-code, PKCE, SAML, MFA หรือ CAPTCHA
- SSO, multi-tenant admins, distributed database/queue/session
- production audit shipping, egress firewall orchestration หรือ production SaaS hardening
