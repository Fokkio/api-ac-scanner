# Code review summary

Review scope: TypeScript web/orchestrator, Python scanner, local target policy, Docker packaging, Semgrep rules and intentionally vulnerable demo fixture

## Fixed findings

- แยก `scanner/app/engines.py` เดิม 468 บรรทัดออกเป็น quick engine, deep orchestration และ pure authorization classifiers
- เปลี่ยน deep scan จากพารามิเตอร์ยาวเป็น `DeepScanPlan`
- รองรับ local host/port เฉพาะ exact allowlist พร้อม independent validation และ DNS pin ใน scanner
- แก้ IPv6 hostname normalization ให้ `[::1]` ตรงกับ allowlist `::1`
- ปฏิเสธ fragment/control characters ใน endpoint path ทั้ง web และ scanner เพื่อไม่ให้ report location ต่างจาก request จริง
- เพิ่ม fail-closed parsing เมื่อ Semgrep คืน result metadata ผิด schema
- เพิ่ม test สำหรับ local auto-verification, local policy, BOLA/BFLA/property/enumeration, malformed analyzer output และ path ambiguity
- แยก administrator routes ตาม asset/deep/source responsibility
- แก้ Docker packaging ให้คำสั่ง scanner test ใน README ใช้งานได้จริง

## Reviewer output

- Current automated quality result: Python B (89.4 average), TypeScript A (96.5 average); grades are not proof of correctness
- ไม่พบ hard-coded production secret, token persistence, redirect following, unbounded queue หรือ unbounded response body

คะแนน A ไม่ได้หมายความว่าไม่มี code smell เหลืออยู่ Analyzer ยังรายงานเรื่อง magic numbers และ complexity บางฟังก์ชันระดับ low/medium โดยเฉพาะ policy/classification แต่ไม่พบ blocker จากรายการเหล่านั้นในการทดสอบรอบนี้

## Verdict

`ship for local MVP` — ใช้งาน local lab ได้ตามขอบเขตและมี runtime evidence แต่ห้ามนำคำว่า suspected ไปใช้เป็น confirmed vulnerability โดยไม่มี business/ownership proof

## V3.2 review addendum — 2026-08-22

Scope: Remote Safe Mutation policy, persisted ownership method, Web-to-Scanner proof transport, live Scanner re-verification, guarded mutation/workflow engines, UI labels, environment configuration and Docker upgrade behavior.

### Findings fixed during review

- แก้ UI ของ legacy local asset ไม่ให้ถูกแสดงเป็น remote เพียงเพราะ record เก่าไม่มี `verificationMethod`; ใช้ current exact local policy เป็นตัวตัดสิน
- เพิ่ม Scanner-side exact target check เพื่อไม่ให้ allowlisted origin ที่พ่วง path/query ผ่าน security boundary
- คง Compose project name เดิมเพื่อลด orphan stack และ upgrade surprise
- แยก config/origin/proof validation ออกจาก security-boundary functions ที่ complexity เกินเกณฑ์
- เพิ่ม service-boundary integration test ยืนยันว่า challenge และ verification method ที่ persist ไว้ถูกส่งถึง Scanner จริง
- รองรับ bracketed IPv6 normalization แบบ fail-closed ใน Scanner allowlist parser

### Automated review evidence

- Whole TypeScript review snapshot: grade A, average 95.3; this is a maintainability signal, not correctness proof
- Focused `remote_authorization.py`: score 100, grade A, average function complexity 4.0
- Focused `appConfig.ts`: score 89, grade B; no high-complexity finding remains, only low-severity numeric-default warnings
- No unresolved blocker was found in the V3.2 change set after runtime regression tests

### V3.2 verdict

`ship for authorized staging with guardrails` — local disposable full workflow is runtime-verified. Remote mode remains opt-in and fail-closed. Do not claim remote full E2E until the exact HTTPS origin serves a current ownership challenge, exposes only disposable `/__ac_test__/` resources, uses test identities and proves cleanup in target-side logs/database.

## Local no-login review addendum — 2026-08-22

Scope: removal of Scanner administrator login for Docker-only loopback use, while retaining session-backed CSRF, upload safety and the existing target-authorization boundaries.

Eight review rounds found and fixed pre-write multipart CSRF handling, DNS-rebinding Host validation, state-schema migration, direct-start LAN binding, known upload/body error mapping, obsolete admin environment migration, temporary state-file cleanup, strict numeric configuration parsing and launcher/route maintainability drift. Rounds 6–8 continued after the original five-round requirement until both review axes reported no actionable in-scope findings. Positive and negative state-changing request paths are covered.

Verdict: `ship for local-only Docker use`. Any LAN, reverse-proxy or public deployment requires a new threat model and real authentication; changing only the published port is not safe.
