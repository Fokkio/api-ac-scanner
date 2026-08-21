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
