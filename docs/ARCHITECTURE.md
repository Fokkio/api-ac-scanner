# Local-first architecture

```text
Browser (127.0.0.1:3000)
        |
        v
Express / TypeScript web
  - no login; loopback operator trust boundary
  - session-backed CSRF
  - asset and report state (atomic JSON)
  - bounded in-process queue
  - endpoint inventory and identity-profile input
  - explicit authorization policy input
        |
        v  private internal token
FastAPI scanner (not published)
  - independent URL/path validation
  - DNS-pinned bounded HTTP client
  - OpenAPI, HAR, Postman, and source-route discovery
  - identity-aware authorization matrix
  - explicit-policy mismatch verification
  - Semgrep source rules and source/runtime correlation
  - guarded POST then DELETE mutation test
  - guarded local or verified-remote workflow + reverse cleanup
  - ephemeral same-origin JSON-login adapter
        |
        +--> allowlisted local API
        +--> verified-remote exact HTTPS origin (explicit feature flag + allowlist + live proof)
        +--> exact verified public origin
```

Browser ไม่เรียก scanner โดยตรง Web ตรวจ input, CSRF, queue capacity และ report scope ก่อน ส่วน scanner ตรวจ URL และ path ซ้ำอีกครั้งเพราะถือเป็น trust boundary แยกกัน Web ไม่มี authentication gate และต้องเข้าถึงผ่าน Compose port ที่ bind เฉพาะ `127.0.0.1`

## Authorization matrix

สำหรับ object path แต่ละรายการ scanner ยิงสาม request:

```text
owner/expected privileged -> same object path
alternate/lower role      -> same object path
anonymous                 -> same object path
```

สำหรับ admin/function path ทำ matrix แบบเดียวกัน ส่วน enumeration ส่ง anonymous request ไปยัง known-existing และ known-missing path อย่างละหนึ่งครั้ง

Token อยู่ใน closure ของ queued job และส่งตรงไป scanner; ไม่บันทึกลง JSON report ไม่ใส่ใน log และ finding เก็บเฉพาะ status/ขนาด/hash/ชื่อ property ที่จำกัดแล้ว

## Guarded workflow boundary

Workflow ใช้ได้กับ exact local allowlist หรือ exact HTTPS origin ที่เปิด `REMOTE_SAFE_MUTATION_ENABLED`, อยู่ใน `REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS` และผ่าน ownership verification เท่านั้น Web บันทึก verification method และส่ง proof ข้าม internal boundary; Scanner ตรวจ config, exact origin และ challenge ซ้ำผ่าน pinned client ก่อน authentication/mutation ทุก path ต้องอยู่ใต้ `/__ac_test__/` และ POST/PUT/PATCH body ต้องมี `apiAcScannerTest: true` จากนั้น scanner พยายาม DELETE cleanup ย้อนลำดับใน `finally`

JSON-login adapter ยิง POST ได้หนึ่งครั้งไปยัง same-origin relative path หลัง target authorization ผ่านแล้ว และดึง token string จาก dotted JSON path ที่กำหนด Token ที่ได้จะแทนที่ base credential headers ทั้งหมดและอยู่ใน memory เท่านั้น ส่วน report exporter ทำ evidence redaction ซ้ำก่อนสร้าง HTML/PDF

## Discovery and correlation

Discovery รับหลักฐานจาก OpenAPI/Swagger, HAR, Postman collection และ route source ที่รองรับ แล้วสร้าง endpoint inventory โดย HAR/Postman จะรับเฉพาะ request ที่ตรงกับ origin ของ asset แบบ exact match เท่านั้น ไม่ใช่ blind crawler และ route ที่สร้างแบบ dynamic อาจค้นไม่พบ

Source finding จะเชื่อมกับ runtime finding ก็ต่อเมื่อ category และ normalized route template ตรงกัน ผล correlation เป็นหลักฐานเสริมแบบ `suspected` ไม่ใช่การยืนยันช่องโหว่ด้วยตัวมันเอง

## Explicit policy and verified findings

V3.0 ขึ้นไปต้องมี policy ครบทุก identity รวม Anonymous สำหรับทุก object/function path ก่อนเริ่ม deep scan ระบบจะให้สถานะ `verified` เฉพาะเมื่อผล runtime ที่ตัดสินได้ขัดกับ policy ที่ผู้ใช้ระบุ คำว่า verified จึงหมายถึง "ยืนยันความขัดแย้งกับ policy ที่ป้อน" ไม่ได้พิสูจน์ว่า policy นั้นถูกต้องตามธุรกิจ

## Guarded mutation

Mutation scan อนุญาตเฉพาะ verified local target หรือ verified-remote exact HTTPS origin ที่ re-verify สำเร็จ, path ใต้ `/__ac_test__/`, JSON ที่มี `apiAcScannerTest: true` และคำยืนยันตาม target mode ระบบทำ POST แล้วพยายาม DELETE path เดิมทันที รวมถึงกรณี POST timeout อย่างไรก็ตาม rollback ไม่สามารถรับประกัน side effect ภายนอกหรือ asynchronous job ที่ target สร้างขึ้นได้

## Persistence

สถานะเก็บใน JSON ไฟล์เดียวและเขียนแบบ atomic replace ภายใน process ถ้า restart งานที่ค้างจะเปลี่ยนเป็น error ชัดเจน เหมาะกับ local single-node เท่านั้น
