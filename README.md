# API Access-Control Scanner

เครื่องมือสแกนช่องโหว่ **Authorization / Access Control** ของ API สร้างผ่าน Docker
(ตาม OWASP API Security Top 10: BOLA, BFLA, Mass Assignment ฯลฯ)

## ฟีเจอร์

1. **Domain scan** (สด / black-box)
   - สแกน domain หรือ base URL ใดก็ได้แบบ read-only confirm
   - หาช่องโหว่ BOLA / BFLA / Unrestricted resource consumption
   - **Auth-swap BOLA test**: ส่ง request ยัง object เดียวกันด้วย token ของ user ปกติ
     แล้วส่งซ้ำด้วย token ของ user คนอื่น (หรือไม่มี token) — ถ้า response body เหมือนกัน
     (similarity ≥ 0.85) แปลว่าการครอบครองไม่ถูกบังคับ → **BOLA confirmed**
   - mutation ถูกแฟล็ก แต่ **ไม่ execute** ในโหมด read-only (ปลอดภัย)
   - dashboard แสดงระดับความร้ายแรง (OWASP API + CVSS)

2. **Source-code scan** (static / Semgrep)
   - รองรับ **Node/Express, Python(Flask/FastAPI), PHP, Java frameworks**
   - หา BOLA / Mass Assignment pattern
   - **Preview-then-apply**: ดู diff เทียบของเดิม กด Apply เพื่อแก้ใน copy ของคุณ
   - dashboard เหมือนข้อ 1

3. **UI/UX**
   - Server-rendered (EJS) + vanilla JS/CSS — ออกแบบมือ ป้องกัน AI UI slop
   - ข้อมูลครบ: severity, OWASP, CVSS, แนวทางแก้, ปุ่ม preview/apply fix

## สถาปัตยกรรม

```
api-ac-scanner/
├── docker-compose.yml   # stack + healthchecks + env
├── Makefile             # convenience commands (build/start/logs/...)
├── scanner/             # Python FastAPI + Semgrep rules (port 8001, internal)
│   ├── app/             # engines, severity, fixers, main
│   └── semgrep_rules/   # nodejs / python / php / java
├── web/                 # Node/Express (TypeScript) + EJS dashboard (port 3000)
│   ├── src/
│   ├── views/
│   └── public/
└── fixtures/            # vulnerable samples for testing the scanner
```

## วิธีรัน (Docker + Make)

```bash
# จาก D:\api-ac-scanner
make build      # สร้าง images
make start      # รัน stack (detached) -> http://localhost:3000
make logs       # ดู log แบบ live
make stop       # หยุด
make help       # ดูคำสั่งทั้งหมด
```

ถ้าไม่ใช้ `make` สามารถรันตรงได้:

```bash
docker compose up --build
# เปิด http://localhost:3000
```

ส่วนประกอบ:
- `web` เปิด port 3000 (local-only ตามดีไซน์)
- `scanner` ทำงานใน internal network เท่านั้น (ไม่เปิด outward)
- **Healthcheck**: ทั้ง `web` และ `scanner` มี healthcheck; `web` จะรอจนกว่า
  `scanner` จะ healthy ก่อนเริ่ม (`depends_on: condition: service_healthy`)

## การตั้งค่า Environment Variables

ตั้งใน `docker-compose.yml` (หรือ `export` ก่อน `make start`) — ตัวอย่างอยู่ในไฟล์แล้ว:

| ตัวแปร | บริการ | คำอธิบาย | ค่าเริ่มต้น |
|---|---|---|---|
| `SESSION_SECRET` | web | คีย์เซ็น session cookie。**ว่างเปล่า = web ปฏิเสธ start** (เดิมเคยมี fallback อ่อนๆ ถูกเอาออกเพราะเสี่ยง session forgery) | ต้องตั้งเอง (prod) |
| `CORS_ORIGINS` | scanner | รายชื่อ origin ที่อนุญาตเรียก scanner API (คั่นด้วย `,`) — ล็อกเป็น allowlist **ไม่ใช่ `"*"`** | `http://localhost:3000` |
| `SCANNER_URL` | web | URL ภายในที่ web เรียก scanner | `http://scanner:8001` |
| `DATA_DIR` | web | ที่เก็บ scan records (`db.json`) | `/data` |
| `UPLOAD_ROOT` | web | ที่เก็บไฟล์ source ที่อัปโหลด | `/uploads` |
| `PORT` | web | พอร์ต web UI | `3000` |

**ตัวอย่าง (production):**

```yaml
environment:
  - SESSION_SECRET=m4X8vP2qL9kR3tB7wZ1nC6yE5uH0iO4s   # สุ่มยาวๆ
  - CORS_ORIGINS=https://scanner.f0kki0.me
```

> 💡 ถ้าเอาไป deploy สาธารณะ **ต้อง** เปลี่ยน `SESSION_SECRET` เป็นค่าสุ่มยาว
> และตั้ง `CORS_ORIGINS` เป็นโดเมนของคุณเท่านั้น

## SSRF Guard (ความปลอดภัยฝั่ง scanner)

Domain scan รับ `target` จากผู้ใช้แล้วไป fetch URL จริง — ถ้าไม่ระวังจะถูกใช้เป็น
"กระสุน" ให้ scanner ไปโทรหา internal/metadata endpoint ได้ (Server-Side Request Forgery)

โปรเจกต์นี้มี **`is_blocked_target()`** (`scanner/app/engines.py`) ที่บล็อกเป้าหมายที่ resolve
ไปยังที่อยู่แบบไม่สาธารณะ:

- 🔒 **Loopback** (`127.0.0.0/8`, `::1`)
- 🔒 **Private RFC1918** (`10/8`, `172.16/12`, `192.168/16`)
- 🔒 **Link-local** (`169.254.0.0/16` — รวม **AWS/GCP metadata `169.254.169.254`**)
- 🔒 **CGNAT** (`100.64.0.0/10`), IPv6 unique-local/link-local
- 🔒 ตรวจทั้ง IP literal **และ** DNS resolution (fail-closed — ถ้า resolve ไม่ได้จะบล็อก)

Guard ถูกเรียกครบ **4 จุด**: target หลัก, URL ที่ผู้ใช้ใส่เอง (object_urls), admin path (BFLA),
และ `_safe_get` (ด่านสุดท้ายก่อนทำ request จริง) เป้าหมายที่ถูกบล็อกจะคืน finding
`domain-ssrf-blocked` แทนที่จะไปทำ request

**ทดสอบ guard:**

```bash
make test-ssrf
# หรือ: docker run --rm -v "$PWD/scanner/app:/app/app" -w /app python:3.11-slim \
#        bash -c "pip install -q httpx fastapi; python -c 'from app import engines; ...'"
# ผลคาดหวัง: block 127.0.0.1/localhost/169.254.169.254/10.x/192.168.x/::1
#            อนุญาต 8.8.8.8 / example.com / api.github.com
```

## การใช้งาน

- **Scan Domain**: ใส่ URL + (optional) auth token ของ user ธรรมดา → รัน
- **Scan Source**: อัปโหลดโฟลเดอร์/ไฟล์ source → ดูรายงาน → กด Preview fix → Apply

## หมายเหตุความปลอดภัย

- Domain scan เปิดให้ใส่ domain ใดก็ได้ แต่ต้อง **ยืนยันว่าคุณได้รับอนุญาต/เป็นเจ้าของ**
  (มี consent checkbox ใน UI) — เครื่องมือนี้สำหรับทดสอบ asset ของตัวเอง
- โหมดดีฟอลต์คือ read-only (ไม่มี write/delete)
- Auto-apply ทำเฉพาะบน **copy ที่อัปโหลด** ของคุณ (original ภายนอกไม่ถูกแตะ)
- ห้ามใช้เครื่องมือนี้สแกน API ของคนอื่นโดยไม่ได้รับอนุญาต

## เทสต์ว่าสแกนเจอจริง

```bash
# ภายใน container scanner
semgrep scan --config scanner/semgrep_rules --json fixtures/vulnerable-node
```

ควรพบ `nodejs-bola-object` และ `nodejs-mass-assignment`
