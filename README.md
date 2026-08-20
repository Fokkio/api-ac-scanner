# API Access-Control Scanner

เครื่องมือสแกนช่องโหว่ **Authorization / Access Control** ของ API สร้างผ่าน Docker
(ตาม OWASP API Security Top 10: BOLA, BFLA, Mass Assignment ฯลฯ)

## ฟีเจอร์

1. **Domain scan** (สด / black-box)
   - สแกน domain หรือ base URL ใดก็ได้แบบ read-only confirm
   - หาช่องโหว่ BOLA / BFLA / Unrestricted resource consumption
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
├── docker-compose.yml
├── scanner/        # Python FastAPI + Semgrep rules (port 8001, internal)
│   ├── app/        # engines, severity, fixers, main
│   └── semgrep_rules/  # nodejs / python / php / java
├── web/            # Node/Express (TypeScript) + EJS dashboard (port 3000)
│   ├── src/
│   ├── views/
│   └── public/
└── fixtures/       # vulnerable samples for testing the scanner
```

## วิธีรัน (Docker)

```bash
# จาก D:\api-ac-scanner
docker compose up --build
# เปิด http://localhost:3000
```

- `web` เปิด port 3000 (local-only ตามดีไซน์)
- `scanner` ทำงานใน internal network เท่านั้น

## การใช้งาน

- **Scan Domain**: ใส่ URL + (optional) auth token ของ user ธรรมดา → รัน
- **Scan Source**: อัปโหลดโฟลเดอร์/ไฟล์ source → ดูรายงาน → กด Preview fix → Apply

## หมายเหตุความปลอดภัย

- Domain scan เปิดให้ใส่ domain ใดก็ได้ แต่ต้อง **ยืนยันว่าคุณได้รับอนุญาต/เป็นเจ้าของ**
  (มี consent checkbox ใน UI) — เครื่องมือนี้สำหรับทดสอบ asset ของตัวเอง
- โหมดดีฟอลต์คือ read-only (ไม่มี write/delete)
- Auto-apply ทำเฉพาะบน **copy ที่อัปโหลด** ของคุณ (original ภายนอกไม่ถูกแตะ)

## เทสต์ว่าสแกนเจอจริง

```bash
# ภายใน container scanner
semgrep scan --config scanner/semgrep_rules --json fixtures/vulnerable-node
```
ควรพบ `nodejs-bola-object` และ `nodejs-mass-assignment`
