# Assignment 2 - CNC211: Suspicious Login Detection

ระบบตรวจจับการเข้าสู่ระบบที่น่าสงสัย (Suspicious Login Detection) จากไฟล์ Log การเข้าสู่ระบบ
ของพนักงาน โดยจะแจ้งเตือนบัญชีผู้ใช้ที่มีการเข้าสู่ระบบไม่สำเร็จ (`FAILED`) ติดต่อกันตั้งแต่ 3 ครั้งขึ้นไป
และเหตุการณ์แรกกับเหตุการณ์สุดท้ายของชุดนั้นต้องห่างกันไม่เกิน 5 นาที การเข้าสู่ระบบสำเร็จ
(`SUCCESS`) จะตัดความต่อเนื่องและเริ่มนับชุดใหม่

การแจ้งเตือนเป็นเพียงสัญญาณให้ตรวจสอบเพิ่มเติม ไม่ได้ยืนยันว่าบัญชีถูกโจมตี

## โครงสร้างไฟล์

| ไฟล์ / โฟลเดอร์ | รายละเอียด |
|---|---|
| `detect_a.py` | อัลกอริทึม A: อ่านและตรวจสอบ Log แล้วตรวจจับด้วย Sliding Window (Two-Pointer) |
| `detect_b.py` | อัลกอริทึม B: ตรวจจับด้วย Brute Force แบบตรวจทุกจุดเริ่มต้น เพื่อใช้เปรียบเทียบกับอัลกอริทึม A |
| `load_logs.py` | ตัวอ่าน Log แบบอิสระ (dict-based) สำหรับทดลอง/ใช้งานแยกจาก `detect_a.load_logs` |
| `login.txt` | ข้อมูล Log ตัวอย่างในรูปแบบ CSV: `timestamp,username,ip_address,status` |
| `benchmark.py` | สคริปต์วัดประสิทธิภาพ (เวลา/หน่วยความจำ) ของ `detect_a` กับ `detect_b` ที่ขนาดข้อมูลต่าง ๆ |
| `benchmark.png` | กราฟผลลัพธ์จากการรัน `benchmark.py` |
| `testcases/` | ชุดข้อมูลทดสอบกรณีขอบ (edge cases) 5 กรณี พร้อมผลการทดสอบจริง (`Testing_Result.pdf`) |
| `docs/` | บันทึกประกอบการแก้ไขโค้ดและการวิเคราะห์ Big-O จากการทำ benchmark |
| `REPORT.md` | รายงานวิเคราะห์และเปรียบเทียบอัลกอริทึม ฉบับย่อ (ไม่เกิน 2 หน้า A4) |
| `REPORT.pdf` | รายงานฉบับเต็ม: โจทย์ การออกแบบอัลกอริทึม ตารางเปรียบเทียบความซับซ้อน และเหตุผลในการเลือก |

## อัลกอริทึมที่ใช้

จัดกลุ่ม Log ตาม `username` แล้วตรวจสอบว่าเหตุการณ์ของผู้ใช้แต่ละคนเรียงตามเวลาอยู่
แล้วหรือไม่ ถ้าเรียงอยู่แล้วจะข้ามขั้นตอนเรียงลำดับไปเลย (ลดเวลาทำงานจาก O(N log N)
เหลือ O(N) สำหรับผู้ใช้นั้น) แต่ถ้ายังไม่เรียงจะเรียงตามเวลาก่อน จากนั้นแยกเหตุการณ์
ออกเป็นชุด `FAILED` ที่ต่อเนื่องกัน (ตัดด้วย `SUCCESS`) และสแกนแต่ละชุดด้วยเทคนิค
Two-Pointer (`left`/`right`) เพื่อหาหน้าต่างเวลาที่ยาวที่สุดซึ่งมี `FAILED` ≥ 3 ครั้ง
และห่างกันไม่เกิน 5 นาที รายละเอียดการวิเคราะห์และเปรียบเทียบกับวิธี Brute Force
อยู่ใน [`REPORT.md`](REPORT.md) และฉบับเต็มใน [`REPORT.pdf`](REPORT.pdf) ส่วน
รายละเอียด Big-O ของการข้าม Sort อยู่ใน
[`docs/benchmark_big_o_analysis.txt`](docs/benchmark_big_o_analysis.txt)

## วิธีใช้งาน

```bash
python3 detect_a.py login.txt
```

หากไม่ระบุชื่อไฟล์ โปรแกรมจะอ่าน `login.txt` จากโฟลเดอร์ปัจจุบัน:

```bash
python3 detect_a.py
```

### ตัวอย่างผลลัพธ์

```
Suspicious login activity detected (requires further review):

- Username: david | FAILED: 3 | Period: 2026-10-01 09:10:00 to 2026-10-01 09:11:00
- Username: frank | FAILED: 3 | Period: 2026-10-01 09:22:00 to 2026-10-01 09:23:00
```

## Benchmark

วัดเวลาและหน่วยความจำของ `detect_a` เทียบกับ `detect_b` ที่ขนาด Log 1,000 / 5,000 / 10,000 / 20,000 แถว:

```bash
python3 benchmark.py
```

ผลลัพธ์ตัวอย่างและกราฟอยู่ที่ [`benchmark.png`](benchmark.png) และสรุปการวิเคราะห์ Big-O
อยู่ที่ [`docs/benchmark_big_o_analysis.txt`](docs/benchmark_big_o_analysis.txt)

## Test Cases

ไฟล์ทดสอบกรณีขอบทั้ง 5 กรณีอยู่ใน [`testcases/`](testcases/) — ทดสอบขอบเขตเวลา 5 นาที,
สถานะ `SUCCESS` คั่นกลาง, หลายบัญชีปนกัน, เวลาเกิดเหตุซ้ำกัน และข้อมูลไม่เรียงตามเวลา

```bash
python3 detect_a.py testcases/testcase1_time.txt
```

ผลการทดสอบจริงอยู่ที่ [`testcases/Testing_Result.pdf`](testcases/Testing_Result.pdf)

## ความต้องการของระบบ

- Python 3.7 ขึ้นไป (ไม่ต้องติดตั้งไลบรารีเพิ่มเติม ใช้เฉพาะ standard library)
