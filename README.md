# Assignment 2 - CNC211: Suspicious Login Detection

ระบบตรวจจับการเข้าสู่ระบบที่น่าสงสัย (Suspicious Login Detection) จากไฟล์ Log การเข้าสู่ระบบ
ของพนักงาน โดยจะแจ้งเตือนบัญชีผู้ใช้ที่มีการ Login ไม่สำเร็จ (`FAILED`) ติดต่อกันตั้งแต่ 3 ครั้งขึ้นไป
และเหตุการณ์แรก-สุดท้ายของชุดนั้นห่างกันไม่เกิน 5 นาที การ Login สำเร็จ (`SUCCESS`) จะตัดความ
ต่อเนื่องและเริ่มนับชุดใหม่

## โครงสร้างไฟล์

| ไฟล์ | รายละเอียด |
|---|---|
| `suspicious_login_detector.py` | โปรแกรมหลักสำหรับอ่านและวิเคราะห์ Log |
| `login.txt` | ข้อมูล Log ตัวอย่างที่ใช้ทดสอบ (`timestamp,username,ip_address,status`) |
| `REPORT.md` | รายงานวิเคราะห์และเปรียบเทียบอัลกอริทึม (ไม่เกิน 2 หน้า A4) |

## อัลกอริทึมที่ใช้

จัดกลุ่ม Log ตาม username แล้วเรียงตามเวลา จากนั้นสแกนครั้งเดียวเพื่อนับชุด `FAILED`
ที่ต่อเนื่องกัน เมื่อพบ `SUCCESS` หรือจบไฟล์จะตรวจสอบว่าชุดนั้นมีความยาว ≥ 3 ครั้ง และ
ห่างกันไม่เกิน 5 นาทีหรือไม่ รายละเอียดการวิเคราะห์และเปรียบเทียบกับวิธี Brute Force
อยู่ใน [`REPORT.md`](REPORT.md)

## วิธีใช้งาน

```bash
python3 suspicious_login_detector.py login.txt
```

### ตัวอย่างผลลัพธ์

```
Suspicious login activity detected:

- david: 3 failed attempts between 2026-10-01 09:10:00 and 2026-10-01 09:11:00
- frank: 3 failed attempts between 2026-10-01 09:22:00 and 2026-10-01 09:23:00
```

## ความต้องการของระบบ

- Python 3.7 ขึ้นไป (ไม่ต้องติดตั้งไลบรารีเพิ่มเติม ใช้เฉพาะ standard library)
</content>
