# 💡 Art-Net/DMX512: Lighting Control & Packet Forensics Cheat Sheet

**Target Protocol:** Art-Net (DMX512 Encapsulated over UDP)
**Typical Port:** UDP 6454

***

## 🔑 \[EXAM FOCUS] Keywords สำหรับสอน Trae IDE

หากโจทย์มีคีย์เวิร์ดเหล่านี้ ให้ AI เปลี่ยนโหมดมาใช้เครื่องมือวิเคราะห์ Art-Net/DMX ทันที:

- **Protocol:** `DMX`, `DMX512`, `Art-Net`
- **Hardware:** `Lighting`, `Video screen`, `LED Matrix Panel`, `RGB`
- **Data Structure:** `Universe`, `Sequence`, `Channels`
- **Logic/Action:** `Recreate an animation`, `Animated GIF`, `dpkt`, `Pillow (PIL)`

***

## 🔍 1. Initial Reconnaissance (การวิเคราะห์โครงสร้าง PCAP)

**\[EXAM FOCUS]** โปรโตคอล Art-Net คือการเอาคำสั่ง DMX512 (ที่ใช้คุมไฟเวที) มาห่อวิ่งบน UDP

**จุดสังเกตใน Wireshark/tshark:**

- ใช้ Filter: `udp` หรือ `artnet` เพื่อกรองแพ็กเก็ต
- โปรโตคอลนี้จะส่งค่าสี RGB (0-255) ของแต่ละหลอดไฟไล่ไปเรื่อยๆ ตาม Channel
- 1 แพ็กเก็ตมักจะจุข้อมูลได้จำกัด ถ้าจอใหญ่จะถูกหั่นเป็นหลาย **"Universe"**

***

## 🚩 2. Data Structure & Payload Extraction (การแกะข้อมูลดิบ)

หากใช้ Python (`dpkt`) ในการแกะ UDP Payload ของ Art-Net ให้โฟกัสที่ Byte Offset เหล่านี้:

- `payload[12]`: **Sequence Number** (ลำดับของเฟรมภาพ)
- `payload[14]`: **Universe ID** (ใช้ระบุครึ่งบน/ครึ่งล่างของจอภาพ)
- `payload[18:]`: **DMX Channels Data** (ข้อมูลสี RGB ของหลอดไฟ)

***

## ⚙️ 3. Logic Analysis: The "Zig-Zag" Matrix (จุดตายที่คนมักพลาด)

**\[EXAM FOCUS]** การต่อสายไฟของจอ LED Matrix ในวงการอุตสาหกรรม มักจะไม่ต่อเรียงซ้ายไปขวาทุกบรรทัด แต่มักจะต่อแบบ **"งูเลื้อย (Zig-Zag / Snake)"** เพื่อประหยัดสายไฟ

- บรรทัดที่ 1 (Index เลขคู่): วิ่งจาก ซ้าย -> ขวา
- บรรทัดที่ 2 (Index เลขคี่): วิ่งจาก ขวา -> ซ้าย

<span style="color:red; font-weight:bold;">\[TRICK] การแก้ตรรกะงูเลื้อยด้วย Python:</span>

````python
# หั่นข้อมูลสีออกเป็นบรรทัด (บรรทัดละ 16 พิกเซล)
lines = [ colors[i*16:i*16+16] for i in range(len(colors)//16) ]

# สลับด้าน (Reverse) เฉพาะบรรทัดที่เป็นเลขคี่
lines = [ line if i%2==0 else line[::-1] for i, line in enumerate(lines) ]
**

🛠️ 4. Python Toolkit (Art-Net to Image Converter)
สคริปต์สกัดภาพแอนิเมชันจากไฟล์ PCAP (ดัดแปลงจากโมดูล dpkt และ PIL):

Python
#!/usr/bin/env python3
import dpkt
from PIL import Image

def extract_artnet_frames(pcap_path):
    f = open(pcap_path,'rb')
    frame = 0
    universe0, universe1 = None, None
    
    for ts, pkt in dpkt.pcap.Reader(f):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_UDP: continue
        
        udp = ip.data
        # ทิ้งแพ็กเก็ตแรก (มักจะเป็นแพ็กเก็ตตั้งค่า)
        if frame == 0:
            frame += 1
            continue

        payload = udp.data
        sequence = payload[12]
        universe = payload[14]
        channels = payload[18:]
        
        # จับกลุ่มทีละ 3 Bytes (R, G, B)
        colors = [ tuple(channels[i*3:i*3+3]) for i in range(len(channels)//3) ]
        # จัดเรียงเป็นบรรทัด (16 พิกเซล/บรรทัด)
        lines = [ colors[i*16:i*16+16] for i in range(len(colors)//16) ]
        # แก้ปัญหาการเดินสายแบบ Zig-Zag
        lines = [ line if i%2==0 else line[::-1] for i, line in enumerate(lines)]
        
        if universe == 0:
            universe0 = lines
        else:
            universe1 = lines[:6] # ใช้แค่ครึ่งเดียวตามเอกสาร
            
        # เมื่อได้ข้อมูลครบทั้ง 2 Universe ให้รวมเป็นเฟรมภาพ
        if universe1 is not None and universe0 is not None:
            frame_data = universe0 + universe1
            # นำ frame_data ไปสร้างเป็นภาพ (เช่น ใช้ PIL Image.new('RGB', (width, height)))
            # ...
            
            # Reset สำหรับเฟรมถัดไป
            universe0, universe1 = None, None

# Usage: extract_artnet_frames('capture.pcap')
**


### 🧠 อัปเกรด Trae IDE Skill (เอาไปแปะเพิ่มใน Rules ได้เลย)

```yaml
## 💡 CTF Logic Recognition (Art-Net / DMX512 & LED Matrix)
# [EXAM FOCUS] หากโจทย์กล่าวถึง: "DMX", "Art-Net", "Lighting", "LED Matrix", "Universe", หรือมีไฟล์ pcap ที่คุยกันบน UDP
# ให้ตระหนักทันทีว่านี่คือโจทย์วิเคราะห์โปรโตคอลระบบแสงสว่าง
#
# กฎการทำ Data Extraction สำหรับโจทย์ประเภทนี้:
# 1. Payload Structure: ใช้ `dpkt` สกัด UDP Payload โดย Sequence = byte 12, Universe = byte 14, และ RGB Data เริ่มที่ byte 18
# 2. Hardware Constraint (Zig-Zag): การเรนเดอร์ภาพ LED Matrix ต้องทำการสลับ Array แบบ Reverse (`[::-1]`) ในบรรทัดที่เป็นเลขคี่เสมอ
# 3. Output Goal: เป้าหมายคือการแปลงค่า RGB ที่สกัดได้ ออกมาเป็นภาพ (.png) หรือ แอนิเมชัน (.gif) เพื่อให้ผู้ใช้อ่าน Flag จากภาพนั้น
````

