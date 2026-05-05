# Modbus FLAG1 Solver (Register Dump → Base64)

อ่าน Modbus Holding Registers (FC03) แล้วพยายามประกอบสตริง Base64 ที่ถูกเก็บแบบ ASCII กระจายหลายรีจิสเตอร์ จากนั้น decode เพื่อหา flag

## Run

```bash
python3 solve.py --host <ip-or-host> --port 502 --unit 1 --start 0 --end 10000
```

## Options

- `--start/--end` ช่วง address ของ holding registers ที่จะสแกน
- `--count` จำนวนรีจิสเตอร์ต่อการอ่าน (1–125)
- `--min-b64-len` ความยาวขั้นต่ำของสตริง Base64 ที่จะลอง decode
- `--flag-regex` กำหนดรูปแบบ flag เอง (ค่าเริ่มต้นพยายามจับ `coc2026{...}`, `flag{...}`, `ctf{...}`, ฯลฯ)

## Output

ถ้าพบ flag จะพิมพ์บรรทัด:

```
[FLAG] ...
[METHOD] ...
[META] ...
```

