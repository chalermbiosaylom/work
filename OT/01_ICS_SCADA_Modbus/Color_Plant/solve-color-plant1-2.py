#!/usr/bin/env python3

import os

# pip install pyModbusTCP
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host="localhost", port=4502, unit_id=1, auto_open=True)

regs = c.read_holding_registers(0, 32)
if regs:
    print(regs)
    token = ''.join([ chr(r) for r in regs])
    os.system(f'firefox http://localhost:8000/{token}')
    input('Press any key to stop')
else:
    print("read error")
