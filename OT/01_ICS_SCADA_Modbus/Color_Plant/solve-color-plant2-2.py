#!/usr/bin/env python3

import os

# pip install pyModbusTCP
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host="localhost", port=4502, unit_id=1, auto_open=True)

regs = c.read_holding_registers(0, 32)
if regs:
    token = ''.join([ chr(r) for r in regs])
else:
    print("read error")

print(f'{token=}')
os.system(f'firefox http://localhost:8000/{token}')

RED, GREEN, BLUE, MIX = 0, 1, 2, 3
LABEL = ['rouge', 'vert', 'bleu']
DEBITS = [ 32, 33, 34, 35 ]
COILS = [ 0, 1, 2, 3]
INPUT_MIX = [3, 4, 5, 6]

def mix_color(color, qt):
    print(f'- Ajoute {qt} unités de {LABEL[color]}')
    c.write_single_register(DEBITS[color], 5)
    # On ouvre à 5 unités / s
    c.write_single_coil(COILS[color], 1)
    count = 0
    while count < qt//5*5:
        count = c.read_input_registers(INPUT_MIX[color])[0]
        print(f'\x0d{count=}', end='')
    # On complète à 1 unités / s
    c.write_single_register(DEBITS[color], 1)
    while count < qt:
        count = c.read_input_registers(INPUT_MIX[color])[0]
        print(f'\x0d{count=}', end='')
    print()
    c.write_single_coil(COILS[color], 0)

def vidange():
    print('- Vidange de la cuve de mixage.')
    # On ouvre la vanne basse en grand !
    c.write_single_register(DEBITS[MIX], 5)
    c.write_single_coil(COILS[MIX], 1)          # Auto si la cuve est pleine
    count = 100
    while count > 0:
        count = c.read_input_registers(INPUT_MIX[MIX])[0]
        print(f'\x0d{count=}', end='')
    print()
    # Pas besoin de refermer, c'est automatique.

# On fait notre mélange en deux passes !
for _ in range(2):
    mix_color(RED, 16)
    mix_color(GREEN, 63)
    mix_color(BLUE, 21)
    vidange()

input('Enter to stop')
