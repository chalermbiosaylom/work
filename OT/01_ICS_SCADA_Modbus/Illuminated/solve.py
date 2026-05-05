#!/usr/bin/env python3

import dpkt
from PIL import Image

frame = 0
universe0, universe1 = None, None
images = []
f = open('capture.pcap','rb')
for ts, pkt in dpkt.pcap.Reader(f):

    eth=dpkt.ethernet.Ethernet(pkt)
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue

    ip=eth.data
    if ip.p!=dpkt.ip.IP_PROTO_UDP:
        continue

    udp=ip.data

    # On jette le premier paquet
    if frame == 0:
        frame += 1
        continue

    payload = udp.data
    sequence = payload[12]
    universe = payload[14]

    channels = payload[18:]
    colors = [ tuple(channels[i*3:i*3+3]) for i in range(len(channels)//3) ]
    lines = [ colors[i*16:i*16+16] for i in range(len(colors)//16) ]
    lines = [ line if i%2==0 else line[::-1] for i, line in enumerate(lines)]
    if universe == 0:
        universe0 = lines
    else:
        universe1 = lines[:6]
    print(f'{sequence=} {universe=}: {len(lines)} lines.')

    if universe1 is not None and universe0 is not None:
        frame_data = universe0 + universe1
        print('\n'.join([str(line) for line in frame_data]))
        frame_data = [ item for line in frame_data for item in line ]
        img = Image.new('RGB', (16,16))
        img.putdata(frame_data)
        images.append(img)
        frame+=1
        universe0, universe1 = None, None

images[0].save('result.gif', save_all=True, append_images=images[1:], duration=40, loop=0)
