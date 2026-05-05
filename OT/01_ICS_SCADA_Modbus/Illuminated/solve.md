Solution
I didn't know the subject, I start by opening the archive with Wireshark. Good news, it There is a dissector for this traffic. We are therefore in the presence of the protocol , encapsulated in , based on . A package looks like this:pcapDMXArt-NetUDPDMX



You can see three important things when you walk through the packages:

There appears to be a sequence number in each of the packets. Moreover, sometimes the sequences do not appear not in the right order of the trace (logical, for the).UDP
The field varies between 0 and 1.universe
if the dissector shows a table of percentages, it is turns out that they are in fact integers between 0 and 255.
Let's refer to the PDF provided, which confirms the two universes observed in the track. We can see that only half of the second universe seems to be used, and this is confirmed in the trace: has always the last half of its values at 0. We also understands that each LED is described by an RGB triplet (Red - Green - Blue) with values from 0 to 255 as shown in the trace. Finally, the journey through the universes zig-zags: the first line is described from left to right, the second from right to left, and so on...Universe: 1

We have all the information to write a parser. I chose to use python, decoding the network trace using dpkt and generating a sequence of frames assembled at the end into an animated GIF thanks to in Pillow. Let's see the code (I omitted a few things for readability, the full script is below).

We start by initializing the sequence and universe numbers, and we prepare an array that will receive the frames of the final gif:

frame = 0
universe0, universe1 = None, None
images = []
We open the network trace and... the first package is thrown away. Because If we look at the trace, we realize that it begins with a half of an image (we only have one universe on this sequence). Laziness to make it clean, therefore:

f = open('capture.pcap','rb')
for ts, pkt in dpkt.pcap.Reader(f):

    # On jette le premier paquet
    if frame == 0:
        frame += 1
        continue
We retrieve the data we are interested in in each package: the sequence, the universe and the DMX data. In reality, the sequence will not be not used because, luckily, they are in order in the capture.

    payload = udp.data
    sequence = payload[12]
    universe = payload[14]
    channels = payload[18:]
We transform the values into a list of triplets:DMX(R, G, B)

    colors = [ tuple(channels[i*3:i*3+3]) for i in range(len(channels)//3) ]
We break down this online list of 16 diodes:

    lines = [ colors[i*16:i*16+16] for i in range(len(colors)//16) ]
Every other line, we reverse the direction of the triples (remember?):

    lines = [ line if i%2==0 else line[::-1] for i, line in enumerate(lines)]
In the case of universe 1, only half of it is kept.

    if universe == 0:
        universe0 = lines
    else:
        universe1 = lines[:6]
When we have recovered the two universes of the sequence, we concatenate them and a corresponding RGB image is created.

    if universe1 is not None and universe0 is not None:
        frame_data = universe0 + universe1
        frame_data = [ item for line in frame_data for item in line ]
        img = Image.new('RGB', (16,16))
        img.putdata(frame_data)
        images.append(img)
        frame+=1
        universe0, universe1 = None, None
When we get to the end of the trace, we save all our frames in a gif.

images[0].save('result.gif', save_all=True, append_images=images[1:], duration=40, loop=0)
The complete script is below, and at the end of its execution, we get: 

Yes, you have to zoom in! :) The flag that appears is .FCSC{L1ghtD3sign3rCr-gg!}

Resolution script
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
