One of your colleagues found this electronic circuit diagram ( circuit.pdf) in a product manual and is asking for your help in understanding it. The manual mentions a function fapplied to integers and gives an example f(19) = 581889079277.

Your colleague needs to find xsuch as f(x) = 454088092903.

The flag is FCSC{<x>}, with <x>the value of xin decimal notation.

I'm going to use an online tool to convert the PDF to JPG and I'm going to analyze it with… GIMP so I can make colored dots.

This circuit seems very complex at first glance: 40 inputs, 40 outputs, and lots of complicated gates. But you quickly realize that it's the same block copied everywhere. After a quick look at Wikipedia to refresh my memory of the symbols, I create the truth table for the recurring block on the right. There are only two inputs, with four combinations to test; it's quick with GIMP and my red and blue dots. The resulting truth table is as follows:

e0	e1	s0
0	0	0
0	1	1
1	0	1
1	1	0
Therefore, we can simplify this large block with a simple XOR operation!

We repeat the operation with the recurring block on the left (which has two outputs) and we obtain this:

e0	e1	s0	s1
0	0	0	0
0	1	1	0
1	0	0	1
1	1	1	1
So it's simply a matter of crossing the threads!

The circuit is greatly simplified, but something else needs to be noted.

We observe that x0it is xored to itself. This necessarily means 0! We can therefore complete a good part of the circuit which is constant. Here is a scribble that summarizes the beginning (red for the 1and blue for the 0):


Next, the block x39is almost identical to the recurring block on the right, but without the final inverter; it is therefore an NXOR. x39 NXOR x39This necessarily means 1we can again complete everything related to the wire coming out of this block.

We realize that inverters are distributed along these wires with constant values, which means that a constant signal enters each right-hand XOR gate. This acts like a key that we XOR to the bits of the first xgate after slightly shuffling them. This results in:

y0 = x0 ^ 0
y1 = x2 ^ 0
y2 = x1 ^ 0
y3 = x4 ^ 0
y4 = x3 ^ 0
y5 = x6 ^ 1
y6 = x5 ^ 1
y7 = x8 ^ 1
y8 = x7 ^ 1
y9 = x10 ^ 1
y10 = x9 ^ 1
We could continue like this, but it's long and boring, so we're going to make a script.

The constant key is 0000011111101101010100101101111011100001, from top to bottom. The script simulating the entire circuit is therefore:

x = [int(b) for b in "{:040b}".format(int(input("> ")))[::-1]]
y = [int(b) for b in "0"*40]

key = [int(b) for b in "0000011111101101010100101101111011100001"]

for i in range(40):
    if i == 0 or i == 39 :
        y[i] = x[i] ^ key[i]
    elif i%2 == 0:
        y[i] = x[i-1] ^ key[i]
    else:
        y[i] = x[i+1] ^ key[i]

print(int("".join([str(i) for i in y])[::-1], base=2))
We can try it and we'll find it f(19) = 581889079277!

All that remains is to create a script that reverses the process:

y = [int(b) for b in "{:040b}".format(int(input("> ")))[::-1]]
x = [int(b) for b in "0"*40]

key = [int(b) for b in "0000011111101101010100101101111011100001"]

for i in range(40):
    if i == 0 or i == 39 :
        x[i] = y[i] ^ key[i]
    elif i%2 == 0:
        x[i] = y[i-1] ^ key[i-1]
    else:
        x[i] = y[i+1] ^ key[i+1]

print(int("".join([str(i) for i in x])[::-1], base=2))
And it works! The flag isFCSC{1061478808711}
