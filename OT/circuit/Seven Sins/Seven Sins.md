You are given a seven-segment display connected to inputs that you know, numbered from 1 to Bit 01 Bit 8as shown in the image 7segments.png. You are asked to provide the 8 sequences of 9 bits that produce the sequential output shown in the image fcsc2022.png.

Note: the flag is FCSC{XXX}where XXXis the sequence of bits found (therefore a sequence of characters '0' and '1').

Example: the flag for the sequence of numbers 789would be FCSC{011100100111111110111101110}.

7-segment display
The hardest part of this challenge is knowing which letter from aA to Z gcorresponds to each segment. A Qwant search for “7-segment displays” returns several images, including this one:

https://robotscolaire.blogspot.com/2019/03/afficheur-7-segments.html

In summary, we start at athe top, continue in the direction of the hands of a clockwise direction, and the middle bar of the 8 is the segment g.

The bit DP(for decimal point ) corresponds to the point in the bottom right corner.

From the example, we also observe that bit 6 ( Enable) is always at 1: it is used to activate the segments corresponding to bits 0 to 5 and 7 to 8.

Suite of useful bits
Using the segment nomenclature, we therefore have:

F=000111110
C=100111100
S=110101110
2= 100111100(and to light up the decimal point: 100111101)
0=111111100
The solution is formed by concatenating the 9-bit sequences of 'F', 'C', 'S', 'C', '2', '0', '2' and '2' with the decimal point lit.
