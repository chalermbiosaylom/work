You are asked to evaluate the given circuit ( sbox.png) using the 4-bit binary value (x3, x2, x1, x0) = (1, 0, 1, 0)to find the value of y = (y3, y2, y1, y0)the output of the circuit. The flag is FCSC{<y>}, with <y>the output value written in 4-bit binary.

Example: on the 4-bit input (x3, x2, x1, x0) = (1, 0, 0, 0), the output value would be (y3, y2, y1, y0) = (0, 0, 1, 1)and the flag would be FCSC{0011}


Table of Contents
Introduction
Python script
Explanation of the script
Result
Introduction
This write-up details how I solved the Sbox - Hackropole challenge using a Python script.

Python script
I wrote a Python script to solve this challenge. The script uses two main functions, XORand NOR, to perform logical operations on four input variables.

Here is the complete script:

def XOR (a, b):
    if a != b:
        return 1
    else:
        return 0

def NOR(a, b):
    if(a == 0) and (b == 0):
        return 1
    elif(a == 0) and (b == 1):
        return 0
    elif(a == 1) and (b == 0):
        return 0
    elif(a == 1) and (b == 1):
        return 0
    
if __name__=='__main__':
    x3=x1=1
    x2=x0=0
            
    y3 = XOR(x0,NOR(x3,x2))
    y2 = XOR(x3,NOR(x2,x1))
    y1 = XOR(x2,NOR(x1,y3))
    y0 = XOR(x1,NOR(y3,y2))
    
    print(f"FCSC{{{y3}{y2}{y1}{y0}}}")
Explanation of the script
The function XORtakes two arguments and returns 1 if the arguments are different, otherwise it returns 0. The function NORalso takes two arguments and returns 1 if both arguments are 0, otherwise it returns 0.

In the main program block, four input variables are defined. Then, the functions `x` XORand `y` NORare used to calculate four new variables. Finally, these new variables are printed in the form `x` FCSC{y3,y2,y1,y0}.

Result
By running this script, I was able to solve the Sbox - Hackropole challenge.
