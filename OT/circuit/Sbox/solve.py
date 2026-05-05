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
