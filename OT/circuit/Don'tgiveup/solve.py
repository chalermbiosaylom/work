x0,x1,x2,x3,x4 = (1,0,0,1,1)

def rotate():
    global x0,x1,x2,x3,x4
    tmp = x0
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = x4
    x4 = tmp

def prop_and_rotate():
    r = x0 ^ (x3 &  (x4^1))
    rotate()
    return r

for _ in range(0,5):
    print(prop_and_rotate())o
