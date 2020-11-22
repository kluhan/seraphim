def euclidean_forward(base,valueToInverse):
    
    q = int(base / valueToInverse)
    if(q < 0):
        q = 0

    a = valueToInverse
    r = base-(q*a)
    erg = base

    x0 = 0
    x1 = 1
    if r == 0:
        return f"ERROR - UNDEFINED INVERSE (Base: {base}), Value: {valueToInverse})"

    while(r != 0):
        invers = (x0 - x1 * q ) % base

        erg = a
        a = r

        q = int(erg/ a)
        if(q < 0):
            q = 0
        
        r = erg-(q*a)

        x0 = x1
        x1 = invers
    
    return invers


print(euclidean_forward(26,13))

print(euclidean_forward(26,15))
print(euclidean_forward(26,5))
print(euclidean_forward(26,19))
print(euclidean_forward(26,17))
print(euclidean_forward(26,27))
print(euclidean_forward(26,80))
print(euclidean_forward(26,610))
print(euclidean_forward(26,5007))
print(euclidean_forward(26,850))
print(euclidean_forward(26,8))





    
