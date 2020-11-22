def getInverse(base,valueToInverse):
    return __extendedEuklid(base,valueToInverse)

def __extendedEuklid(base,valueToInverse):
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
   







    
