def get_inverse(base,value_to_inverse):
    return __extended_euclid(base,value_to_inverse)

def __extended_euclid(base,value_to_inverse):
    
    q = int(base / value_to_inverse)
    if(q < 0):
        q = 0
    a = value_to_inverse
    r = base-(q*a)
    res = base

    x0 = 0
    x1 = 1
    if r == 0:
        print(f"ERROR - UNDEFINED INVERSE (Base: {base}), Value: {value_to_inverse})")
        return 0

    while(r != 0):
        invers = (x0 - x1 * q ) % base

        res = a
        a = r

        q = int(res/ a)
        if(q < 0):
            q = 0
        
        r = res-(q*a)

        x0 = x1
        x1 = invers
    
    return invers
   







    
