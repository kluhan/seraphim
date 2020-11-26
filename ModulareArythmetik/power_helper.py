def repeated_square(value_to_pow):
    res = 2
    running = True
    while(running):
        if(res*2 < value_to_pow):
            res = res * 2
        else:
            running = False
            return res

    return res
    
def squre_power_calc(value_to_pow):
    return 1


def little_fermat(base, value_to_pow):
    while(value_to_pow > base):
        value_to_pow = value_to_pow - (base-1)
    return value_to_pow
