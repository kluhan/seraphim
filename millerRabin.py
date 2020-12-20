from random import randrange

def miller_rabin(n, k):
    """Checks if a given number is prime.

    Checks a given number k-times with the Miller-Rabin test

    Args:
        n: Number to be checked.
        k: How often the Miller-Rabin test will be executed before returning True

    Returns:
        Returns True if the given number is likely to be prime and false if it is not
    """

    # primitive prime test
    if n == 2:
        return True
        
    # check LSB of n, if it is zero n is a multiple of two and can not be prime 
    if not n & 1:
        return False

    def check(base, depth, exp, mod):

        x = pow(base, exp, mod)

        # check first element of series
        if x == 1:
            # if first element of series is one we can not say n isn't prime so we assume it is prime 
            return True

        # compute rabin-miller for all previous calculated exponents  
        for _ in range(depth - 1):

            # check if x is equal to -1
            if x == mod - 1:
                # if series contains -1 we can not say n isn't prime so we assume it is prime   
                return True

            # square x to get next number to check
            x = pow(x, 2, mod)

        # if last element of series is -1 we can not say n isn't prime so we assume it is prime   
        return x == n - 1

    depth = 0
    exponent = n - 1

    # find the samlest exponent which needs to be checked by dividing by two as often as possible
    while exponent % 2 == 0:
        # divide exponent by two by shifting one bit to the right
        exponent >>= 1
        depth += 1

    # check prime k-times
    for _ in range(k):
        # draw random base
        base = randrange(2, n - 1)

        # test prime drawn base 
        if not check(base, depth, exponent, n):
            # return false if miller-rabin test proves that n isn't prime
            return False
    # after k-times retrun true if miller-rabin hasn't shown that n isn't prime  
    return True
