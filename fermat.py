from random import randrange

def fermat(n, k):
    """Checks if a given number is prime.

    Checks a given number k-times with the fermat primality test 

    Args:
        n: Number to be checked.
        k: How often the fermat primality test test will be executed before returning True

    Returns:
        Returns True if the given number is likely to be prime and false if it is not
    """

    # primitive prime test
    if n == 2:
        return True

    # check LSB of n, if it is zero n is a multiple of two and can not be prime 
    if not n & 1:
        return False

    def check(n):
        # draw random base
        r = randrange(2, n)-1

        if(pow(r, n-1, n) != 1 ):
            return False
        else:
            return True

    # check prime k-times
    for _ in range(k):
        # test prime drawn base 
        if not check(n):
            # return false if miller-rabin test proves that n isn't prime
            return False
        # after k-times retrun true if miller-rabin hasn't shown that n isn't prime 
        else:
            return True
        