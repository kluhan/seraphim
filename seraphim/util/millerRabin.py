from random import randrange


def miller_rabin(n, k, mode_list=None):
    """Checks if a given number is prime.

    Checks a given number k-times with the Miller-Rabin test

    Args:
        n: Number to be checked.
        k: How often the Miller-Rabin test will be executed before returning True

    Returns:
        Returns True if the given number is likely to be prime and false if it is not
    """

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

    # check LSB of n, if it is zero n is a multiple of two and can not be prime
    if not n & 1:
        return False

    # primitive prime test
    lowPrimes = [
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
        199,
        211,
        223,
        227,
        229,
        233,
        239,
        241,
        251,
        257,
        263,
        269,
        271,
        277,
        281,
        283,
        293,
        307,
        311,
        313,
        317,
        331,
        337,
        347,
        349,
        353,
        359,
        367,
        373,
        379,
        383,
        389,
        397,
        401,
        409,
        419,
        421,
        431,
        433,
        439,
        443,
        449,
        457,
        461,
        463,
        467,
        479,
        487,
        491,
        499,
        503,
        509,
        521,
        523,
        541,
        547,
        557,
        563,
        569,
        571,
        577,
        587,
        593,
        599,
        601,
        607,
        613,
        617,
        619,
        631,
        641,
        643,
        647,
        653,
        659,
        661,
        673,
        677,
        683,
        691,
        701,
        709,
        719,
        727,
        733,
        739,
        743,
        751,
        757,
        761,
        769,
        773,
        787,
        797,
        809,
        811,
        821,
        823,
        827,
        829,
        839,
        853,
        857,
        859,
        863,
        877,
        881,
        883,
        887,
        907,
        911,
        919,
        929,
        937,
        941,
        947,
        953,
        967,
        971,
        977,
        983,
        991,
        997,
    ]

    # check if n is element of lowPrime-list
    if n in lowPrimes:
        return True

    for prime in lowPrimes:
        # check if any of the low prime numbers can divide n
        if n % prime == 0:
            return False

    # find the samlest exponent which needs to be checked by dividing by two as often as possible
    while exponent % 2 == 0:
        # divide exponent by two by shifting one bit to the right
        exponent >>= 1
        depth += 1

    # check prime k-times
    for _ in range(k):
        if mode_list is None:
            # draw random base
            base = randrange(2, n - 1)
        else:
            base = mode_list[_]
        # test prime drawn base
        if not check(base, depth, exponent, n):
            # return false if miller-rabin test proves that n isn't prime
            return False
    # after k-times retrun true if miller-rabin hasn't shown that n isn't prime
    return True
