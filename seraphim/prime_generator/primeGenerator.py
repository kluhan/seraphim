from secrets import randbits
import miller_rabin as miller_rabin_reference
from seraphim.util.millerRabin import miller_rabin
from seraphim.util.fermat import fermat


def prime_generator(size, accuracy=10, mode=1):
    """
    Class to generate primes

    Class to generate random primes of a given length. Implementation is based on bnlucas solution from 25.6.2013 which was postet on Stackoverflow.
    The original implementation can be found under https://stackoverflow.com/questions/17298130/working-with-large-primes-in-python

    Args:
    size: size of random prime.
    accuracy: Optional; probability for composite numbers to be assumed to be prime.
        The passed number is used as negative exponent to the base of 4 to compute
        the needed accuracy. For example:

        1 => 4^-1 = 0.25
        2 => 4^-2 = 0.0625
        4 => 4^-4 = 0.00390625
        8 => 4^-8 = 0.00000152588
    mode: determines the test to test primality with
        0 => fermat
        1 => miller_rabin
        2 => miller_rabin_reference
    """

    if mode == 0:
        primalityTest = fermat
    elif mode == 1:
        primalityTest = miller_rabin
    elif mode == 2:
        primalityTest = miller_rabin_reference.miller_rabin

    while True:
        assert size > 2

        # generates n crypto-secure random bits
        random_number = randbits(size)

        # checks if num is smaller than 2
        if random_number < 5:
            # set num to a minimum of 3
            random_number = 5

        # checks if num is odd
        if not random_number & 1:
            # increase num by 1 to get odd number
            random_number += 1

        # Checks all odd numbers, starting with the generated random number,
        # whether they are prime. Stops after the first prime is found.
        while True:
            if primalityTest(random_number, accuracy):
                probable_prime = random_number
                break

            random_number += 2

        if probable_prime.bit_length() <= size:
            yield probable_prime
