from random import randrange
from secrets import randbits

def PrimeGenerator(size, accuracy=10):
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
    """

    def rabin_miler(n, k):
        """Checks if a given number is prime.

        Checks a given number k-times with the Rabin-Miller test

        Args:
            n: Number to be checked.
            k: How often the Rabbin-Miller test will be executed before returning True

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
            for i in range(depth - 1):

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
        for i in range(k):
            # draw random base
            base = randrange(2, n - 1)

            # test prime drawn base 
            if not check(base, depth, exponent, n):
                # return false if miller-rabin test proves that n isn't prime
                return False
        # after k-times retrun true if miller-rabin hasn't shown that n isn't prime  
        return True

    while True:
        # generates n crypto-secure random bits
        random_number = randbits(size)
         
        # checks if num is smaller than 2
        if (random_number < 5):
            # set num to a minimum of 3 
            random_number = 5

        # checks if num is odd
        if (not random_number & 1):
            # increase num by 1 to get odd number
            random_number += 1
        
        # Checks all odd numbers, starting with the generated random number, 
        # whether they are prime. Stops after the first prime is found.
        while True:
            if rabin_miler(random_number, accuracy):
                probable_prime = random_number 
                break

            random_number += 2

        if(probable_prime.bit_length() <= size):
            yield probable_prime

