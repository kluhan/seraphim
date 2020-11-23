import pytest
from primeGenerator import prime_generator

def test_PrimeGeneratorSize():
    for i in range(100):
        prime = next(prime_generator(256, 1))
        
        assert prime.bit_length() <= 256


