from seraphim.prime_generator.primeGenerator import prime_generator


def test_PrimeGeneratorSize():
    for _ in range(100):
        prime = next(prime_generator(256, 1))
        assert prime.bit_length() <= 256
