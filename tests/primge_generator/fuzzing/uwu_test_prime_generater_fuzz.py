import sys
import atheris
from seraphim.prime_generator.primeGenerator import prime_generator
from seraphim.util.fermat import fermat
from seraphim.util.millerRabin import miller_rabin


class PrimeGeneratorFuzzing:
    def test_prime_generator_fuzzing(self):
        args = sys.argv
        args.append("-runs=100")
        atheris.Setup(args, self.__setup_input_prime_generator)
        atheris.Fuzz()

    def __test_prime_fermat(self, prime, times_to_check):
        fermat_check = fermat(prime, times_to_check)
        assert fermat_check

    def __test_prime_millerRabin(self, prime, times_to_check):
        miller_rabin_check = miller_rabin(prime, times_to_check)
        assert miller_rabin_check

    def __test_prime_millerRabin_fermat(self, prime, times_to_check):
        fermat_check = fermat(prime, times_to_check)
        miller_rabin_check = miller_rabin(prime, times_to_check)
        assert miller_rabin_check and fermat_check

    def __setup_input_prime_generator(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
        data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)

        # generate prime
        prime_base = fdp.ConsumeIntInRange(2 ** 8, 2 ** 12)
        prime = next(prime_generator(prime_base, mode=2))
        times_to_check = fdp.ConsumeIntInRange(1, 10)
        self.__test_prime_fermat(prime, times_to_check)
        self.__test_prime_millerRabin(prime, times_to_check)
        self.__test_prime_millerRabin_fermat(prime, times_to_check)
