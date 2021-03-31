import sys
import secrets
import atheris
from tests.elliptic_curve.test_pointarithmetic import TestPointArithmetic
from tests.elliptic_curve.test_randomcurve import TestRandomCurve


class EllipticCurveFuzzing:
    def test_random_curve_fuzzing(self):
        args = sys.argv
        args.append("-runs=10000")
        atheris.Setup(args, self.__setup_input_random_curve)
        atheris.Fuzz()

    def test_point_arithmetic_projective_fuzzing(self):
        args = sys.argv
        args.append("-runs=10000")
        atheris.Setup(args, self.__setup_input_arithmetic_projective)
        atheris.Fuzz()

    def test_point_arithmetic_affine_fuzzing(self):
        args = sys.argv
        args.append("-runs=10000")
        atheris.Setup(args, self.__setup_input_arithmetic_affine)
        atheris.Fuzz()

    def __setup_input_arithmetic_projective(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
        data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        secret_alice_size = fdp.ConsumeIntInRange(32, 2 ** 6)
        secret_bob_size = fdp.ConsumeIntInRange(32, 2 ** 6)
        secret_alice = int(secrets.randbits(secret_alice_size))
        secret_bob = int(secrets.randbits(secret_bob_size))
        TestPointArithmetic().test_point_arithmetic_projective(secret_alice, secret_bob)

    def __setup_input_arithmetic_affine(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
        data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        secret_alice_size = fdp.ConsumeIntInRange(32, 2 ** 6)
        secret_bob_size = fdp.ConsumeIntInRange(32, 2 ** 6)
        secret_alice = int(secrets.randbits(secret_alice_size))
        secret_bob = int(secrets.randbits(secret_bob_size))
        TestPointArithmetic().test_point_arithmetic_affine(secret_alice, secret_bob)

    def __setup_input_arithmetic_curve(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
        data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        generator_size = fdp.ConsumeIntInRange(3, 2 ** 6)
        exponent_size = fdp.ConsumeIntInRange(2, 2 ** 6)
        prime_size = fdp.ConsumeIntInRange(3, 2 ** 8)
        test_test = TestRandomCurve()
        test_test.test_random_curve(generator_size, exponent_size, prime_size)


# PrimeGeneratorFuzzing().test_random_curve_fuzzing()
EllipticCurveFuzzing().test_point_arithmetic_projective_fuzzing()
EllipticCurveFuzzing().test_point_arithmetic_affine_fuzzing()
