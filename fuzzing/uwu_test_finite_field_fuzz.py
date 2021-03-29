import sys
import atheris
from tests.finite_fields.test_finite_field_element import TestFiniteFieldElement
from tests.finite_fields.test_polynomarithmetic import TestPolynomArithmetic
from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.finite_field import FF
from seraphim.finite_fields.finite_field_element import FFE
from seraphim.prime_generator.primeGenerator import prime_generator


class FiniteFieldElementFuzzing:
    def __setup_input_polynomarithmetic_fuzzing(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
        data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        size1 = fdp.ConsumeIntInRange(2, (2 ** 10))
        size2 = fdp.ConsumeIntInRange(2, (2 ** 10))
        coefficients1 = []
        coefficients2 = []

        for _ in range(size1):
            coefficients1.append(fdp.ConsumeIntInRange(-(2 ** 10), (2 ** 10)))

        for _ in range(size2):
            coefficients2.append(fdp.ConsumeIntInRange(-(2 ** 10), (2 ** 10)))

        poly1 = Polynomial(coefficients1)
        poly2 = Polynomial(coefficients2)

        test124 = TestPolynomArithmetic()
        test124.test_polynom_arithmetic_add(poly1, poly2)
        test124.test_polynom_arithmetic_degree(poly1)
        test124.test_polynom_arithmetic_derivate(poly1)
        test124.test_polynom_arithmetic_differentiate(poly1)
        test124.test_polynom_arithmetic_eq_false(poly1)
        test124.test_polynom_arithmetic_eq_true(poly1)
        test124.test_polynom_arithmetic_mod(poly1, poly2)
        test124.test_polynom_arithmetic_mul(poly1, poly2)
        # test124.test_polynom_arithmetic_ne_false(poly1)
        test124.test_polynom_arithmetic_ne_true(poly1)
        test124.test_polynom_arithmetic_neg(poly1)
        test124.test_polynom_arithmetic_pow(poly1, fdp.ConsumeIntInRange(1, (2 ** 10)))
        test124.test_polynom_arithmetic_sub(poly1, poly2)
        test124.test_polynom_arithmetic_truediv(poly1, poly2)

    def __setup_input_finite_field_fuzzing(self, data):
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
        value = fdp.ConsumeIntInRange(1, (2 ** 10))
        prime = next(prime_generator(fdp.ConsumeIntInRange(3, (2 ** 10))))
        ff = FF(value, prime)
        size1 = fdp.ConsumeIntInRange(2, (2 ** 10))
        size2 = fdp.ConsumeIntInRange(2, (2 ** 10))
        coefficients1 = []
        coefficients2 = []
        for _ in range(size1):
            coefficients1.append(fdp.ConsumeIntInRange(-(2 ** 10), (2 ** 10)))

        for _ in range(size2):
            coefficients2.append(fdp.ConsumeIntInRange(-(2 ** 10), (2 ** 10)))

        poly1 = Polynomial(coefficients1)
        poly2 = Polynomial(coefficients2)
        ffe1 = FFE(ff, poly1)
        ffe2 = FFE(ff, poly2)
        test124 = TestFiniteFieldElement()
        test124.test_finite_field_element_add(ffe1, ffe2)
        test124.test_finite_field_element_sub(ffe1, ffe2)
        test124.test_finite_field_element_mul(ffe1, ffe2)

    def test_finite_field_fuzzing(self):
        args = sys.argv
        args.append("-runs=1000")
        atheris.Setup(args, self.__setup_input_finite_field_fuzzing)
        atheris.Fuzz()

    def test_polynomarithmetic_fuzzing(self):
        args = sys.argv
        args.append("-runs=500")
        atheris.Setup(args, self.__setup_input_polynomarithmetic_fuzzing)
        atheris.Fuzz()
