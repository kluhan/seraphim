import sys
import atheris
from tests.mod_arithmetic.test_bigNumbers import TestBigNumbers
from tests.mod_arithmetic.test_modularearythmetic_eff import TestModulareArythmeticEF


class ModArithmeticFuzzing:
    def __setup_input_modular_arithmetic(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
          data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        base = fdp.ConsumeIntInRange(1, (2 ** 10))
        value = fdp.ConsumeIntInRange(1, (2 ** 10))
        variable = fdp.ConsumeIntInRange(1, (2 ** 10))
        test124 = TestModulareArythmeticEF()
        test124.test_restclass_representative(base, value)
        test124.test_restclass_add(base, value, variable)
        test124.test_restclass_mul(base, value, variable)
        test124.test_restclass_pow(base, value, variable)
        test124.test_restclass_sub(base, value, variable)
        test124.test_restclass_truediv(base, value, variable)
        test124.test_restclass_eq(base, value)
        test124.test_restclass_geEqual(base, value)
        test124.test_restclass_leEqual(base, value)

    def test_modularearythmetic_eff_fuzzing(self):
        args = sys.argv
        args.append("-runs=10000")
        atheris.Setup(args, self.__setup_input_modular_arithmetic)
        atheris.Fuzz()

    def __setup_input_big_numbers(self, data):
        """The entry point for our fuzzer.
        This is a callback that will be repeatedly invoked with different arguments
        after Fuzz() is called.
        We translate the arbitrary byte string into a format our function being fuzzed
        can understand, then call it.
        Args:
          data: Bytestring coming from the fuzzing engine.
        """
        fdp = atheris.FuzzedDataProvider(data)
        size = fdp.ConsumeIntInRange(1, (2 ** 10))
        test124 = TestBigNumbers()
        test124.test_restclass_add(size)
        test124.test_restclass_sub(size)
        test124.test_restclass_mul(size)
        test124.test_restclass_pow(size)
        test124.test_restclass_truediv(size)

    def test_bigNumbers_fuzzing(self):
        args = sys.argv
        args.append("-runs=10000")
        atheris.Setup(args, self.__setup_input_big_numbers)
        atheris.Fuzz()