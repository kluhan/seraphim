import sys
import atheris
from tests.mod_arithmetic.test_bigNumbers import TestBigNumbers


def TestOneInput(data):
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


args = sys.argv
args.append("-runs=1000")
atheris.Setup(args, TestOneInput)
atheris.Fuzz()