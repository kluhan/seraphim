def Test_bigNumbers_fuzzing():
    args = sys.argv
    args.append("-runs=1000")
    atheris.Setup(args, TestOneTwo)
    atheris.Fuzz()


def Test_modularearythmetic_eff_fuzzing():
    args = sys.argv
    args.append("-runs=1000")
    atheris.Setup(args, TestOneInput)
    atheris.Fuzz()


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


def TestOneTwo(data):
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


Test_bigNumbers_fuzzing()
Test_modularearythmetic_eff_fuzzing()