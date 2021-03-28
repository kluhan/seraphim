import sys
import atheris
from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import ModIsZeroError
from tests.mod_arithmetic.test_modularearythmetic_eff import TestModulareArythmeticEF


def test_restclass_add(base, value, var):
    try:
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass + var
        x = x + var
        print(restclass_res.current_value == x)
        assert restclass_res.current_value == x
    except ModIsZeroError:
        assert True


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

    base = fdp.ConsumeIntInRange(-(2 ** 12), (2 ** 12))
    value = fdp.ConsumeIntInRange(-(2 ** 12), (2 ** 12))
    var = fdp.ConsumeIntInRange(-(2 ** 12), (2 ** 12))
    test = TestModulareArythmeticEF()
    test.test_restclass_add(base, value, var)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
