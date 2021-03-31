from secrets import randbits
import pytest
from mod import Mod
from seraphim.mod_arithmetics.modulare_arithmetic_efficient import RestclassEfficient
from seraphim.mod_arithmetics.modulare_arithmetic_efficient import ModIsZeroError
from seraphim.util.extended_euclidean import InversionError

# 2 ** 14
class TestBigNumbers:
    @pytest.fixture
    def size(self):
        return 2 ** 12

    def test_restclass_add(self, size):
        try:
            base = randbits(size)
            value = randbits(size)
            add = randbits(size)
            restclass = RestclassEfficient(value, base)
            x = Mod(value, base)
            restclass_res = restclass + add
            x = x + add
            assert restclass_res.current_value == x
        except ModIsZeroError:
            assert True

    def test_restclass_sub(self, size):
        try:
            base = randbits(size)
            value = randbits(size)
            sub = randbits(size)
            restclass = RestclassEfficient(value, base)
            x = Mod(value, base)
            restclass_res = restclass - sub
            x = x - sub
            assert restclass_res.current_value == x
        except ModIsZeroError:
            assert True

    def test_restclass_mul(self, size):
        try:
            base = randbits(size)
            value = randbits(size)
            faktor = randbits(size)
            restclass = RestclassEfficient(value, base)
            x = Mod(value, base)
            restclass_res = restclass * faktor
            x = x * faktor
            assert restclass_res.current_value == x
        except ModIsZeroError:
            assert True

    def test_restclass_pow(self, size):
        try:
            base = randbits(size)
            value = randbits(size)
            power = randbits(size)
            restclass = RestclassEfficient(value, base)
            x = Mod(value, base)
            restclass_res = restclass ** power
            x = x ** power
            assert restclass_res.current_value == x
        except ModIsZeroError:
            assert True

    def test_restclass_truediv(self, size):
        try:
            base = randbits(size)
            value = randbits(size)
            divider = randbits(size)
            restclass = RestclassEfficient(value, base)
            x = Mod(value, base)
            restclass_res = restclass / divider
            y = x // divider
            assert restclass_res.current_value == y

        except ModIsZeroError:
            assert True
        except InversionError:
            assert True
        except ValueError:
            assert True
        except ZeroDivisionError:
            assert True

    # def test_restclass_truediv_broke(self):
    #    base = (2 ** 255) - 19  # randbits(self.size)
    #    py = RestclassEfficient(
    #        15278678023448118676834786174010220272456316670626470910400599246085451685119,
    #        base,
    #    )
    #    px = RestclassEfficient(
    #        10890237597772915387920653252329006178118543546739258841018607706089588874959,
    #        base,
    #    )
    #    qy = RestclassEfficient(
    #        14781619447589544791020593568409986887264606134616475288964881837755586237401,
    #        base,
    #    )
    #    qx = RestclassEfficient(9, base)
    #    x = (py - qy) / (px - qx)


xa = TestBigNumbers()
xa.test_restclass_truediv(4543)
