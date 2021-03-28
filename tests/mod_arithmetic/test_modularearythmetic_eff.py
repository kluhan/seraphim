import pytest
from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import ModIsZeroError
from seraphim.util.extended_euclidean import InversionError


class TestModulareArythmeticEF:
    @pytest.fixture
    def value(self):
        return 5

    @pytest.fixture
    def mod(self):
        return 13

    @pytest.fixture
    def variable(self):
        return 9

    def test_restclass_representative(self, value, mod):
        restclass = RestclassEF(value, mod)
        erg = []
        for i in range(mod):
            erg.append(i)
        check = restclass.get_representative() == erg
        assert check

    def test_restclass_add(self, value, mod, variable):
        restclass = RestclassEF(value, mod)
        x = Mod(value, mod)
        restclass_res = restclass + variable
        x = x + variable
        assert restclass_res.current_value == x

    def test_restclass_sub(self, value, mod, variable):
        restclass = RestclassEF(value, mod)
        restclass_res = restclass - variable
        x = Mod(value, mod)
        x = x - variable
        assert restclass_res.current_value == x

    def test_restclass_mul(self, value, mod, variable):
        restclass = RestclassEF(value, mod)
        restclass_res = restclass * variable
        x = Mod(value, mod)
        x = x * variable
        assert restclass_res.current_value == x

    def test_restclass_pow(self, value, mod, variable):
        restclass = RestclassEF(value, mod)
        restclass_res = restclass ** variable
        x = Mod(value, mod)
        x = x ** variable
        assert restclass_res.current_value == x

    def test_restclass_truediv(self, value, mod, variable):
        try:
            restclass = RestclassEF(value, mod)
            restclass_res = restclass / variable
            x = Mod(value, mod)
            x = x // variable
            assert restclass_res.current_value == x
        except ModIsZeroError:
            assert True
        except InversionError:
            assert True
        except ValueError:
            assert True
        except ZeroDivisionError:
            assert True

    def test_restclass_lt(self, value, mod):
        restclass = RestclassEF(value - 1, mod)
        x = Mod(value, mod)
        restclass_res = restclass.current_value < x
        assert restclass_res

    def test_restclass_leEqual(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value, mod)
        restclass_res = restclass.current_value <= x
        assert restclass_res

    def test_restclass_leLess(self, value, mod):
        restclass = RestclassEF(value - 1, mod)
        x = Mod(value, mod)
        restclass_res = restclass.current_value <= x
        assert restclass_res

    def test_restclass_eq(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value, mod)
        restclass_res = restclass.current_value == x
        assert restclass_res

    def test_restclass_noteq(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value + (mod - 1), mod)
        restclass_res = restclass.current_value != x
        assert restclass_res

    def test_restclass_gt(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value - 1, mod)
        restclass_res = restclass.current_value > x
        assert restclass_res

    def test_restclass_geEqual(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value, mod)
        restclass_res = restclass.current_value >= x
        assert restclass_res

    def test_restclass_geGreater(self, value, mod):
        restclass = RestclassEF(value, mod)
        x = Mod(value - 1, mod)
        restclass_res = restclass.current_value >= x
        assert restclass_res
