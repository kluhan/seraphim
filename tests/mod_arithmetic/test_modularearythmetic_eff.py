from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF


class TestModulareArythmeticEF:
    def test_restclass_add(self):
        restclass = RestclassEF(5, 13)
        x = Mod(5, 13)
        restclass_res = restclass + 4
        x = x + 4
        assert restclass_res.current_value == x

    def test_restclass_sub(self):
        restclass = RestclassEF(5, 13)
        restclass_res = restclass - 4
        x = Mod(5, 13)
        x = x - 4
        assert restclass_res.current_value == x

    def test_restclass_mul(self):
        restclass = RestclassEF(5, 13)
        restclass_res = restclass * 15
        x = Mod(5, 13)
        x = x * 15
        assert restclass_res.current_value == x

    def test_restclass_pow(self):
        restclass = RestclassEF(5, 13)
        restclass_res = restclass ** 3
        x = Mod(5, 13)
        x = x ** 3
        assert restclass_res.current_value == x

    def test_restclass_truediv(self):
        restclass = RestclassEF(5, 13)
        restclass_res = restclass / 25
        x = Mod(5, 13)
        x = x // 25
        assert restclass_res.current_value == x

    def test_restclass_lt(self):
        restclass = RestclassEF(5, 13)
        x = Mod(33, 13)
        restclass_res = restclass.current_value < x
        assert restclass_res

    def test_restclass_leEqual(self):
        restclass = RestclassEF(5, 13)
        x = Mod(5, 13)
        restclass_res = restclass.current_value <= x
        assert restclass_res

    def test_restclass_leLess(self):
        restclass = RestclassEF(5, 13)
        x = Mod(34, 13)
        restclass_res = restclass.current_value <= x
        assert restclass_res

    def test_restclass_eq(self):
        restclass = RestclassEF(5, 13)
        x = Mod(5, 13)
        restclass_res = restclass.current_value == x
        assert restclass_res

    def test_restclass_noteq(self):
        restclass = RestclassEF(5, 13)
        x = Mod(19, 13)
        restclass_res = restclass.current_value != x
        assert restclass_res

    def test_restclass_gt(self):
        restclass = RestclassEF(5, 13)
        x = Mod(2, 13)
        restclass_res = restclass.current_value > x
        assert restclass_res

    def test_restclass_geEqual(self):
        restclass = RestclassEF(5, 13)
        x = Mod(5, 13)
        restclass_res = restclass.current_value >= x
        assert restclass_res

    def test_restclass_geGreater(self):
        restclass = RestclassEF(5, 13)
        x = Mod(57, 13)
        restclass_res = restclass.current_value >= x
        assert restclass_res
