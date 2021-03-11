from secrets import randbits
from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF


class TestBigNumbers:
    size = 2 ** 13

    def test_restclass_add(self):
        base = randbits(self.size)
        value = randbits(self.size)
        add = randbits(self.size)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass + add
        x = x + add
        assert restclass_res.current_value == x

    def test_restclass_sub(self):
        base = randbits(self.size)
        value = randbits(self.size)
        sub = randbits(self.size)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass - sub
        x = x - sub
        assert restclass_res.current_value == x

    def test_restclass_mul(self):
        base = randbits(self.size)
        value = randbits(self.size)
        faktor = randbits(self.size)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass * faktor
        x = x * faktor
        assert restclass_res.current_value == x

    def test_restclass_pow(self):
        base = randbits(self.size)
        value = randbits(self.size)
        power = randbits(self.size)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass ** power
        x = x ** power
        assert restclass_res.current_value == x

    def test_restclass_truediv(self):
        base = randbits(self.size)
        value = randbits(self.size)
        divider = randbits(self.size)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass / divider
        x = x // divider
        assert restclass_res.current_value == x
