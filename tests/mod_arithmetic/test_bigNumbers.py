from secrets import randbits
from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.mod_arithmetics.primeGenerator import prime_generator


class TestBigNumbers:
    def test_restclass_add(self):
        primeGen = prime_generator(2048)
        base = next(primeGen)
        value = next(primeGen)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass + 4
        x = x + 4
        assert restclass_res.current_value == x

    def test_restclass_sub(self):
        base = prime_generator(4098)
        value = prime_generator(4098)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)

        restclass_res = restclass - 2
        assert restclass_res.current_value == 0

    def test_restclass_mul(self):
        base = prime_generator(4098)
        value = prime_generator(4098)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass * 15
        assert restclass_res.current_value == 0

    def test_restclass_pow(self):
        primeGen = prime_generator(2048)
        base = next(primeGen)
        value = next(primeGen)
        powpow = randbits(2 ** 16)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        restclass_res = restclass ** powpow
        x = x ** powpow
        assert restclass_res.current_value == x

    def test_restclass_truediv(self):
        base = prime_generator(4098)
        value = prime_generator(4098)
        restclass = RestclassEF(value, base)
        x = Mod(value, base)
        divider = restclass / prime_generator(4098)
        restclass_res = restclass // divider
        x = x // divider
        assert restclass_res.current_value == 1
