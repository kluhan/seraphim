from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF


class TestBigNumbers:
    def test_restclass_add(self):
        base = 5
        value = 27
        restclass = RestclassEF(value, base)
        restclass_res = restclass + 4
        assert restclass_res.current_value == 1

    def test_restclass_sub(self):
        base = 5
        value = 27
        restclass = RestclassEF(value, base)
        restclass_res = restclass - 2
        assert restclass_res.current_value == 0

    def test_restclass_mul(self):
        base = 5
        value = 27
        restclass = RestclassEF(value, base)
        restclass_res = restclass * 15
        assert restclass_res.current_value == 0

    def test_restclass_pow(self):
        base = 5
        value = 27
        restclass = RestclassEF(value, base)
        restclass_res = restclass ** 3
        assert restclass_res.current_value == 3

    def test_restclass_truediv(self):
        base = 5
        value = 27
        restclass = RestclassEF(value, base)
        restclass_res = restclass / 17
        assert restclass_res.current_value == 1
