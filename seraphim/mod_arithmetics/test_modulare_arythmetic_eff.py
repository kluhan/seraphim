from mod import Mod
from seraphim import modulare_arythmetic_efficient

class TestRestclass():
    @classmethod
    def test_RestclassEF_add(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        x = Mod(5,13)
        restclass_res = restclass + 4
        x = x + 4
        assert restclass_res.current_value == x

    @classmethod
    def test_restclass_sub(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass - 2
        assert restclass_res.current_value == 1
       
    @classmethod 
    def test_restclass_mul(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass * 15
        assert restclass_res.current_value == 0

    @classmethod
    def test_restclass_pow(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass ** 3
        assert restclass_res.current_value == 2

    @classmethod
    def test_restclass_truediv(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass / 17
        assert restclass_res.current_value == 4

    @classmethod
    def test_restclass_lt(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass < 14
        assert restclass_res

    @classmethod
    def test_restclass_leE(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass <= 63
        assert restclass_res

    @classmethod
    def test_restclass_leL(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass <= 64
        assert restclass_res

    @classmethod
    def test_restclass_eq(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass == 33
        assert restclass_res

    @classmethod
    def test_restclass_ne(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass != 15
        assert restclass_res

    @classmethod
    def test_restclass_gt(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass > 15
        assert restclass_res

    @classmethod
    def test_restclass_geE(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass >= 3
        assert restclass_res

    @classmethod
    def test_restclass_geG(cls):
        restclass = modulare_arythmetic_efficient.RestclassEF(5,13)
        restclass_res = restclass >= 22
        assert restclass_res