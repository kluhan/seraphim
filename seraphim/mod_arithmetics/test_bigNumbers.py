from seraphim import modulare_arythmetic_efficient as modulare_arythmetic_efficient

class TestRestclass():
      
    @classmethod 
    def test_RestclassEF_add(cls):
        base = 17
        value = 10
        restclass = modulare_arythmetic_efficient.RestclassEF(base,value)
        restclass_res = restclass + 4
        assert restclass_res.current_value == 2

    @classmethod
    def test_restclass_sub(cls):
        base = 17
        value = 10
        restclass = modulare_arythmetic_efficient.RestclassEF(base,value)
        restclass_res = restclass - 2
        assert restclass_res.current_value == 1

    @classmethod
    def test_restclass_mul(cls):
        base = 17
        value = 10
        restclass = modulare_arythmetic_efficient.RestclassEF(base,value)
        restclass_res = restclass * 15
        assert restclass_res.current_value == 0

    @classmethod
    def test_restclass_pow(cls):
        base = 17
        value = 10
        restclass = modulare_arythmetic_efficient.RestclassEF(base,value)
        restclass_res = restclass ** 3
        assert restclass_res.current_value == 2

    @classmethod
    def test_restclass_truediv(cls):
        base = 17
        value = 10
        restclass = modulare_arythmetic_efficient.RestclassEF(base,value)
        restclass_res = restclass / 17
        assert restclass_res.current_value == 4

