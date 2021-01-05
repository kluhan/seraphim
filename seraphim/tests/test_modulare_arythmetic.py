from modarythmetic import modulare_arythmetic

class TestRestclass():

    @classmethod
    def test_Restclassef_add(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass + 4
        assert restclass_res.current_value == 2

    @classmethod
    def test_Restclass_sub(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass - 2
        assert restclass_res.current_value == 1

    @classmethod
    def test_Restclass_mul(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass * 15
        assert restclass_res.current_value == 0

    @classmethod
    def test_Restclass_pow(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass ** 3
        assert restclass_res.current_value == 2

    @classmethod
    def test_Restclass_truediv(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass / 17
        assert restclass_res.current_value == 4

    @classmethod
    def test_Restclass_lt(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass < 14
        assert restclass_res

    @classmethod
    def test_Restclass_leE(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass <= 63
        assert restclass_res
		
    @classmethod
    def test_Restclass_leL(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass <= 64
        assert restclass_res

    @classmethod
    def test_Restclass_eq(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass == 33
        assert restclass_res

    @classmethod
    def test_Restclass_ne(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass != 15
        assert restclass_res

    @classmethod
    def test_Restclass_gt(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass > 15
        assert restclass_res

    @classmethod
    def test_Restclass_geE(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass >= 3
        assert restclass_res

    @classmethod
    def test_Restclass_geG(cls):
        restclass = modulare_arythmetic.Restclass(5,13)
        restclass_res = restclass >= 22
        assert restclass_res

