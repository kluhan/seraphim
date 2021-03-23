from mod import Mod
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF


class TestFiniteFieldElement:
    def test_restclass_add(self):
        restclass = RestclassEF(5, 13)
        x = Mod(5, 13)
        restclass_res = restclass + 4
        x = x + 4
        assert restclass_res.current_value == x


# ff = finiteField.FF(17,6)
# ffe1 = FFE(ff, poly.Polynomial([1,5,11,4,13,2]))
# print("ffe1: ", ffe1)

# ffe2 = FFE(ff, [12,15,1,3,14,12])
# print("ffe2: ", ffe2)

# ffe3 = FFE(ff, None)
# print("ffe3: ", ffe3)

# print((ffe1 + ffe2).poly.coefficients)
# print((ffe1 - ffe2).poly.coefficients)
# print((ffe1 * ffe2).poly.coefficients)