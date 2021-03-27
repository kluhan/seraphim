import numpy as np
from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.finite_field import FF
from seraphim.finite_fields.finite_field_element import FFE


class TestFiniteFieldElement:
    poly1 = Polynomial([10, 15, 20, 25])
    poly2 = Polynomial([7, 14, 21, 28])
    ff = FF(17, 6)
    ffe1 = FFE(ff, poly1)
    ffe2 = FFE(ff, poly2)

    def test_finite_field_element_add(self):
        res = self.ffe1 + self.ffe2
        numpy_z = np.polyadd(self.ffe1.poly.coefficients, self.ffe2.poly.coefficients)
        check = res.poly.coefficients == numpy_z
        assert check.all()

    def test_finite_field_element_sub(self):
        res = self.ffe1 - self.ffe2
        numpy_z = np.polysub(self.ffe1.poly.coefficients, self.ffe2.poly.coefficients)
        check = res.poly.coefficients == numpy_z
        assert check.all()

    def test_finite_field_element_mul(self):
        res = self.ffe1 * self.ffe2
        numpy_z = np.polymul(self.ffe1.poly.coefficients, self.ffe2.poly.coefficients)
        check = res.poly.coefficients == numpy_z
        assert check.all()