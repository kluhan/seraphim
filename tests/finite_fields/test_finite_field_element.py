import pytest
import numpy as np

from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.finite_field import FF
from seraphim.finite_fields.finite_field_element import FFE


class TestFiniteFieldElement:
    @pytest.fixture
    def ff(self):
        return FF(17, 6)

    @pytest.fixture
    def ffe1(self, ff):
        poly1 = Polynomial([10, 15, 20, 25])
        return FFE(ff, poly1)

    @pytest.fixture
    def ffe2(self, ff):
        poly2 = Polynomial([7, 14, 21, 28])
        return FFE(ff, poly2)

    def test_finite_field_element_add(self, ffe1, ffe2):
        np_x = np.array(list(reversed(ffe1.poly.coefficients)))
        np_y = np.array(list(reversed(ffe2.poly.coefficients)))
        res = ffe1 + ffe2
        numpy_z = np.polyadd(np_x, np_y)
        check = res.poly.coefficients == list(reversed(numpy_z))
        assert check

    def test_finite_field_element_sub(self, ffe1, ffe2):
        res = ffe1 - ffe2
        np_x = np.array(list(reversed(ffe1.poly.coefficients)))
        np_y = np.array(list(reversed(ffe2.poly.coefficients)))
        numpy_z = np.polysub(np_x, np_y)
        check = res.poly.coefficients == list(reversed(numpy_z))
        assert check

    def test_finite_field_element_mul(self, ffe1, ffe2):
        res = ffe1 * ffe2
        np_x = np.array(list(reversed(ffe1.poly.coefficients)))
        np_y = np.array(list(reversed(ffe2.poly.coefficients)))
        numpy_z = np.polymul(np_x, np_y)
        check = res.poly.coefficients == list(reversed(numpy_z))
        assert check


# asdfasdf = TestFiniteFieldElement()
# poly1 = Polynomial([10, 15, 20, 25])
# ff = FF(6, 17)
# ffe1 = FFE(ff, poly1)
# poly2 = Polynomial([7, 14, 21, 28])
# ffe2 = FFE(ff, poly2)
# asdfasdf.test_finite_field_element_add(ffe1, ffe2)
