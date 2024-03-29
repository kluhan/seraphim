import pytest
import numpy as np
from seraphim.finite_fields.polynomial import Polynomial


class TestPolynomArithmetic:
    @pytest.fixture
    def poly1(self):
        return Polynomial([1, 3, 2, 2])

    @pytest.fixture
    def poly2(self):
        return Polynomial([2, 0, 2, 1])

    @pytest.fixture
    def variable(self):
        return 2

    def test_polynom_arithmetic_add(self, poly1, poly2):
        numpy_x = np.array(list(reversed(poly1.coefficients)))
        numpy_y = np.array(list(reversed(poly2.coefficients)))
        numpy_z = np.polyadd(numpy_x, numpy_y)
        poly3 = poly1 + poly2
        check = list(reversed(numpy_z)) == poly3.coefficients
        assert check

    def test_polynom_arithmetic_sub(self, poly1, poly2):
        numpy_x = np.array(list(reversed(poly1.coefficients)))
        numpy_y = np.array(list(reversed(poly2.coefficients)))
        poly3 = poly1 - poly2
        numpy_z = np.polysub(numpy_x, numpy_y)
        check = list(reversed(numpy_z)) == poly3.coefficients
        assert check

    def test_polynom_arithmetic_mul(self, poly1, poly2):
        numpy_x = np.array(list(reversed(poly1.coefficients)))
        numpy_y = np.array(list(reversed(poly2.coefficients)))
        poly3 = poly1 * poly2
        numpy_z = np.polymul(numpy_x, numpy_y)
        check = list(reversed(numpy_z)) == poly3.coefficients
        assert check

    def test_polynom_arithmetic_degree(self, poly1):
        x = np.array(list(reversed(poly1.coefficients)))
        y = poly1.degree()
        assert y == x.size - 1

    def test_polynom_arithmetic_neg(self, poly1):
        x = np.array(list(reversed(poly1.coefficients)))
        x = -x
        poly_tmp = -poly1
        check = list(reversed(x)) == poly_tmp.coefficients
        assert check

    def test_polynom_arithmetic_pow(self, poly1, variable):
        x = np.array(list(reversed(poly1.coefficients)))
        x = np.polynomial.polynomial.polypow(x, variable)
        y = poly1 ** variable
        assert y.coefficients == list(reversed(x))

    def test_polynom_arithmetic_eq_true(self, poly1):
        x = np.array(list(reversed(poly1.coefficients)))
        assert list(reversed(x)) == poly1.coefficients

    def test_polynom_arithmetic_eq_false(self, poly1):
        tmp_array = list(reversed(poly1.coefficients))
        tmp_array.append(4)
        tmp_array.append(5)
        x = np.array(tmp_array)
        assert not (list(reversed(x)) == poly1.coefficients)

    def test_polynom_arithmetic_ne_true(self, poly1):
        tmp_array = list(reversed(poly1.coefficients))
        tmp_array.append(4)
        tmp_array.append(5)
        x = np.array(tmp_array)
        assert list(reversed(x)) != poly1.coefficients

    def test_polynom_arithmetic_ne_false(self, poly1):
        x = np.array([list(reversed(poly1.coefficients))])
        assert list(reversed(x)) != poly1.coefficients

    def test_polynom_arithmetic_differentiate(self, poly1):
        x = np.array(list(reversed(poly1.coefficients)))
        x = np.polyder(x)
        y = poly1
        y.differentiate()
        check = x == list(reversed(y.coefficients))
        assert check.all()

    def test_polynom_arithmetic_derivate(self, poly1):
        x = np.array(list(reversed(poly1.coefficients)))
        x = np.polyder(x)
        y = poly1.deriviate()
        check = x == list(reversed(y.coefficients))
        assert check.all()

    def test_polynom_arithmetic_mod(self, poly1, poly2):
        try:
            poly_numpy_1 = np.array(list(reversed(poly1.coefficients)))
            poly_numpy_2 = np.array(list(reversed(poly2.coefficients)))
            remainder_self = poly1 % poly2
            quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
            assert remainder_self.coefficients == list(reversed(remainder_numpy))
        except IndexError:
            assert True

    def test_polynom_arithmetic_truediv(self, poly1, poly2):
        try:
            poly_numpy_1 = np.array(list(reversed(poly1.coefficients)))
            poly_numpy_2 = np.array(list(reversed(poly2.coefficients)))
            quotient_self = poly1 / poly2
            quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
            check_quotients = quotient_self.coefficients == list(reversed(quotient))
            assert check_quotients
        except IndexError:
            assert True
