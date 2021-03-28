import numpy as np
from seraphim.finite_fields.polynomial import Polynomial


class TestFiniteFieldElement:
    poly1 = Polynomial([1, 3, 2, 2])
    poly2 = Polynomial([2, 0, 2, 1])
    numpy_x = np.array([1, 3, 2, 2])
    numpy_y = np.array([2, 0, 2, 1])

    def test_finite_field_element_add(self):
        numpy_z = np.polyadd(self.numpy_x, self.numpy_y)
        poly3 = self.poly1 + self.poly2
        check = numpy_z == poly3.coefficients
        assert check.all()

    def test_finite_field_element_sub(self):
        poly3 = self.poly1 - self.poly2
        numpy_z = np.polysub(self.numpy_x, self.numpy_y)
        check = numpy_z == poly3.coefficients
        assert check.all()

    def test_finite_field_element_mul(self):
        poly3 = self.poly1 * self.poly2
        numpy_z = np.polymul(self.numpy_x, self.numpy_y)
        check = numpy_z == poly3.coefficients
        assert check.all()

    def test_finite_field_element_degree(self):
        x = np.array(list(reversed(self.poly1.coefficients)))
        y = self.poly1.degree()
        assert y == x.size - 1

    def test_finite_field_element_neg(self):
        x = np.array(self.poly1.coefficients)
        x = -x
        poly_tmp = -self.poly1
        check = x == poly_tmp.coefficients
        assert check.all()

    def test_finite_field_element_pow(self):
        x = np.array(list(reversed(self.poly1.coefficients)))
        x = np.polynomial.polynomial.polypow(x, 2)
        y = self.poly1 ** 2
        assert y.coefficients == list(reversed(x))

    def test_finite_field_element_eq_true(self):
        x = np.array(list(reversed(self.poly1.coefficients)))
        assert list(reversed(x)) == self.poly1.coefficients

    def test_finite_field_element_eq_false(self):
        tmp_array = list(reversed(self.poly1.coefficients))
        tmp_array.append(4)
        tmp_array.append(5)
        x = np.array(tmp_array)
        assert not (list(reversed(x)) == self.poly1.coefficients)

    def test_finite_field_element_ne_true(self):
        tmp_array = list(reversed(self.poly1.coefficients))
        tmp_array.append(4)
        tmp_array.append(5)
        x = np.array(tmp_array)
        assert list(reversed(x)) != self.poly1.coefficients

    def test_finite_field_element_ne_false(self):
        x = np.array([list(reversed(self.poly1.coefficients))])
        assert list(reversed(x)) != self.poly1.coefficients

    def test_finite_field_element_differentiate(self):
        x = np.array(list(reversed(self.poly1.coefficients)))
        x = np.polyder(x)
        y = self.poly1
        y.differentiate()
        check = x == list(reversed(y.coefficients))
        assert check.all()

    def test_finite_field_element_derivate(self):
        x = np.array(list(reversed(self.poly1.coefficients)))
        x = np.polyder(x)
        y = self.poly1.deriviate()
        check = x == list(reversed(y.coefficients))
        assert check.all()

    def test_finite_field_element_mod(self):
        poly_numpy_1 = np.array(list(reversed(self.poly1.coefficients)))
        poly_numpy_2 = np.array(list(reversed(self.poly2.coefficients)))
        remainder_self = self.poly1 % self.poly2
        quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
        assert remainder_self.coefficients == list(reversed(remainder_numpy))

    def test_finite_field_element_truediv(self):
        poly_numpy_1 = np.array(list(reversed(self.poly1.coefficients)))
        poly_numpy_2 = np.array(list(reversed(self.poly2.coefficients)))
        quotient_self = self.poly1 / self.poly2
        quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
        check_quotients = quotient_self.coefficients == list(reversed(quotient))
        assert check_quotients

    # def test_finite_field_element_floordiv(self):
    #    poly_1 = Polynomial([4, 9, 5, 4])
    #    poly_2 = Polynomial([1, 2])
    #    poly_numpy_1 = np.array([4, 5, 9, 4])
    #    poly_numpy_2 = np.array([2, 1])
    #    polydiv = poly_1 // poly_2
    #    quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
    #    check_quotients = polydiv.coefficients == list(reversed(quotient))
    #    assert check_quotients


# asdf = TestFiniteFieldElement()
# asdf.test_finite_field_element_degree()
# asdf.test_finite_field_element_neg()
# asdf.test_finite_field_element_derivate()
# asdf.test_finite_field_element_differentiate()
# asdf.test_finite_field_element_eq_false()
# asdf.test_finite_field_element_ne_false()
# asdf.test_finite_field_element_eq_true()
# asdf.test_finite_field_element_ne_true()
# asdf.test_finite_field_element_mod()
# asdf.test_finite_field_element_truediv()
