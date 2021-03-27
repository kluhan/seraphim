import numpy as np
from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.poly_division import poly_ext_synth_division


class TestFiniteFieldElement:
    def test_poly_ext_synth_division(self):
        poly_1 = Polynomial([4, 9, 5, 4])
        poly_2 = Polynomial([1, 2])
        poly_numpy_1 = np.array([4, 5, 9, 4])
        poly_numpy_2 = np.array([2, 1])

        polydiv, remainder_self = poly_ext_synth_division(poly_1, poly_2)
        quotient, remainder_numpy = np.polydiv(poly_numpy_1, poly_numpy_2)
        check_quotients = list(reversed(polydiv.coefficients)) == quotient
        check_remainder = remainder_self.coefficients == remainder_numpy
        assert check_quotients.all() and check_remainder.all()
