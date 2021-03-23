from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.poly_division import poly_ext_synth_division
import numpy as np


class TestFiniteFieldElement:
    def test_poly_ext_synth_division(self):
        polydiv1 = Polynomial([4, 9, 5, 4])
        polydiv2 = Polynomial([1, 2])
        print("polydiv1: ", polydiv1)
        print("polydiv2: ", polydiv2)

        y = np.array([4, 9, 5, 4])
        x = np.array([1, 2])
        print("numpy_polydiv1: ", y)
        print("numpy_polydiv2: ", x)

        polydiv, remainder = poly_ext_synth_division(polydiv1, polydiv2)
        print("polydiv:", polydiv)
        print("remainder:", remainder)

        quotient, remainder = np.polydiv(y, x)
        print("numpy_polydiv:", quotient)
        print("numpy_remainder:", remainder)


x = TestFiniteFieldElement()
x.test_poly_ext_synth_division()


# Defining ndarray
