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
