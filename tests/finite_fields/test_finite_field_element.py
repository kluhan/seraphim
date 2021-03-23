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
        print(res.poly.coefficients)
        # check = numpy_z == poly3.coefficients
        # assert check.all()

    def test_finite_field_element_sub(self):
        res = self.ffe1 - self.ffe2
        print(res.poly.coefficients)
        # check = numpy_z == poly3.coefficients
        # assert check.all()

    def test_finite_field_element_mul(self):
        res = self.ffe1 * self.ffe2
        print(res.poly.cofficients)
        # check = numpy_z == poly3.coefficients
        # assert check.all()


x = TestFiniteFieldElement()
x.test_finite_field_element_add()
x.test_finite_field_element_sub()
x.test_finite_field_element_mul()