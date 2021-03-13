from seraphim.finite_fields.polynomial import Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF


class PolynomialModulo(Polynomial):
    def __init__(self, coefficients, p):
        super().__init__(coefficients)
        i = 0
        count = len(coefficients)
        while i < count:
            self.coefficients[i] = RestclassEF(coefficients[i], p)
            i += 1
