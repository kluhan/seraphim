from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.polynomial import PolynomialModulo
from seraphim.mod_arithmetics.modulare_arithmetic_efficient import RestclassEfficient


class FiniteFieldElement(object):
    """
    Klasse für die Elemente in einem Endlichen Körper.
    Es wird der zugehörige endliche Körper der Klasse FiniteField mitgegeben und ein Polynom.
    Das Polynom kann entweder eine Liste an Koeffizienten sein oder vom Typ Polynomial.
    Das Polynom muss irreduzibel sein, es wird hier nicht überprüft, ob es sich um ein irreduzibles Polynom handelt.
    """

    def __init__(self, field, param):
        """Field vom Typ FiniteField, param kann verschiedene Typen annehmen: Polynomial, list[]"""
        self.field = field

        if isinstance(param, Polynomial):
            self.poly = PolynomialModulo(param.coefficients, self.field.p)
        elif isinstance(param, PolynomialModulo):
            self.poly = param
        elif isinstance(param, list):
            self.poly = PolynomialModulo(param, self.field.p)
        else:
            raise TypeError

        # while is_reducible(self.poly, self.field.p):
        #    self.poly = poly_ext_synth_division(self.poly, field.generator)

    def __str__(self):
        return "FiniteField(%s), Polynomial:%s" % (
            str(self.field),
            str(self.poly),
        )

    def __add__(self, other):
        assert self.field == other.field
        return FiniteFieldElement(self.field, self.poly + other.poly)

    def __sub__(self, other):
        assert self.field == other.field
        return FiniteFieldElement(self.field, self.poly - other.poly)

    def __mul__(self, other):
        assert self.field == other.field
        return FiniteFieldElement(self.field, self.poly * other.poly)

    def calculate(self, x):
        ret = RestclassEfficient(0, self.field.p)

        for n, a in enumerate(self.poly.coefficients):
            ret += a * x ** n

        return ret

    def getConstant(self):
        return self.poly.coefficients[0]

    def getLinear(self):
        return self.poly.coefficients[1]
