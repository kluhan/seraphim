from random import randrange
from seraphim.finite_fields.helper import get_minimal_polynomial
from seraphim.finite_fields.polynomial import Polynomial
from seraphim.finite_fields.finite_field_element import FFE


class FF(object):
    """
    Endlicher Körper der Form p^n. Optional kann ein Generator-Polynom übergeben werden.
    p ist der Modulus und die Charakteristik des Körpers und muss eine Primzahl sein
    n ist die Dimension und Exponent
    """

    def __init__(self, n, p, generator=None):
        assert p > 1
        assert n > 0

        self.p = p
        self.n = n

        if isinstance(generator, Polynomial):
            self.generator = generator
        else:
            self.generator = get_minimal_polynomial(p, n)

    def __str__(self):
        s = "FF(%s^%s)" % (str(self.p), str(self.n))
        s += "\n"
        s += "Erzeugerpolynom:\n"
        s += str(self.generator)
        return str(s)

    def generate_random_element(self, maxint=100):
        polynom = generate_random_polynomial(self.n, maxint)
        return FFE(self, polynom)


def generate_random_polynomial(degree, maxint=100, mod=True):
    coef = []

    for i in range(0, degree):
        val = randrange(maxint)
        if mod is True:
            coef.append(val % degree)
        else:
            coef.append(val)
    coef.append(1)
    return Polynomial(coef)


