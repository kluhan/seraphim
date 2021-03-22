from random import randrange
import helper
import polynomial as polyn
import finite_field_element


class FF(object):
    """
    Endlicher Körper der Form p^n. Optional kann ein Generator-Polynom übergeben werden.
    p ist der Modulus und die Charakteristik des Körpers und muss eine Primzahl sein
    n ist die Dimension und Exponent
    """

    def __init__(self, p, n, generator=None):
        assert p > 1
        assert n > 0

        self.p = p
        self.n = n

        if isinstance(generator, polyn.Polynomial):
            self.generator = generator
        else:
            self.generator = helper.get_minimal_polynomial(p, n)

    def __str__(self):
        s = "FF(%s^%s)" % (str(self.p), str(self.n))
        s += "\n"
        s += "Erzeugerpolynom:\n"
        s += str(self.generator)
        return str(s)

    def generate_random_element(self, maxint=100):
        polynom = generate_random_polynomial(self.n, maxint)
        return finite_field_element.FFE(self, polynom)


def generate_random_polynomial(degree, maxint=100, mod=True):
    coef = []

    for i in range(0, degree):
        val = randrange(maxint)
        if mod is True:
            coef.append(val % degree)
        else:
            coef.append(val)
    coef.append(1)
    return polyn.Polynomial(coef)


ff1 = FF(5, 2)
print(ff1)
poly = polyn.Polynomial([1, 1, 1, 1, 1, 1, 1])
ff2 = FF(17, 6, poly)
print(ff2)
ff1_random_element = ff1.generate_random_element(40)
print("Zufallselement: ", ff1_random_element)
p1 = generate_random_polynomial(7, 100, False)
print("P1: ", p1.coefficients)
p2 = generate_random_polynomial(7, 100, True)
print("P2: ", p2.coefficients)
