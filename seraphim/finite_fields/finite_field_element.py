import polynomial as polyn
from seraphim.finite_fields.poly_division import poly_ext_synth_division
from seraphim.finite_fields.helper import is_reducible


class FFE(object):
    """
    Klasse für die Elemente in einem Endlichen Körper.
    Es wird der zugehörige endliche Körper der Klasse FF mitgegeben und ein Polynom.
    Das Polynom kann entweder eine Liste an Koeffizienten sein oder vom Typ Polynomial.
    Das Polynom muss irreduzibel sein, es wird hier nicht überprüft, ob es sich um ein irreduzibles Polynom handelt.
    """

    def __init__(self, field, param):
        """Field vom Typ FF, param kann verschiedene Typen annehmen: Polynomial, list[]"""
        self.field = field
        print(f"SOME PARAMS YO {type(param)}")

        if isinstance(param, polyn.Polynomial):
            self.poly = polyn.PolynomialModulo(param.coefficients, self.field.p)
        elif isinstance(param, polyn.PolynomialModulo):
            self.poly = param
        elif isinstance(param, list):
            self.poly = polyn.PolynomialModulo(param, self.field.p)
        else:
            print("AN DIESE STELLE MUSS EINE TOLLE FEHLERMELDUNG HIN")
            assert ()

        while is_reducible(self.poly, self.field.p):
            self.poly = poly_ext_synth_division(self.poly, field.generator)

        self.p = self.field.p
        self.n = self.field.n

    def __str__(self):
        if isinstance(self.poly, polyn.Polynomial) or isinstance(
            self.poly, polyn.PolynomialModulo
        ):
            return "FF(%s,%s), Polynomial:%s" % (
                str(self.p),
                str(self.n),
                str(self.poly),
            )
        else:
            return "FFE(%s,%s)" % (str(self.p), str(self.n))

    def __add__(self, other):
        assert self.field == other.field
        return FFE(self.field, self.poly + other.poly)

    def __sub__(self, other):
        assert self.field == other.field
        return FFE(self.field, self.poly - other.poly)

    def __mul__(self, other):
        assert self.field == other.field
        return FFE(self.field, self.poly * other.poly)


# ff = finiteField.FF(17,6)
# ffe1 = FFE(ff, poly.Polynomial([1,5,11,4,13,2]))
# print("ffe1: ", ffe1)

# ffe2 = FFE(ff, [12,15,1,3,14,12])
# print("ffe2: ", ffe2)

# ffe3 = FFE(ff, None)
# print("ffe3: ", ffe3)

# print((ffe1 + ffe2).poly.coefficients)
# print((ffe1 - ffe2).poly.coefficients)
# print((ffe1 * ffe2).poly.coefficients)
