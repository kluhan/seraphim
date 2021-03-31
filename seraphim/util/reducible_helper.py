from seraphim.finite_fields.polynomial import Polynomial
from seraphim.mod_arithmetics.modulare_arithmetic_efficient import RestclassEfficient


def is_reducible(polynom, p):
    intmod = RestclassEfficient(1, p).get_representative()

    zmodx = [Polynomial(list(reversed(x))) for x in intmod]

    zero = polynom - polynom
    for m in zmodx:
        if m.deg() > 0 and polynom % m == zero:
            return True, m
    return False
