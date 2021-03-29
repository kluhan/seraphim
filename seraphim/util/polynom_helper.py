from seraphim.finite_fields.polynomial import Polynomial


def get_minimal_polynomial(p, n):
    """Hilfsfunktionen zu Polynomen

    Funktion zum Erstellen eines minimalen, irreduziblen Polynoms von Grad n und Konstante p: x^n + p"""
    polynom = [p]
    while n > 1:
        polynom.append(0)
        n = n - 1

    polynom.append(1)

    return Polynomial(polynom)