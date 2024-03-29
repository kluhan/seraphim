"""
    Irreduzibilitätskriterien
    Implementiert wurden das Eisenstein- und das Perronkriterium
    Quellen:
        https://rms.unibuc.ro/bulletin/pdf/53-3/perron.pdf
        http://math-www.uni-paderborn.de/~chris/Index33/V/par5.pdf

    Übergeben werden Polynome vom Typ Polynomial, keine direkten Listen von Koeffizienten
"""
import logging
import helper
import itertools


def factor(n):
    # Faktorisierung einer Zahl n
    i = 0
    factors = []
    for i in range(1, n + 1):
        if n % i == 0:
            factors.append(i)

    return factors


def prime_factor(n):
    # Primfaktorzerlegung einer Zahl n
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)

    if n > 1:
        factors.append(n)
    return factors


# rekursive Implementierung von HCF
def hcf(x, y):
    """Highest common factor"""
    if y == 0:
        return x
    else:
        return hcf(y, x % y)


def is_polynomial_coprime(polynomial):
    """Überprüft, ob ein Polynom teilerfremd (coprime) ist"""
    non_zero_polynomial = [
        i for i in polynomial.coefficients if i != 0
    ]  # Nullen würden Ergebnis von HCF verfälschen

    if polynomial.degree() == 0:
        return True

    for x, y in itertools.combinations(non_zero_polynomial, 2):
        if hcf(x, y) != 1:
            return False

    return True


# Quelle: https://rms.unibuc.ro/bulletin/pdf/53-3/perron.pdf
def is_irreducible_perron(polynomial):
    """
    Prüft ein Polynom auf Irreduzierbarkeit (Perron).
    Führender Koeffizient != 1 funktioniert nicht.
    Keine Aussage möglich, wenn vorletzer Koeffizient kleiner ist als die absolute Summe der restlichen Koeffizienten
    """
    if polynomial.degree() < 0:
        return logging.error("Polynom ungültig")

    const_coefficient = polynomial.coefficients[0]
    if const_coefficient == 0:
        return 0

    lead_coefficient = polynomial.coefficients[polynomial.degree()]
    assert lead_coefficient == 1
    nm1_coefficient = abs(polynomial.coefficients[polynomial.degree() - 1])

    total = 1
    i = 0
    for coeff in polynomial.coefficients:
        if i < polynomial.degree() - 1:
            total += abs(coeff)
        i = i + 1

    if nm1_coefficient > total:
        return 1

    return 2


# Quellen: https://www.uni-frankfurt.de/81429607/Stix_Algebra_SkriptWS2016_17.pdf
# http://math-www.uni-paderborn.de/~chris/Index33/V/par5.pdf
def is_irreducible_eisenstein(polynomial):
    """
    Eine Implementierung des Eisensteinkriteriums.
    """
    # Polynom muss einen Grad m >= 1 haben
    if polynomial.degree() < 1:
        return 2

    # Voraussetzung für Eisenstein sind teilerfremde Koeffizienten
    if helper.is_polynomial_coprime(polynomial is False):
        return 2

    # Prüfe, ob es eine Primzahl gibt, die alle Koeffizienten des Polynoms bis Grad m - 1 teilt. p^2 darf a0 nicht teilen
    const_coeff = polynomial.coefficients[0]

    if const_coeff == 0:
        return 0

    # Erhalte Primfaktorzerlegung der Konstante, um Grundlage von Primzahlen zu erhalten
    prime_factors = helper.prime_factor(const_coeff)

    for p in prime_factors:

        if (
            const_coeff % pow(p, 2) != 0
        ):  # teilt p^2 den konstanten Koeffizienten, dann kann keine Aussage getroffen werden
            return 2

        for coeff in polynomial.coefficients[0 : polynomial.degree() - 1]:
            if coeff % p != 0:
                return 2  # teilt die Primzahl den Koeffizienten nicht, kann keine Aussage getroffen werden

    return 1
