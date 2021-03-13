import itertools
import polynomial as poly


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


def factor(n):
    # Faktorisierung einer Zahl n
    i = 0
    factors = []
    for i in range(1, n + 1):
        if n % i == 0:
            factors.append(i)

    return factors


# https://www.inf.hs-flensburg.de/lang/krypto/algo/euklid.htm#section3
def ext_gcd(a, b):
    """Erweiterter euklidischer Algorithmus, kopiert"""
    if b == 0:
        return a, 1, 0
    else:
        g, u, v = ext_gcd(b, a % b)
        q = a // b
        return g, v, u - q * v


# rekursive Implementierung von HCF
def hcf(x, y):
    """Highest common factor"""
    if y == 0:
        return x
    else:
        return hcf(y, x % y)


def get_minimal_polynomial(p, n):
    """Hilfsfunktionen zu Polynomen

    Funktion zum Erstellen eines minimalen, irreduziblen Polynoms von Grad n und Konstante p: x^n + p"""
    polynomial = [p]
    while n > 1:
        polynomial.append(0)
        n = n - 1

    polynomial.append(1)

    return poly.Polynomial(polynomial)


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


def is_reducible(polynom, gen):
    zero = polynom - polynom
    for m in gen:
        if m.degree() > 0 and polynom % m == zero:
            return True, m
    return False


def zero_polynomial():
    return poly.Polynomial([])


poly1 = poly.Polynomial([4, 6, 8])
print(is_polynomial_coprime(poly1))

poly2 = poly.Polynomial([1, 3, 5, 11])
print(is_polynomial_coprime(poly2))
