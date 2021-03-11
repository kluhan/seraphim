import copy


class Polynomial(object):
    """Klasse zur Darstellung von Polynomen in Form einer Koeffizientenliste aufsteigend von Grad 0 bis n"""

    def __init__(self, coefficients):
        self.coefficients = coefficients

    def _zero_(self):
        return self.coefficients[0] - self.coefficients[0]

    def degree(self):
        return len(self.coefficients) - 1

    def __neg__(self):
        return Polynomial([-c for c in self.coefficients])

    def __add__(self, other):
        result = []
        zero = self._zero_()

        max_iter = max(self.degree(), other.degree()) + 1
        i = 0

        # iteriere bis zu dem größten Element der Liste --> maximaler Grad + 1
        while i < max_iter:
            coef = self._zero_()
            # Überspringe Rechnung, falls der Grad des Polynoms unter der Iterationsnummer ist. Addiere ansonsten
            if i <= self.degree():
                coef = coef + self.coefficients[i]
            if i <= other.degree():
                coef = coef + other.coefficients[i]

            result.append(coef)
            i += 1

        return Polynomial(result)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, other):
        result = [0] * (len(self.coefficients) + len(other.coefficients) - 1)

        for i in range(len(self.coefficients)):
            for j in range(len(other.coefficients)):
                result[i + j] += self.coefficients[i] * other.coefficients[j]

        return Polynomial(result)

    def __pow__(self, i):
        return self.__smart_pow__(i)[0]

    # https://github.com/Glank/Galois
    def __smart_pow__(self, i, temp=None):
        assert i >= 1
        if temp is None:
            temp = {1: copy.deepcopy(self)}
        if i in temp:
            return temp[i], temp
        else:
            half = i // 2
            half_ = half + i % 2
            left, temp = self.__smart_pow__(half, temp=temp)
            temp[half] = left
            right, temp = self.__smart_pow__(half_, temp=temp)
            temp[half_] = right
            return left * right, temp

    def __str__(self):
        ret = ""
        for i in range(self.degree() + 1):
            if i != 0:
                ret += "+"
            ret += "%s*x^%d" % (str(self.coefficients[i]), i)

        ret = ret.replace("x^0", "1")
        ret = ret.replace("*1", "")
        ret = ret.replace("x^1", "x")
        ret = ret.replace("+-", "-")
        return ret

    # https://github.com/Glank/Galois
    def __divmod__(self, other):
        remainder = copy.deepcopy(self)
        zero = self._zero_()
        p_zero = Polynomial([zero])
        one = other.coefficients[-1] / other.coefficients[-1]
        if other == Polynomial([one]):
            return (self, Polynomial([zero]))
        x = Polynomial([zero, one])
        quotient = Polynomial([zero])
        while remainder != p_zero and remainder.degree() >= other.degree():
            r_lead = remainder.coefficients[-1]
            o_lead = other.coefficients[-1]
            q_part = Polynomial([r_lead / o_lead])
            q_deg = remainder.degree() - other.degree()
            if q_deg > 0:
                q_part *= x ** q_deg
            r_sub = other * q_part
            remainder -= r_sub
            quotient += q_part
        return (quotient, remainder)

    def __mod__(self, other):
        return divmod(self, other)[1]

    def __eq__(self, other):
        if self.degree() != other.degree():
            return False
        for s_c, o_c in zip(self.coefficients, other.coefficients):
            if s_c != o_c:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __div__(self, other):
        div, mod = divmod(self, other)
        assert mod == Polynomial([self._zero_()])
        return div

    def __truediv__(self, other):
        div, mod = divmod(self, other)
        assert mod == Polynomial([self._zero_()])
        return div

    def __floordiv__(self, other):
        return divmod(self, other)[0]

    def __repr__(self):
        return str(self)

    def differentiate(self):
        """Funktion zur Differenzierung des Polynoms"""
        for i in range(1, len(self.coefficients)):
            self.coeff[i - 1] = i * self.coeff[i]
        del self.coeff[-1]

    def deriviate(self):
        """Kopiere Polynom und gib Ableitung mittels differentiate() zurück"""
        poly_copy = Polynomial(self.coeff[:])
        poly_copy.differentiate()
        return poly_copy

    def calculate(self, x):
        ret = 0

        for n, a in enumerate(self.coefficients):
            ret += a * x ** n

        return ret


poly1 = Polynomial([1, 3, 6, 1])
print(poly1)

poly2 = Polynomial([2, 4, 5, 5, 3, 2, 0, 1])
print(poly2)

print(poly1 + poly2)

poly3 = Polynomial([1, 3, 2, 2])

poly4 = Polynomial([2, 0, 2, 1])

print(poly3 * poly4)
