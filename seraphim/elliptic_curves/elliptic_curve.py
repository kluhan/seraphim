from copy import copy
from seraphim.finite_fields.polynomial import PolynomialModulo, Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF



class PointsAreNotDistinct(Exception):
    """Addition is not possible if two points are not distinct"""

class EllipticCurve:
    
    def __init__(self, curve, mod, generator):
        self.curve = PolynomialModulo(curve,mod)
        self.generator = generator
        self.mod = mod

    def getPoint(self, x, y=None):
        return EllipticCurvePoint(self, x, y)


class EllipticCurvePoint:
    
    def __init__(self, ellipticCurve, x, y=None,):
        self.ellipticCurve = ellipticCurve
        self.x = x
        self.inf = False

        if y is not None:
            self.y = y
        else:
            self.y = self.ellipticCurve.curve.calculate(x).sqrt()

    def __copy__(self):
        return EllipticCurvePoint(self.ellipticCurve, self.x, self.y)

    def __add__(p, q):
        # (p.x,p.y) + (q.x, p.y) = (r.x, r.y)

        if p.inf and not q.inf: 
            return q

        if not p.inf and q.inf: 
            return p 

        if p == q:
            slope = ((3 * (p.x ** 2)) + p.ellipticCurve.getLinear())/(2 * p.y)
        else:    
            if p.x == q.x:
                p.inf = True
                p.x = None
                p.y = None
                print(str(p) + "+" + str(q) + "=" +str(result))
                return p 
            slope = (p.y - q.y)/(p.x - q.x)

        result_x = (slope ** 2) - p.x - q.x
        result_y = (slope * (p.x - result_x)) - p.y

        result = EllipticCurvePoint(p.ellipticCurve, result_x, result_y)
        print(str(p) + "+" + str(q) + "=" +str(result))
        return result

    def __mul__(self, multiplyer):
        print(str(self) + "*" + str(multiplyer))
        p = copy(self)
        for i in range(1, multiplyer):
            p = p + self
        
        return p 


    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y

    def __repr__(self):
        return "(" + str(self.x) + ", " + str(self.y) + ")"



curve = [
    0, #Constant
    1, #x^1
    486662, #x^2
    1, #x^3
]


curve = [
    1, #Constant
    1, #x^1
    0, #x^2
    1, #x^3
]


mod = (2 ** 255)-19

mod = 7


generator = 9
test_curve = EllipticCurve(curve, mod, generator)

point_1 = test_curve.getPoint(2)
print(point_1)
point_2 = test_curve.getPoint(0, 6)
print(point_2)
point_3 = point_1 + point_2
print(point_3)
point_4 = point_1 + point_1
print(point_4)
point_5 = point_1 * 19
print(point_5)