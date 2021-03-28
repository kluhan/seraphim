import json 
from copy import copy
from seraphim.finite_fields.polynomial import PolynomialModulo, Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF

class EllipticCurvePoint:
    
    def __init__(self, ellipticCurve, x, y=None, inf=False):
        self.ellipticCurve = ellipticCurve
        self.x = x
        self.inf = inf

        if y is not None:
            self.y = y
        else:
            self.y = self.ellipticCurve.curve.calculate(x).sqrt()

    def __copy__(self):
        return EllipticCurvePoint(self.ellipticCurve, self.x, self.y)

    def __add__(p, q):
        # (p.x,p.y) + (q.x, p.y) = (r.x, r.y)

        if p.inf and not q.inf:
            #print(str(p) + "+" + str(q) + "=" + str(q)) 
            return q

        if not p.inf and q.inf:
            #print(str(p) + "+" + str(q) + "=" + str(p)) 
            return p 

        if p == q:
            slope = ((3 * (p.x ** 2)) + p.ellipticCurve.curve.getLinear())/(2 * p.y)

        else:    
            if int(p.x) == int(q.x):
                #print(str(p) + "+" + str(q) + "= INF")
                return EllipticCurvePoint(p.ellipticCurve, 0, 0, True) 
            slope = (p.y - q.y)/(p.x - q.x)

        result_x = (slope ** 2) - p.x - q.x
        result_y = (slope * (p.x - result_x)) - p.y

        result = EllipticCurvePoint(p.ellipticCurve, result_x, result_y)
        #print(str(p) + "+" + str(q) + "=" +str(result))
        return result

    def __mul__(point, factor):
        #print(str(point) + "*" + str(factor))

        factor_bin = str(bin(factor))[3:]
        result = copy(point)

        for i in factor_bin:
            result += result
            if i == "1":
                result += point
        return result

    def __eq__(self, other):
        return int(self.x) == int(other.x) and int(self.y) == int(other.y)

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y

    def __repr__(self):
        if self.inf:
            return "(INF, INF)"
        else:
            return "(" + str(self.x) + ", " + str(self.y) + ")"

    def serialize(self):
        elliptic_curve_point_dict = {
            "x": self.x.current_value,
            "y": self.y.current_value,
            "inf": self.inf,
        }

        return json.dumps(elliptic_curve_point_dict)

    @classmethod
    def deserialize(cls, curve, serialized):
        elliptic_curve_point_dict = json.loads(serialized)
        return cls(curve, elliptic_curve_point_dict['x'], y=elliptic_curve_point_dict['y'], inf=elliptic_curve_point_dict['inf'])
