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


class EllipticCurvePointProjective(EllipticCurvePoint):
    
    def __init__(self, ellipticCurve, x, y=None, z=1, inf=False):
        super().__init__(ellipticCurve, x, y, inf)
        self.z = z


    def __copy__(self):
        return EllipticCurvePointProjective(self.ellipticCurve, self.x, self.y)


    def __add__(self, other):

        if self.x == 0:
            return other
        elif other.x == 0:
            return self
        
        t0 = self.y * other.z
        t1 = other.y * self.z
        u0 = self.x * other.z
        u1 = other.x * self.z

        if u0 == u1:
            if t0 == t1:
                return self.double()
            else:
                return EllipticCurvePointProjective(self.ellipticCurve, 0, inf=True)
        else:
            t = t0 - t1
            u = u0 - u1
            u2 = u * u
            v = self.z * other.z
            w = t * t * v - u2 * (u0 + u1)
            u3 = u * u2
            rx = u * w
            ry = t * (u0 * u2 - w) - t0 * u3
            rz = u3 * v
            
            return EllipticCurvePointProjective(self.ellipticCurve, rx, y=ry, z=rz)
    
    
    def double(self):
        if self.x == 0 or self.y == 0:
            return EllipticCurvePointProjective(self.ellipticCurve, 0, inf=True)
        else:
            t = self.x * self.x * 3 + self.ellipticCurve.curve.getLinear() * self.z * self.z
            u = self.y * self.z * 2
            v = u * self.x * self.y * 2
            w = t * t - v * 2
            rx = u * w
            ry = t * (v - w) - u * u * self.y * self.y * 2
            rz = u * u * u
            return EllipticCurvePointProjective(self.ellipticCurve, rx, y=ry, z=rz)

    def __mul__(point, factor):
        if not isinstance(factor, int):
            raise TypeError("Expected integer")
        if factor < 0:
            return -point * -n
        result = EllipticCurvePointProjective(point.ellipticCurve, 0, 0, 0)
        temp = point
        while factor != 0:
            if factor & 1 != 0:
                result += temp
            temp = temp.double()
            factor >>= 1
        return result

    def __eq__(self, other):
        if self.x or other.x:
            return self.x and other.x
        else:
            return (self.x * other.z, self.y * other.z ) == (other.x * self.z, other.y * self.z)
    
    def __ne__(self, other):
        return not (self == other)


    def __repr__(self):
        if self.inf:
            return "(INF, INF, INF)"
        else:
            return "(" + str(self.x) + ", " + str(self.y) + ", " + str(self.z) + ")"

    def to_affine(self):
        x = self.x / self.z
        y = self.y / self.z
        return EllipticCurvePoint(self.ellipticCurve, x, y=y)

    def serialize(self):
        affine_point = super.serialize(self.to_affine)
        
        return json.dumps(affine_point)

    @classmethod
    def deserialize(cls, curve, serialized):
        elliptic_curve_point_dict = json.loads(serialized)
        return cls(curve, elliptic_curve_point_dict['x'], y=elliptic_curve_point_dict['y'], inf=elliptic_curve_point_dict['inf'])

