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

    def __add__(p, q):
        if p == q:
            if p.y == 0:
                return EllipticCurvePointProjective(p.ellipticCurve, 0, inf=True)
            else:
                W = ( p.ellipticCurve.curve.getLinear() * (p.z ** 2) ) + ( 3 * (p.x ** 2) )
                S = p.y * p.z
                B = p.x * p.y * S
                H = W ** 2 - 8 * B
                x_new = 2 * H * S
                y_new = W * ( 4 * B - H) - 8 * p.y ** 2 * S ** 2
                z_new = 8 * S ** 3 

                return EllipticCurvePointProjective(p.ellipticCurve, x_new, y=y_new, z=z_new)

        else:    
            U1 = q.y * p.z
            U2 = p.y * q.z
            V1 = q.x * p.z
            V2 = p.x * q.z

            if(V1 == V2):
                if(U1 != U2):
                    return EllipticCurvePointProjective(p.ellipticCurve, 0, inf=True)
                else:
                    return p + p 
            U = U1 - U2
            V = V1 - V2
            W = p.z * q.z 
            A = U ** 2 * W - V ** 3 - 2 * V ** 2 * V2
            x_new = V * A
            y_new = U * ( V ** 2 * V2 - A) - V ** 3 * U2
            z_new = V ** 3 * W

            return EllipticCurvePointProjective(p.ellipticCurve, x_new, y=y_new, z=z_new)




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
        return super().__eq__(other) and self.z == other.z

    def __ne__(self, other):
        return super().__ne__(other) or self.z != other.z

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

