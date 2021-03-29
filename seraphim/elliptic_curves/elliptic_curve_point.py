import json
from copy import copy


class CurvePoint:
    def __copy__(self):
        raise NotImplementedError("subclasses must override __copy__()!")

    def __add__(self, other):
        raise NotImplementedError("subclasses must override __add__()!")

    def __mul__(self, other):
        raise NotImplementedError("subclasses must override __mul__()!")

    def __eq__(self, other):
        raise NotImplementedError("subclasses must override __eq__()!")

    def __ne__(self, other):
        raise NotImplementedError("subclasses must override __ne__()!")

    def __repr__(self):
        raise NotImplementedError("subclasses must override __repr__()!")

    def serialize(self):
        raise NotImplementedError("subclasses must override serialize()!")

    def to_secrect(self):
        raise NotImplementedError("subclasses must override to_secret()!")

    @classmethod
    def deserialize(cls, curve, serialized):
        raise NotImplementedError("subclasses must override deserialize()!")

    @classmethod
    def point_at_infinity(cls):
        raise NotImplementedError("subclasses must override point_at_infinity()!")


class AffineCurvePoint(CurvePoint):
    def __init__(self, curve, x, y=None, inf=False):
        self.curve = curve
        self.x = x
        self.inf = inf

        if y is not None:
            self.y = y
        else:
            self.y = self.curve.curve.calculate(x).sqrt()

    def __copy__(self):

        return AffineCurvePoint(self.curve, self.x, self.y)

    def __add__(self, q):
        p = self
        if p.inf and not q.inf:
            return q

        if not p.inf and q.inf:
            return p

        if p == q:
            slope = ((3 * (p.x ** 2)) + p.curve.curve.getLinear()) / (2 * p.y)

        else:
            if int(p.x) == int(q.x):
                return AffineCurvePoint.point_at_infinity()

            slope = (p.y - q.y) / (p.x - q.x)

        result_x = (slope ** 2) - p.x - q.x
        result_y = (slope * (p.x - result_x)) - p.y

        return AffineCurvePoint(p.curve, result_x, result_y)

    def __mul__(self, factor):
        point = self
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
        return not self == other

    def __repr__(self):
        if self.inf:
            return "[INF, INF]"
        else:
            return "[" + str(self.x) + ", " + str(self.y) + "]"

    def serialize(self):
        affine_curve_point_dict = {
            "x": self.x.current_value,
            "y": self.y.current_value,
            "inf": self.inf,
        }

        return json.dumps(affine_curve_point_dict)

    def to_secrect(self):
        return self.x

    @classmethod
    def deserialize(cls, curve, serialized):
        affine_curve_point_dict = json.loads(serialized)
        return cls(
            curve,
            affine_curve_point_dict["x"],
            y=affine_curve_point_dict["y"],
            inf=affine_curve_point_dict["inf"],
        )

    @classmethod
    def point_at_infinity(cls):
        return AffineCurvePoint(None, 0, 0, inf=True)


class ProjectiveCurvePoint(CurvePoint):
    def __init__(self, curve, x, y=None, z=1, inf=False):
        self.curve = curve
        self.x = x
        self.z = z
        self.inf = inf

        if y is not None:
            self.y = y
        else:
            self.y = self.curve.curve.calculate(x).sqrt()

    def __copy__(self):
        return ProjectiveCurvePoint(self.cruve, self.x, self.y, self.z, self.inf)

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
                return ProjectiveCurvePoint.point_at_infinity()
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

            return ProjectiveCurvePoint(self.curve, rx, y=ry, z=rz)

    def double(self):
        if self.x == 0 or self.y == 0:
            return ProjectiveCurvePoint.point_at_infinity()
        else:
            t = self.x * self.x * 3 + self.curve.curve.getLinear() * self.z * self.z
            u = self.y * self.z * 2
            v = u * self.x * self.y * 2
            w = t * t - v * 2
            rx = u * w
            ry = t * (v - w) - u * u * self.y * self.y * 2
            rz = u * u * u
            return ProjectiveCurvePoint(self.curve, rx, y=ry, z=rz)

    def __mul__(self, factor):
        point = self
        result = ProjectiveCurvePoint.point_at_infinity()

        double_bucket = point
        while factor != 0:
            if factor & 1 != 0:
                result += double_bucket
            double_bucket = double_bucket.double()
            factor >>= 1

        return result

    def __eq__(self, other):
        if self.x or other.x:
            return self.x and other.x
        else:
            return (self.x * other.z, self.y * other.z) == (
                other.x * self.z,
                other.y * self.z,
            )

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        if self.inf:
            return "[INF, INF, INF]"
        else:
            return "[" + str(self.x) + ", " + str(self.y) + ", " + str(self.z) + "]"

    def serialize(self):
        projective_curve_point_dict = {
            "x": (self.x / self.z).current_value,
            "y": (self.y / self.z).current_value,
            "inf": self.inf,
        }

        return json.dumps(projective_curve_point_dict)

    def to_secrect(self):
        return self.x / self.z

    @classmethod
    def deserialize(cls, curve, serialized):
        projective_curve_point_dict = json.loads(serialized)
        return cls(
            curve,
            projective_curve_point_dict["x"],
            y=projective_curve_point_dict["y"],
            z=1,
            inf=projective_curve_point_dict["inf"],
        )

    @classmethod
    def point_at_infinity(cls):
        return ProjectiveCurvePoint(None, 0, 0, 0, inf=True)
