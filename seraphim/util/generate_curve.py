from seraphim.elliptic_curves.elliptic_curve import EllipticCurve
from seraphim.elliptic_curves.elliptic_curve_point import CurvePoint, ProjectiveCurvePoint, AffineCurvePoint

new_curve = EllipticCurve.randomize(2 ** 3, 2 ** 6, 2 ** 8)

print(new_curve.serialize())