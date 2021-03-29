from seraphim.elliptic_curves.elliptic_curve import EllipticCurve

new_curve = EllipticCurve.randomize(2 ** 3, 2 ** 6, 2 ** 8)
print(new_curve.serialize())