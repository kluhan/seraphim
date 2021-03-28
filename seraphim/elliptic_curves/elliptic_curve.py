from copy import copy

from seraphim.finite_fields.polynomial import PolynomialModulo, Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.elliptic_curves.elliptic_curve_point import CurvePoint, AffineCurvePoint, ProjectiveCurvePoint
from seraphim.finite_fields.finite_field_element import FFE
from seraphim.finite_fields.finite_field import FF


class EllipticCurve:
    def __init__(self, curve, mod, generator, projective=True):
        polynom = Polynomial(curve)
        finite_field = FF(polynom.degree(), mod)

        self.curve = FFE(finite_field, polynom)
        self.generator = generator
        self.projective = projective

    def getPoint(self, x, y=None):
        if self.projective:
            return ProjectiveCurvePoint(self, x, y, 1)
        else:
            return AffineCurvePoint(self, x, y)

    def getGenerator(self):
        if self.projective:
            return ProjectiveCurvePoint(self, self.generator)
        else:
            return AffineCurvePoint(self, self.generator)
