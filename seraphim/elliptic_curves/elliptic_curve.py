from copy import copy
from seraphim.finite_fields.polynomial import PolynomialModulo, Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.elliptic_curves.elliptic_curve_point import EllipticCurvePoint

class EllipticCurve:
    
    def __init__(self, curve, mod, generator):
        self.curve = PolynomialModulo(curve,mod)
        self.generator = generator
        self.mod = mod

    def getPoint(self, x, y=None):
        return EllipticCurvePoint(self, x, y)
    
    def getGenerator(self):
        return EllipticCurvePoint(self, generator)
        