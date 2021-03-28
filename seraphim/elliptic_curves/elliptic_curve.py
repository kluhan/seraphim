from copy import copy

from seraphim.finite_fields.polynomial import PolynomialModulo, Polynomial
from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF
from seraphim.elliptic_curves.elliptic_curve_point import EllipticCurvePoint
from seraphim.finite_fields.finite_field_element import FFE
from seraphim.finite_fields.finite_field import FF

class EllipticCurve:
    
    def __init__(self, curve, mod, generator):
        # eine liste von elementen x = [1,2,3,4] wenn x[-1] wird letztes element ausgegeben
        polynom = Polynomial(curve)
        finite_field = FF(polynom.degree(), mod)
        
        self.curve = FFE(finite_field, polynom)
        self.generator = generator

    def getPoint(self, x, y=None):
        return EllipticCurvePoint(self, x, y)
    
    def getGenerator(self):
        return EllipticCurvePoint(self, self.generator)
        