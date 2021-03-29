from secrets import randbelow
import json

from seraphim.finite_fields.polynomial import Polynomial
from seraphim.elliptic_curves.elliptic_curve_point import (
    AffineCurvePoint,
    ProjectiveCurvePoint,
)
from seraphim.finite_fields.finite_field_element import FiniteFieldElement
from seraphim.finite_fields.finite_field import FiniteField
from seraphim.prime_generator.primeGenerator import prime_generator


class EllipticCurve:
    def __init__(self, curve, mod, generator, projective=True):
        polynom = Polynomial(curve)
        finite_field = FiniteField(polynom.degree(), mod)

        self.curve = FiniteFieldElement(finite_field, polynom)
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

    @classmethod
    def randomize(cls, generator_size, exponent_size, prime_size):
        generator = randbelow(generator_size)

        curve = []
        for _ in range(4):
            curve.append(randbelow(exponent_size))

        prime_gen = prime_generator(prime_size)
        mod = next(prime_gen)

        return cls(curve, mod, generator)
