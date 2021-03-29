import pytest
import secrets
from seraphim.elliptic_curves.elliptic_curve import EllipticCurve

class TestPointArithmetic:

    @pytest.fixture
    def generator_size(self):
        return int(secrets.randbits(2 ** 4))
    
    @pytest.fixture
    def exponent_size(self):
        return int(secrets.randbits(2 ** 5))

    @pytest.fixture
    def prime_size(self):
        return int(secrets.randbits(4))
    
    def test_point_arithmetic_projective(self, generator_size, exponent_size, prime_size):
       
       random_curve = EllipticCurve.randomize(generator_size, exponent_size, prime_size)

       assert type(random_curve) is EllipticCurve
