import secrets
import pytest
from seraphim.elliptic_curves.elliptic_curve import EllipticCurve


class TestPointArithmetic:
    @pytest.fixture
    def secret_alice(self):
        return int(secrets.randbits(2 ** 6))

    @pytest.fixture
    def secret_bob(self):
        return int(secrets.randbits(2 ** 6))

    def test_point_arithmetic_projective(self, secret_alice, secret_bob):
        test_curve = EllipticCurve(
            [0, 1, 486662, 1], (2 ** 255) - 19, 9, projective=True
        )

        alice_point = test_curve.getGenerator()
        bob_point = test_curve.getGenerator()

        alice_point = alice_point * secret_alice
        bob_point = bob_point * secret_bob

        bob_recived = alice_point
        alice_recived = bob_point

        alice_key = alice_recived * secret_alice
        bob_key = bob_recived * secret_bob

        assert bob_key == alice_key

        assert bob_key.serialize() == alice_key.serialize()

    def test_point_arithmetic_affine(self, secret_alice, secret_bob):
        test_curve = EllipticCurve(
            [0, 1, 486662, 1], (2 ** 255) - 19, 9, projective=False
        )

        alice_point = test_curve.getGenerator()
        bob_point = test_curve.getGenerator()

        alice_point = alice_point * secret_alice
        bob_point = bob_point * secret_bob

        bob_recived = alice_point
        alice_recived = bob_point

        alice_key = alice_recived * secret_alice
        bob_key = bob_recived * secret_bob

        assert bob_key == alice_key

        assert bob_key.serialize() == alice_key.serialize()