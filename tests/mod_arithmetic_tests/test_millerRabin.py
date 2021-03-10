import pytest
import mock

from seraphim.util.millerRabin import miller_rabin
class TestMillerRabin:

    def test_MillerRabinFalsePositive(self):
        prime = miller_rabin(11111 , 1, [10], False)
        assert prime == True  

    def test_MillerRabinTruePositive(self):
        assert miller_rabin(131, 10) == True

        assert miller_rabin(3319, 10) == True

        assert miller_rabin(77777777977777777, 10) == True

    def test_MillerRabinTrueNegative(self):
        assert miller_rabin(100, 10) == False

        assert miller_rabin(82907, 10) == False

        assert miller_rabin(5505024, 10) == False

    def test_MillerRabinFermatNumbers(self):
        prime = miller_rabin(65537, 10)
        assert prime == True

        prime = miller_rabin(4294967297, 10)
        assert prime == False



