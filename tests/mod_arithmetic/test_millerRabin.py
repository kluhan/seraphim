from seraphim.util.millerRabin import miller_rabin


class TestMillerRabin:
    def test_MillerRabinFalsePositive(self):
        prime = miller_rabin(3825123056546413051, 9, [2, 3, 5, 7, 11, 13, 17, 19, 23])
        assert prime

    def test_MillerRabinTruePositive(self):
        assert miller_rabin(131, 10)

        assert miller_rabin(3319, 10)

        assert miller_rabin(77777777977777777, 10)

    def test_MillerRabinTrueNegative(self):
        assert not miller_rabin(100, 10)

        assert not miller_rabin(82907, 10)

        assert not miller_rabin(5505024, 10)

    def test_MillerRabinFermatNumbers(self):
        prime = miller_rabin(65537, 10)
        assert prime

        prime = miller_rabin(4294967297, 10)
        assert prime
