from seraphim.util.fermat import fermat

class TestFermat:

    def test_FermatTruePositive(self):
        assert fermat(131, 10) is True

        assert fermat(3319, 10) is True

        assert fermat(77777777977777777, 10) is True

    def test_FermatTrueNegative(self):
        assert fermat(100, 10) is False

        assert fermat(82907, 10) is False

        assert fermat(5505024, 10) is False

    def test_FermatFalsePositive(self):
        prime = False
        for _ in range(100):
            prime = fermat(88357, 1)
            if prime is True:
                break

        assert prime is False

    def test_FermatFalseNegative(self):
        for _ in range(1000):
            prime = fermat(3319, 1)
            assert prime is True

    def test_FermatFermatNumbers(self):
        prime = fermat(65537, 10)
        assert prime is True

        prime = fermat(4294967297, 10)
        assert prime is False
        