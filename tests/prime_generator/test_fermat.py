from seraphim.util.fermat import fermat


class TestFermat:
    def test_FermatTruePositive(self):
        assert fermat(131, 10)

        assert fermat(3319, 10)

        assert fermat(77777777977777777, 10)

    def test_FermatTrueNegative(self):
        assert not fermat(100, 10)

        assert not fermat(82907, 10)

        assert not fermat(5505024, 10)

    def test_FermatFalsePositive(self):
        prime = False
        for _ in range(100):
            prime = fermat(88357, 1)
            if prime:
                break

        assert not prime

    def test_FermatFalseNegative(self):
        for _ in range(1000):
            prime = fermat(3319, 1)
            assert prime

    def test_FermatFermatNumbers(self):
        prime = fermat(65537, 10)
        assert prime

        prime = fermat(4294967297, 10)
        assert not prime
