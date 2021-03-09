import pytest
from millerRabin import miller_rabin

def test_MillerRabinTruePositive():
    assert miller_rabin(131, 10) == True

    assert miller_rabin(3319, 10) == True

    assert miller_rabin(77777777977777777, 10) == True

def test_MillerRabinTrueNegative():
    assert miller_rabin(100, 10) == False

    assert miller_rabin(82907, 10) == False

    assert miller_rabin(5505024, 10) == False

def test_MillerRabinFalsePositive():
    prime = False
    for _ in range(100):
        prime = miller_rabin(88357, 1)
        if(prime != False):
            break

    assert prime == True

def test_MillerRabinFalseNegative():
    for _ in range(1000):
        prime = miller_rabin(3319, 1)
        assert prime == True       

def test_MillerRabinFermatNumbers():
    prime = miller_rabin(65537, 10)
    assert prime == True

    prime = miller_rabin(4294967297, 10)
    assert prime == False



