import pytest
from seraphim.util.fermat import fermat

def test_FermatTruePositive():
    assert fermat(131, 10) == True

    assert fermat(3319, 10) == True

    assert fermat(77777777977777777, 10) == True

def test_FermatTrueNegative():
    assert fermat(100, 10) == False

    assert fermat(82907, 10) == False

    assert fermat(5505024, 10) == False

def test_FermatFalsePositive():
    prime = False
    for _ in range(100):
        prime = fermat(88357, 1)
        if(prime == True):
            break

    assert prime == False

def test_FermatFalseNegative():
    for _ in range(1000):
        prime = fermat(3319, 1)
        assert prime == True       

def test_FermatFermatNumbers():
    prime = fermat(65537, 10)
    assert prime == True

    prime = fermat(4294967297, 10)
    assert prime == False



