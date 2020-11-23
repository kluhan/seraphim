import pytest
from ModulareArythmetik.modulare_arythmetic_efficient import RestklasseEF
import time

class TestRestklasse():

	def test_restklasseef_add(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse + 4
            assert restklasseerg.currentValue == 2

	def test_restklasse_sub(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse - 2
            assert restklasseerg.currentValue == 1

	def test_restklasse_mul(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse * 15
            assert restklasseerg.currentValue == 0

	def test_restklasse_pow(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse ** 3
            assert restklasseerg.currentValue == 2

	def test_restklasse_truediv(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse / 17
            assert restklasseerg.currentValue == 4

	def test_restklasse_lt(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse < 14
            assert restklasseerg

	def test_restklasse_leE(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse <= 63
            assert restklasseerg
		
	def test_restklasse_leL(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse <= 64
            assert restklasseerg

	def test_restklasse_eq(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse == 33
            assert restklasseerg

	def test_restklasse_ne(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse != 15
            assert restklasseerg

	def test_restklasse_gt(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse > 15
            assert restklasseerg

	def test_restklasse_geE(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse >= 3
            assert restklasseerg

	def test_restklasse_geG(self):
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse >= 22
            assert restklasseerg

