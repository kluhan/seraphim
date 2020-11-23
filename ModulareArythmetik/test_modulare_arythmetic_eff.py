import pytest
from ModulareArythmetik.modulare_arythmetic_efficient import RestklasseEF
import time

class TestRestklasse():

		
	def test_restklasseef_add(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse + 4
            print("---  test_restklasseef_add finished in %s seconds ---" % (time.time() - start_time))
            assert restklasseerg.currentValue == 2

	def test_restklasse_sub(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse - 2
            assert restklasseerg.currentValue == 1
            print("---  test_restklasse_sub finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_mul(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse * 15
            assert restklasseerg.currentValue == 0
            print("---  test_restklasse_mul finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_pow(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse ** 3
            assert restklasseerg.currentValue == 2
            print("---  test_restklasse_pow finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_truediv(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse / 17
            assert restklasseerg.currentValue == 4
            print("---  test_restklasse_truediv finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_lt(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse < 14
            assert restklasseerg
            print("---  test_restklasse_lt finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_leE(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse <= 63
            assert restklasseerg
            print("---  test_restklasse_leE finished in %s seconds ---" % (time.time() - start_time))
		
	def test_restklasse_leL(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse <= 64
            assert restklasseerg
            print("---  test_restklasse_leL finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_eq(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse == 33
            assert restklasseerg
            print("---  test_restklasse_eq finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_ne(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse != 15
            assert restklasseerg
            print("---  test_restklasse_ne finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_gt(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse > 15
            assert restklasseerg
            print("---  test_restklasse_gt finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_geE(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse >= 3
            assert restklasseerg
            print("---  test_restklasse_geE finished in %s seconds ---" % (time.time() - start_time))

	def test_restklasse_geG(self):
            start_time = time.time()
            restklasse = RestklasseEF(5,13)
            restklasseerg = restklasse >= 22
            assert restklasseerg
            print("--- test_restklasse_geG finished in %s seconds ---" % (time.time() - start_time))

