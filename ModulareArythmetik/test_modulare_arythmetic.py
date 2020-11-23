import pytest
from ModulareArythmetik.modulare_arythmetic import Restclass
import time

class TestRestclass():

	def test_Restclassef_add(self):
            restclass = Restclass(5,13)
            restclass_res = restclass + 4
            assert restclass_res.current_value == 2

	def test_Restclass_sub(self):
            restclass = Restclass(5,13)
            restclass_res = restclass - 2
            assert restclass_res.current_value == 1

	def test_Restclass_mul(self):
            restclass = Restclass(5,13)
            restclass_res = restclass * 15
            assert restclass_res.current_value == 0

	def test_Restclass_pow(self):
            restclass = Restclass(5,13)
            restclass_res = restclass ** 3
            assert restclass_res.current_value == 2

	def test_Restclass_truediv(self):
            restclass = Restclass(5,13)
            restclass_res = restclass / 17
            assert restclass_res.current_value == 4

	def test_Restclass_lt(self):
            restclass = Restclass(5,13)
            restclass_res = restclass < 14
            assert restclass_res

	def test_Restclass_leE(self):
            restclass = Restclass(5,13)
            restclass_res = restclass <= 63
            assert restclass_res
		
	def test_Restclass_leL(self):
            restclass = Restclass(5,13)
            restclass_res = restclass <= 64
            assert restclass_res

	def test_Restclass_eq(self):
            restclass = Restclass(5,13)
            restclass_res = restclass == 33
            assert restclass_res

	def test_Restclass_ne(self):
            restclass = Restclass(5,13)
            restclass_res = restclass != 15
            assert restclass_res

	def test_Restclass_gt(self):
            restclass = Restclass(5,13)
            restclass_res = restclass > 15
            assert restclass_res

	def test_Restclass_geE(self):
            restclass = Restclass(5,13)
            restclass_res = restclass >= 3
            assert restclass_res

	def test_Restclass_geG(self):
            restclass = Restclass(5,13)
            restclass_res = restclass >= 22
            assert restclass_res

