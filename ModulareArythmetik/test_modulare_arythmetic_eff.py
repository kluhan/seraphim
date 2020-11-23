import pytest
from ModulareArythmetik.modulare_arythmetic_efficient import RestclassEF
import time

class TestRestclass():

	def test_RestclassEF_add(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass + 4
            assert restclass_res.current_value == 2

	def test_restclass_sub(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass - 2
            assert restclass_res.current_value == 1

	def test_restclass_mul(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass * 15
            assert restclass_res.current_value == 0

	def test_restclass_pow(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass ** 3
            assert restclass_res.current_value == 2

	def test_restclass_truediv(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass / 17
            assert restclass_res.current_value == 4

	def test_restclass_lt(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass < 14
            assert restclass_res

	def test_restclass_leE(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass <= 63
            assert restclass_res
		
	def test_restclass_leL(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass <= 64
            assert restclass_res

	def test_restclass_eq(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass == 33
            assert restclass_res

	def test_restclass_ne(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass != 15
            assert restclass_res

	def test_restclass_gt(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass > 15
            assert restclass_res

	def test_restclass_geE(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass >= 3
            assert restclass_res

	def test_restclass_geG(self):
            restclass = RestclassEF(5,13)
            restclass_res = restclass >= 22
            assert restclass_res

