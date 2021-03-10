# Python Module RestclassEF

from seraphim.util.power_helper import little_fermat, repeated_square, squre_power_calc
from seraphim.util.extenden_euclidean import get_inverse


class RestclassEF:
    def __init__(self, current_value, mod):
        self.mod = mod
        self.current_value = current_value % mod

    def __add__(self, value_to_add):
        new_value = self.__efficient_add(self.current_value, value_to_add)
        return RestclassEF(new_value, self.mod)

    def __sub__(self, value_to_sub):
        new_value = self.__efficient_sub(self.current_value, value_to_sub)
        return RestclassEF(new_value, self.mod)

    def __mul__(self, value_to_mul):
        new_value = self.__efficient_mul(self.current_value, value_to_mul)
        return RestclassEF(new_value, self.mod)

    def __pow__(self, value_to_pow):
        new_value = self.__efficient_pow(self.current_value, value_to_pow)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

    def __truediv__(self, value_to_div):
        new_value = self.__efficient_division(self.current_value, value_to_div)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

    def __lt__(self, value_to_compare):
        return self.__efficient_lt(self.current_value, value_to_compare)

    def __le__(self, value_to_compare):
        return self.__efficient_le(self.current_value, value_to_compare)

    def __eq__(self, value_to_compare):
        return self.__efficient_eq(self.current_value, value_to_compare)

    def __ne__(self, value_to_compare):
        return self.__efficient_ne(self.current_value, value_to_compare)

    def __gt__(self, value_to_compare):
        return self.__efficient_gt(self.current_value, value_to_compare)

    def __ge__(self, value_to_compare):
        return self.__efficient_ge(self.current_value, value_to_compare)

    def __efficient_mod(self, value):
        # toDo self made
        return value % self.mod

    def __efficient_add(self, current_value, value_to_add):
        return current_value + self.__efficient_mod(value_to_add)

    def __efficient_sub(self, current_value, value_to_sub):
        return current_value - self.__efficient_mod(value_to_sub)

    def __efficient_mul(self, current_value, value_to_mul):
        return current_value * self.__efficient_mod(value_to_mul)

    def __efficient_division(self, current_value, value_to_div):
        inv_value_to_div = get_inverse(self.mod, value_to_div)
        res = inv_value_to_div * current_value
        return self.__efficient_mod(res)

    def __efficient_pow(self, current_value, value_to_pow):
        # fermat
        # new_pow = little_fermat(self.mod, value_to_pow)

        # square and multiplay
        # zu binär und dann square and multiplay -> hemming gewicht 1/2
        # naf- form (non adjecent form) -> hemming gewicht 1/3
        return squre_power_calc(current_value, value_to_pow, self.mod)

    def __efficient_lt(self, current_value, value_to_compare):
        return current_value < self.__efficient_mod(value_to_compare)

    def __efficient_le(self, current_value, value_to_compare):
        return current_value <= self.__efficient_mod(value_to_compare)

    def __efficient_eq(self, current_value, value_to_compare):
        return current_value == self.__efficient_mod(value_to_compare)

    def __efficient_ne(self, current_value, value_to_compare):
        return current_value != self.__efficient_mod(value_to_compare)

    def __efficient_gt(self, current_value, value_to_compare):
        return current_value > self.__efficient_mod(value_to_compare)

    def __efficient_ge(self, current_value, value_to_compare):
        return current_value >= self.__efficient_mod(value_to_compare)

    def get_representative(self):
        # todo,
        return 32
