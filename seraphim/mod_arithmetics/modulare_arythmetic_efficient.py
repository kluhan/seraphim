# Python Module RestclassEF
from seraphim.util.power_helper import square_power_calc
from seraphim.util.extended_euclidean import get_inverse
from seraphim.util.tonelli_shanks import tonelli_shanks


class Error(Exception):
    """Base class for other exceptions"""


class ValueNotInZError(Error):
    """Raised when the input value is too small"""


class ModIsZeroError(Error):
    """Raised when the input value is too small"""


class RestclassEF:
    def __init__(self, current_value, mod):
        # try:
        if isinstance(current_value, RestclassEF):
            current_value = current_value.current_value

        if mod == 0:
            raise ModIsZeroError
        if (
            not str(current_value).replace("-", "").isnumeric()
            or not str(mod).replace("-", "").isnumeric()
        ):
            print(current_value)
            print(mod)
            raise ValueNotInZError
        self.mod = mod
        self.current_value = current_value % mod

    def __int__(self):
        return self.current_value

    def __add__(self, value_to_add):
        if isinstance(value_to_add, RestclassEF):
            new_value = self.__efficient_add(
                self.current_value, value_to_add.current_value
            )
        else:
            new_value = self.__efficient_add(self.current_value, value_to_add)
        return RestclassEF(new_value, self.mod)

    def __radd__(self, value_to_add):
        new_value = self.__efficient_add(value_to_add, self.current_value)
        return RestclassEF(new_value, self.mod)

    def __sub__(self, value_to_sub):
        if isinstance(value_to_sub, RestclassEF):
            new_value = self.__efficient_sub(
                self.current_value, value_to_sub.current_value
            )
        else:
            new_value = self.__efficient_sub(self.current_value, value_to_sub)
        return RestclassEF(new_value, self.mod)

    def __rsub__(self, value_to_sub):
        new_value = self.__efficient_sub(value_to_sub, self.current_value)
        return RestclassEF(new_value, self.mod)

    def __mul__(self, value_to_mul):
        if isinstance(value_to_mul, RestclassEF):
            new_value = self.__efficient_mul(
                self.current_value, value_to_mul.current_value
            )
        else:
            new_value = self.__efficient_mul(self.current_value, value_to_mul)
        return RestclassEF(new_value, self.mod)

    def __rmul__(self, value_to_mul):
        return self.__mul__(value_to_mul)

    def __pow__(self, value_to_pow):
        if isinstance(value_to_pow, RestclassEF):
            new_value = self.__efficient_pow(
                self.current_value, value_to_pow.current_value
            )
        else:
            new_value = self.__efficient_pow(self.current_value, value_to_pow)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

    def __div__(self, value_to_div):
        if isinstance(value_to_div, RestclassEF):
            new_value = self.__efficient_division(
                self.current_value, value_to_div.current_value
            )
        else:
            new_value = self.__efficient_division(self.current_value, value_to_div)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

    def __rdiv__(self, value_to_div):
        self.__div__(value_to_div)

    def __truediv__(self, value_to_div):
        if isinstance(value_to_div, RestclassEF):
            new_value = self.__efficient_division(
                self.current_value, value_to_div.current_value
            )
        else:
            new_value = self.__efficient_division(self.current_value, value_to_div)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

    def __neg__(self):
        return self.mod - self.current_value

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
        #   - einfach mod rechnen
        #   - ausgabe imemr positiv egal was reinkomme yo
        #   - was passiert mit x mod -y wenn der mod basis negativ ist
        if isinstance(value, RestclassEF):
            value = value.current_value
        x = int(value // self.mod)
        return value - x * self.mod
        # return value % self.mod

    def __efficient_add(self, current_value, value_to_add):
        return current_value + self.__efficient_mod(value_to_add)

    def __efficient_sub(self, current_value, value_to_sub):
        return current_value - self.__efficient_mod(value_to_sub)

    def __efficient_mul(self, current_value, value_to_mul):
        return current_value * self.__efficient_mod(value_to_mul)

    def __efficient_division(self, current_value, value_to_div):
        check_normal_div = current_value % value_to_div
        # print("test: ", test)
        if check_normal_div == 0:
            return self.__efficient_mod(int(current_value / value_to_div))
        if value_to_div == 1:
            return self.__efficient_mod(current_value)
        inv_value_to_div = get_inverse(self.mod, value_to_div, current_value)
        res = inv_value_to_div * current_value
        return self.__efficient_mod(res)

    def __efficient_pow(self, current_value, value_to_pow):
        return square_power_calc(current_value, value_to_pow, self.mod)

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

    def __repr__(self):
        return str(self.current_value)

    def sqrt(self):
        return RestclassEF(tonelli_shanks(self.current_value, self.mod), self.mod)

    def get_representative(self):
        x = []
        for i in range(self.mod):
            x.append(i)
        return x
