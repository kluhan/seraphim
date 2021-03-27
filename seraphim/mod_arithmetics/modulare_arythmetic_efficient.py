# Python Module RestclassEF
from seraphim.util.power_helper import square_power_calc
from seraphim.util.extenden_euclidean import get_inverse


class Error(Exception):
    """Base class for other exceptions"""


class ValueNotInZError(Error):
    """Raised when the input value is too small"""


class ModIsZeroError(Error):
    """Raised when the input value is too small"""


class RestclassEF:
    def __init__(self, current_value, mod):
        try:
            if isinstance(current_value, RestclassEF):
                current_value = current_value.current_value

            if mod == 0:
                raise ModIsZeroError
            if (
                not str(current_value).replace("-", "").isnumeric()
                or not str(mod).replace("-", "").isnumeric()
            ):
                raise ValueNotInZError
            self.mod = mod
            self.current_value = current_value % mod
        except ModIsZeroError:
            print("Given mod was 0, try a mod value that is not 0")
            raise

        except ValueNotInZError:
            print("Some initialize value was not in Z, try using only integer.")
            print(f"current_value was: {current_value}")
            print(f"mod was: {mod}")
            raise
        print(f"current_value was: {current_value}")
        print(f"mod was: {mod}")

    def __add__(self, value_to_add):
        if isinstance(value_to_add, RestclassEF):
            new_value = self.__efficient_add(
                self.current_value, value_to_add.current_value
            )
        else:
            new_value = self.__efficient_add(self.current_value, value_to_add)
        return RestclassEF(new_value, self.mod)

    def __sub__(self, value_to_sub):
        if isinstance(value_to_sub, RestclassEF):
            new_value = self.__efficient_sub(
                self.current_value, value_to_sub.current_value
            )
        else:
            new_value = self.__efficient_sub(self.current_value, value_to_sub)
        return RestclassEF(new_value, self.mod)

    def __mul__(self, value_to_mul):
        if isinstance(value_to_mul, RestclassEF):
            new_value = self.__efficient_mul(
                self.current_value, value_to_mul.current_value
            )
        else:
            new_value = self.__efficient_mul(self.current_value, value_to_mul)
        return RestclassEF(new_value, self.mod)

    def __pow__(self, value_to_pow):
        if isinstance(value_to_pow, RestclassEF):
            new_value = self.__efficient_pow(
                self.current_value, value_to_pow.current_value
            )
        else:
            new_value = self.__efficient_pow(self.current_value, value_to_pow)
        new_res = self.__efficient_mod(new_value)
        return RestclassEF(new_res, self.mod)

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
        inv_value_to_div = get_inverse(self.mod, value_to_div)
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

    def get_representative(self):
        x = []
        for i in range(self.mod):
            x.append(i)
        return x
