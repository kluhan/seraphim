from ModulareArythmetik.extenden_euclidean import get_inverse

class Restclass():

    def __init__(self, base, current_value):
        self.base = base
        self.current_value = current_value % base

    def __add__(self, value_to_add):
        new_value = self.current_value + value_to_add
        new_res =  new_value % self.base
        return Restclass(self.base, new_res)

    def __sub__(self, value_to_sub):
        new_value = self.current_value - value_to_sub
        new_res =  new_value % self.base
        return Restclass(self.base, new_res)

    def __mul__(self, value_to_mul):
        new_value = self.current_value * value_to_mul
        new_res =  new_value % self.base
        return Restclass(self.base, new_res)

    def __pow__(self, value_to_pow):
        new_value = self.current_value ** value_to_pow
        new_res =  new_value % self.base
        return Restclass(self.base, new_res)

    def __truediv__(self, value_to_div):
        inv_value = get_inverse(self.base, value_to_div)
        new_res = (inv_value * self.current_value) % self.base
        return Restclass(self.base, new_res)

    def __lt__(self, value_to_compare):
        new_value = self.current_value < (value_to_compare % self.base)
        return new_value

    def __le__(self, value_to_compare):
        new_value = self.current_value <= (value_to_compare % self.base)
        return new_value

    def __eq__(self, value_to_compare):
        new_value = self.current_value == (value_to_compare % self.base)
        return new_value

    def __ne__(self, value_to_compare):
        new_value = self.current_value != (value_to_compare % self.base)
        return new_value

    def __gt__(self,value_to_compare):
        new_value = self.current_value > (value_to_compare % self.base)
        return new_value


    def __ge__(self, value_to_compare):
        new_value = self.current_value >= (value_to_compare % self.base)
        return new_value


