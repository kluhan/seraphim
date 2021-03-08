# Python Module RestclassEF

from halloklauth.helper.power_helper import little_fermat, repeated_square, squre_power_calc
import helper.extenden_euclidean as ee

class RestclassEF():

    def __init__(self, base, current_value):
        self.base = base
        self.current_value = current_value % base

    def __add__(self, value_to_add):
        new_value = self.__efficient_add(self.current_value ,value_to_add)
        return RestclassEF(self.base, new_value)

    def __sub__(self, value_to_sub):
        new_value = self.__efficient_sub(self.current_value ,value_to_sub)
        return RestclassEF(self.base, new_value)

    def __mul__(self, value_to_mul):
        new_value = self.__efficient_mul(self.current_value ,value_to_mul)
        return RestclassEF(self.base, new_value)

    def __pow__(self, value_to_pow):
        new_value = self.__efficient_pow(self.current_value , value_to_pow)
        new_res =  self.__efficient_mod(new_value)
        return RestclassEF(self.base, new_res)

    def __truediv__(self, value_to_div):
        new_value = self.__efficient_division(self.current_value,value_to_div)
        new_res =  self.__efficient_mod(new_value)
        return RestclassEF(self.base, new_res)

    def __lt__(self, value_to_compare):
        return self.__efficient_lt(self.current_value,value_to_compare)

    def __le__(self, value_to_compare):
        return self.__efficient_le(self.current_value,value_to_compare)

    def __eq__(self, value_to_compare):
        return self.__efficient_eq(self.current_value,value_to_compare)

    def __ne__(self, value_to_compare):
        return self.__efficient_ne(self.current_value,value_to_compare)

    def __gt__(self, value_to_compare):
        return self.__efficient_gt(self.current_value,value_to_compare)

    def __ge__(self, value_to_compare):
        return self.__efficient_ge(self.current_value,value_to_compare)

    def __efficient_mod(self, value):
        #toDo self made
        return value % self.base

    def __efficient_add(self, current_value,value_to_add):
        return current_value + self.__efficient_mod(value_to_add)
    
    def __efficient_sub(self, current_value,value_to_sub):
        return current_value - self.__efficient_mod(value_to_sub)

    def __efficient_mul(self, current_value,value_to_mul):
        return current_value * self.__efficient_mod(value_to_mul)
          
    def __efficient_division(self, current_value,value_to_div):
        inv_value_to_div = ee.get_inverse(self.base, value_to_div)
        res = inv_value_to_div * current_value
        return self.__efficient_mod(res)

    def __efficient_pow(self,  current_value,value_to_pow):
        #fermat
        new_pow = little_fermat(self.base, value_to_pow)

        # square and multiplay
        # zu binär und dann square and multiplay -> hemming gewicht 1/2
        # naf- form (non adjecent form) -> hemming gewicht 1/3

        if(new_pow > 2):
            powres_pot = repeated_square(value_to_pow)
            a = squre_power_calc(current_value**powres_pot)
            r = current_value**(value_to_pow - powres_pot)
            return self.__efficient_mul(self.__efficient_mod(a),self.__efficient_mod(r))
        else:
            return self.__efficient_mod(current_value ** value_to_pow)

    def __efficient_lt(self,  current_value,value_to_compare):
        return current_value < self.__efficient_mod(value_to_compare)

    def __efficient_le(self, current_value,value_to_compare):
        return current_value <= self.__efficient_mod(value_to_compare)    

    def __efficient_eq(self,  current_value,value_to_compare):
        return current_value == self.__efficient_mod(value_to_compare) 

    def __efficient_ne(self, current_value,value_to_compare):
        return current_value != self.__efficient_mod(value_to_compare) 
    
    def __efficient_gt(self, current_value,value_to_compare):
        return current_value > self.__efficient_mod(value_to_compare)  

    def __efficient_ge(self,  current_value,value_to_compare):
        return current_value >= self.__efficient_mod(value_to_compare)  

    def get_representative(self):
        #todo,
        return 32

 