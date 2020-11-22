class RestklasseEF():

    def __init__(self, base, currentValue):
        self.base = base
        self.currentValue = currentValue % base

    def __add__(self, valueToAdd):
        newValue = self.__efficientAdd(self.currentValue ,valueToAdd)
        return RestklasseEF(self.base, newValue)

    def __sub__(self, valueToSub):
        newValue = self.__efficientSub(self.currentValue ,valueToSub)
        return RestklasseEF(self.base, newValue)

    def __mul__(self, valueToMul):
        newValue = self.__efficientMul(self.currentValue ,valueToMul)
        return RestklasseEF(self.base, newValue)

    def __pow__(self, valueToPow):
        newValue = self.__efficientPow(self.currentValue , valueToPow)
        newErg =  self.__efficientMod(newValue)
        return RestklasseEF(self.base, newErg)

    def __truediv__(self, valueToDiv):
        newValue = self.__efficientDivision(self.currentValue,valueToDiv)
        newErg =  self.__efficientMod(newValue)
        return RestklasseEF(self.base, newErg)

    def __lt__(self, valueToDiv):
        return self.__efficientLt(self.currentValue,valueToDiv)

    def __le__(self, valueToDiv):
        return self.__efficientLe(self.currentValue,valueToDiv)

    def __eq__(self, valueToDiv):
        return self.__efficientEq(self.currentValue,valueToDiv)

    def __ne__(self, valueToDiv):
        return self.__efficientDivision(self.currentValue,valueToDiv)

    def __gt__(self, valueToDiv):
        return self.__efficientGt(self.currentValue,valueToDiv)


    def __ge__(self, valueToDiv):
        return self.__efficientGe(self.currentValue,valueToDiv)

        
    
    def __efficientMod(self, value):
        return value % self.base

    def __efficientAdd(self, currentValue,valueToAdd):
        return currentValue + self.__efficientMod(valueToAdd)
    
    def __efficientSub(self, currentValue,valueToSub):
        return currentValue - self.__efficientMod(valueToSub)

    def __efficientMul(self, currentValue,valueToMul):
        return currentValue * self.__efficientMod(valueToMul)
          
    def __efficientPow(self,  currentValue,valueToPow):
        return currentValue ** valueToPow  

    def __efficientDivision(self, currentValue,valueToDiv):
        
        return currentValue / valueToDiv    

    def __efficientLt(self,  currentValue,valueToCompare):
        return currentValue < self.__efficientMod(valueToCompare)

    def __efficientLe(self, currentValue,valueToCompare):
        return currentValue <= self.__efficientMod(valueToCompare)    

    def __efficientEq(self,  currentValue,valueToCompare):
        return currentValue == self.__efficientMod(valueToCompare) 

    def __efficientNe(self, currentValue,valueToCompare):
        return currentValue != self.__efficientMod(valueToCompare) 
    
    def __efficientGt(self, currentValue,valueToCompare):
        return currentValue > self.__efficientMod(valueToCompare)  

    def __efficientGe(self,  currentValue,valueToCompare):
        return currentValue >= self.__efficientMod(valueToCompare)  




