from ModulareArythmetik.extenden_euclidean import getInverse

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

    def __lt__(self, valueToCompare):
        return self.__efficientLt(self.currentValue,valueToCompare)

    def __le__(self, valueToCompare):
        return self.__efficientLe(self.currentValue,valueToCompare)

    def __eq__(self, valueToCompare):
        return self.__efficientEq(self.currentValue,valueToCompare)

    def __ne__(self, valueToCompare):
        return self.__efficientNe(self.currentValue,valueToCompare)

    def __gt__(self, valueToCompare):
        return self.__efficientGt(self.currentValue,valueToCompare)

    def __ge__(self, valueToCompare):
        return self.__efficientGe(self.currentValue,valueToCompare)

    def __efficientMod(self, value):
        return value % self.base

    def __efficientAdd(self, currentValue,valueToAdd):
        return currentValue + self.__efficientMod(valueToAdd)
    
    def __efficientSub(self, currentValue,valueToSub):
        return currentValue - self.__efficientMod(valueToSub)

    def __efficientMul(self, currentValue,valueToMul):
        return currentValue * self.__efficientMod(valueToMul)
          
    def __efficientDivision(self, currentValue,valueToDiv):
        invValueToDiv = getInverse(self.base, valueToDiv)
        erg = invValueToDiv * currentValue
        return self.__efficientMod(erg)

    def __efficientPow(self,  currentValue,valueToPow):
        if(valueToPow > 2):
            powErgPot = self.__repeatedSquare(valueToPow)
            a = currentValue**powErgPot
            r = currentValue**(valueToPow - powErgPot)
            return self.__efficientMod(a)  * self.__efficientMod(r)
        else:
            return self.__efficientMod(currentValue ** valueToPow)

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

    def __repeatedSquare(self,valueToPow):
        erg = 2
        running = True
        while(running):
            if(erg*2 < valueToPow):
                erg = erg * 2
            else:
                running = False
                return erg

        return erg
