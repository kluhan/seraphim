class Restklasse():

    def __init__(self, base, currentValue):
        self.base = base
        self.currentValue = currentValue % base

    def __add__(self, valueToAdd):
        newValue = self.currentValue + valueToAdd
        newErg =  newValue % self.base
        return Restklasse(self.base, newErg)

    def __sub__(self, valueToSub):
        newValue = self.currentValue - valueToSub
        newErg =  newValue % self.base
        return Restklasse(self.base, newErg)

    def __mul__(self, valueToMul):
        newValue = self.currentValue * valueToMul
        newErg =  newValue % self.base
        return Restklasse(self.base, newErg)

    def __pow__(self, valueToPow):
        newValue = self.currentValue ** valueToPow
        newErg =  newValue % self.base
        return Restklasse(self.base, newErg)

    def __truediv__(self, valueToDiv):
        newValue = self.currentValue / valueToDiv
        newErg =  newValue % self.base
        return Restklasse(self.base, newErg)

    def __lt__(self, valueToCompare):
        newValue = self.currentValue < (valueToCompare % self.base)
        return newValue

    def __le__(self, valueToCompare):
        newValue = self.currentValue <= (valueToCompare % self.base)
        return newValue


    def __eq__(self, valueToCompare):
        newValue = self.currentValue == (valueToCompare % self.base)
        return newValue


    def __ne__(self, valueToCompare):
        newValue = self.currentValue != (valueToCompare % self.base)
        return newValue

    def __gt__(self,valueToCompare):
        newValue = self.currentValue > (valueToCompare % self.base)
        return newValue


    def __ge__(self, valueToCompare):
        newValue = self.currentValue >= (valueToCompare % self.base)
        return newValue
