import finite_element

class ZModP(list):
    '''Implementierung von Zahlen Z mod p'''
    def __init__(self, p):
        self.p = p
        list.__init__(self)

        for i in range(p):
            self.append(finite_element.FE(i, p))

zmodp = ZModP(17)
print(zmodp)
