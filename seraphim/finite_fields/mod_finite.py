from seraphim.mod_arithmetics.modulare_arythmetic_efficient import RestclassEF

## Generiert die Representanten einer Restklasse zum mod p
class ZModP(list):
    """Implementierung von Zahlen Z mod p"""

    def __init__(self, p):
        self.p = p
        list.__init__(self)

        for i in range(p):
            self.append(RestclassEF(i, p))


zmodp = ZModP(17)
print(zmodp)
