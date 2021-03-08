class FE(object):
    '''Element in einem Körper modulo p'''
    def __init__(self, n, p): 
        self.n = n % p
        self.p = p
        
    def __add__(self, other): 
        assert self.p == other.p 
        return FE((self.n + other.n),self.p)
        
    def __sub__(self, other):
        assert self.p == other.p
        return FE((self.n - other.n), self.p)
    
    def __mul__(self, other):
        assert self.p == other.p
        return FE((self.n * other.n), self.p)
        
    def __div__(self, other):
        assert self.p == other.p
        return FE((self.n / other.n), self.p)
        
    def __truediv__(self, other): 
        assert self.p == other.p
        return FE((self.n / other.n), self.p)
    
    def __pow__(self, exp):
        return FE((self.n ** exp), self.p)
        
    def __neg__(self):
        return FE((self.p - self.n), self.p)
        
    def __eq__(self, other):
        return self.n == other.n and self.p == other.p
        
    def __ne__(self, other): 
        return self.n != other.n and self.p == other.p
        
    def __str__(self):
        return "FE(%s,%s)" % (str(self.n), str(self.p))
        
    def __repr__(self):
        return "FE(%s,%s)" % (str(self.n), str(self.p))
    
a = FE(3,5)
b = FE(8,5)

print("a:", str(a))
print(a.p)
print("b:", str(b))
print(b.p)
print("a+b:", str(a + b))
print("a*b:", str(a * b))
print("a-b:", str(a - b))
print("a/b:", str(a / b))