ff1 = FF(5, 2)
print(ff1)
poly = polyn.Polynomial([1, 1, 1, 1, 1, 1, 1])
ff2 = FF(17, 6, poly)
print(ff2)
ff1_random_element = ff1.generate_random_element(40)
print("Zufallselement: ", ff1_random_element)
p1 = generate_random_polynomial(7, 100, False)
print("P1: ", p1.coefficients)
p2 = generate_random_polynomial(7, 100, True)
print("P2: ", p2.coefficients)