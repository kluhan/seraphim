from seraphim.elliptic_curves.elliptic_curve import EllipticCurve

curve = [
    0,  # Constant
    1,  # x^1
    486662,  # x^2
    1,  # x^3
]


# curve = [
#    1, #Constant
#    1, #x^1
#    0, #x^2
#    1, #x^3
# ]

mod = (2 ** 255) - 19
generator = 9

test_curve = EllipticCurve(curve, mod, generator, projective=True)
mod = (2 ** 255) - 19
# print(str(mod))
# mod = 40206835204840513073

alice_sec = 546132165436135461321687631035789
bob_sec = 1965413236532196874131687691687


alice_sec = 2425967623052370772757633156976982469681
bob_sec = 6075380529345458860144577398704761614649

alice_point = test_curve.getGenerator()
bob_point = test_curve.getGenerator()

print("generator" + str(alice_point))

alice_point = alice_point * alice_sec
bob_point = bob_point * bob_sec


print("Alice_Point: " + str(alice_point))
print("Bob_Point: " + str(bob_point))
print("Alice_Point_Seri: " + str(alice_point.serialize()))
print("Bob_Point_Seri: " + str(bob_point.serialize()))


bob_recived = alice_point
alice_recived = bob_point

alice_key = alice_recived * alice_sec
bob_key = bob_recived * bob_sec

print("Alice_Key_Seri: " + str(alice_key.serialize()))
print("Bob_Key_Seri: " + str(bob_key.serialize()))
print("Alice_Key: " + str(alice_key))
print("Bob_Key: " + str(bob_key))

r = bob_key.serialize() == alice_key.serialize()

print("Alice_Key == Bob_key: " + str(r))