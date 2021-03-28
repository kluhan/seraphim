import json

from seraphim.elliptic_curves.elliptic_curve import EllipticCurve

curve = [
    0,  # Constant
    1,  # x^1
    486662,  # x^2
    1,  # x^3
]


generator = 9

# curve = [
#    1,  # Constant
#    1,  # x^1
#    0,  # x^2
#    1,  # x^3
# ]

mod = (2 ** 255) - 19

test_curve = EllipticCurve(curve, mod, generator, projective=True)

alice_sec = 546132165436135461321687631035789
bob_sec = 1965413236532196874131687691687

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