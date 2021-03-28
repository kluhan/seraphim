import json

from seraphim.elliptic_curves.elliptic_curve import EllipticCurve
from seraphim.elliptic_curves.elliptic_curve_point import EllipticCurvePoint
    
curve = [
    0, #Constant
    1, #x^1
    486662, #x^2
    1, #x^3
]



#curve = [
#    1, #Constant
#    1, #x^1
#    0, #x^2
#    1, #x^3
#]


mod = (2 ** 255)-19
#print(str(mod))
#mod = 40206835204840513073

test = {
    "curve": [
    0, #Constant
    1, #x^1
    486662, #x^2
    1, #x^3
],
    "p": (2 ** 255)-19,
    "generator": 9
}

generator = 9
test_curve = EllipticCurve(curve, mod, generator)

alice_sec = 2425967623052370772757633156976982469681
bob_sec = 6075380529345458860144577398704761614649

alice_point = test_curve.getGenerator()
bob_point = test_curve.getGenerator()

alice_point = alice_point * alice_sec
bob_point = bob_point * bob_sec

print(bob_point)
seri = bob_point.serialize()
print(seri)
print(EllipticCurvePoint.deserialize(test_curve, seri))

#
#print("Alice_Point: " + str(alice_point))
#print("Bob_Point: " + str(bob_point))
#
#bob_recived = alice_point
#alice_recived = bob_point
#
#alice_key = alice_recived * alice_sec
#bob_key = bob_recived * bob_sec
#
#print("Alice_Key: " + str(alice_key))
#print("Bob_Key: " + str(bob_key))
#