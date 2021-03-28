from itertools import cycle
import socket
import sys
import time
import threading
import secrets
import json

from seraphim.elliptic_curves.elliptic_curve import EllipticCurve
from seraphim.elliptic_curves.elliptic_curve_point import EllipticCurvePoint


class KeyAgreement:
    def __init__(self, domain):
        with open("domain_parameter.json") as domain_parameter_file:
            domain_parameter = json.load(domain_parameter_file)[domain]

        self.curve = domain_parameter["curve"]
        self.mod = domain_parameter["p"]
        self.generator = domain_parameter["generator"]

        self.elliptic_curve = EllipticCurve(self.curve, self.mod, self.generator)

    def compute_local_key(self):
        self.secret = secrets.randbelow(self.mod)
        start_point = self.elliptic_curve.getGenerator()

        self.local_key = start_point * self.secret

        return self.local_key.serialize()

    def compute_shared_key(self, foreign_key):

        self.shared_key = (
            EllipticCurvePoint.deserialize(self.elliptic_curve, foreign_key)
            * self.secret
        )

        return self.shared_key.x

    def encrypt(self, msg):
        encrypted_msg = ""

        for msg_chunk, key in zip(msg, cycle(str(self.shared_key.x.current_value))):
            encrypted_msg += chr(ord(msg_chunk) ^ ord(key))

        return encrypted_msg

    def decrypt(self, msg):
        return self.encrypt(msg)
