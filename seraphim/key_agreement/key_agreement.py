from itertools import cycle
import secrets
import json

from colorama import Fore

from seraphim.elliptic_curves.elliptic_curve import EllipticCurve
from seraphim.elliptic_curves.elliptic_curve_point import (
    ProjectiveCurvePoint,
    AffineCurvePoint,
)


class KeyAgreement:
    def __init__(self, domain, style="projective", v=True):
        self.secret = None
        self.local_key = None
        self.shared_key = None
        self.verbose = v

        with open("domain_parameter.json") as domain_parameter_file:
            domain_parameter = json.load(domain_parameter_file)[domain]

        if style == "projective":
            self.CurvePoint = ProjectiveCurvePoint
            style = True
        if style == "affine":
            self.CurvePoint = AffineCurvePoint
            style = False

        self.curve = domain_parameter["curve"]
        self.mod = domain_parameter["mod"]
        self.generator = domain_parameter["generator"]

        if self.verbose:
            self._print_init()
        self.elliptic_curve = EllipticCurve(
            self.curve, self.mod, self.generator, projective=style
        )

    def compute_local_key(self):
        self.secret = secrets.randbelow(self.mod)
        start_point = self.elliptic_curve.getGenerator()

        self.local_key = start_point * self.secret

        if self.verbose:
            self._print_local_key()
        return self.local_key.serialize()

    def compute_shared_key(self, foreign_point):
        foreign_point = self.CurvePoint.deserialize(self.elliptic_curve, foreign_point)
        secret_point = foreign_point * self.secret
        self.shared_key = secret_point.to_secrect()

        if self.verbose:
            self._print_shared_key(foreign_point, secret_point)
        return self.shared_key

    def encrypt(self, msg):
        encrypted_msg = ""

        for msg_chunk, key in zip(msg, cycle(str(self.shared_key))):
            encrypted_msg += chr(ord(msg_chunk) ^ ord(key))

        return encrypted_msg

    def decrypt(self, msg):
        return self.encrypt(msg)

    def _print_init(self):

        print("       curve: <%s%s%s>" % (Fore.YELLOW, str(self.curve), Fore.RESET))
        print("       mod: <%s%d%s>" % (Fore.YELLOW, self.mod, Fore.RESET))
        print("       generator: <%s%d%s>" % (Fore.YELLOW, self.generator, Fore.RESET))

    def _print_local_key(self):

        print("       secret: <%s%d%s>" % (Fore.YELLOW, self.secret, Fore.RESET))
        print(
            "       local_key.x: <%s%d%s>" % (Fore.YELLOW, self.local_key.x, Fore.RESET)
        )
        print(
            "       local_key.y: <%s%d%s>" % (Fore.YELLOW, self.local_key.y, Fore.RESET)
        )

        if isinstance(self.local_key, ProjectiveCurvePoint):
            print(
                "       local_key.z: <%s%d%s>"
                % (Fore.YELLOW, self.local_key.z, Fore.RESET)
            )

    def _print_shared_key(self, foreign_point, secret_point):
        print("       secret: <%s%d%s>" % (Fore.YELLOW, self.secret, Fore.RESET))

        print(
            "       foreign_point.x: <%s%d%s>"
            % (Fore.YELLOW, foreign_point.x, Fore.RESET)
        )
        print(
            "       foreign_point.y: <%s%d%s>"
            % (Fore.YELLOW, foreign_point.y, Fore.RESET)
        )

        if isinstance(foreign_point, ProjectiveCurvePoint):
            print(
                "       foreign_point.z: <%s%d%s>"
                % (Fore.YELLOW, foreign_point.z, Fore.RESET)
            )

        print(
            "       secret_point.x: <%s%d%s>"
            % (Fore.YELLOW, secret_point.x, Fore.RESET)
        )
        print(
            "       secret_point.y: <%s%d%s>"
            % (Fore.YELLOW, secret_point.y, Fore.RESET)
        )

        if isinstance(secret_point, ProjectiveCurvePoint):
            print(
                "       secret_point.z: <%s%d%s>"
                % (Fore.YELLOW, secret_point.z, Fore.RESET)
            )

        print(
            "       secret_key: <%s%d%s>" % (Fore.YELLOW, self.shared_key, Fore.RESET)
        )


test = KeyAgreement("curve25519")
