import socket
import threading
import json

from colorama import init, Fore

from additions.chat.quote import Quote
from seraphim.key_agreement.key_agreement import KeyAgreement


# https://github.com/grakshith/p2p-chat-python/blob/master/p2p.py


class SecureServer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("", 0))
        self.sock.listen(1)
        self.connection = None

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        self.connection.send(msg.encode("utf-8"))

    def receive(self):
        return self.connection.recv(4096).decode("utf-8")

    def run(self):
        init()
        quote = Quote()

        print(
            "Listening on <%s%s:%d%s>\n"
            % (
                Fore.BLUE,
                self.sock.getsockname()[0],
                self.sock.getsockname()[1],
                Fore.RESET,
            )
        )
        self.connection, address = self.sock.accept()

        print(
            "Incoming connection from <%s%s:%s%s>"
            % (Fore.BLUE, str(address[0]), str(address[1]), Fore.RESET)
        )
        print("     read:  %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        print("     write: %sSUCCESSFUL%s\n" % (Fore.GREEN, Fore.RESET))

        print("Key agreement via ECDH<%s%s%s>" % (Fore.BLUE, "PASSIV", Fore.RESET))
        domain = self.receive()
        self.send(domain)
        print(
            "     agreed on domain-parameter: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET)
        )

        foreign_key = self.receive()
        self.send(foreign_key)

        keyAgreement = KeyAgreement(domain)
        print("     received foreign_point: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        print("     compute local_point: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        local_key = keyAgreement.compute_local_key()

        self.send(local_key)
        if self.receive() == local_key:
            print(
                "     submitted local_point: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET)
            )
        else:
            print("     submitted local_point: %sFAILD%s" % (Fore.RED, Fore.RESET))

        print("     established shared_key: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        shared_key = keyAgreement.compute_shared_key(foreign_key)

        print("\nShared key is <%s%s%s>\n" % (Fore.CYAN, shared_key, Fore.RESET))

        while True:
            msg = self.receive()
            msg = json.loads(msg)
            print(
                "%s%s%s@%s%s:%s%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    str(address[0]),
                    str(address[1]),
                    Fore.RESET,
                    msg["quote"],
                )
            )
            print(
                "%s%s%s@%s%s:%s%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    str(address[0]),
                    str(address[1]),
                    Fore.RESET,
                    keyAgreement.decrypt(msg["quote"]),
                )
            )

            msg = quote.get()
            msg["author"] = msg["author"].replace(" ", "")
            msg["quote"] = keyAgreement.encrypt(msg["quote"])
            self.send(json.dumps(msg))
            print(
                "%s%s%s@%s%s:%s%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    self.sock.getsockname()[0],
                    self.sock.getsockname()[1],
                    Fore.RESET,
                    keyAgreement.decrypt(msg["quote"]),
                )
            )
            print(
                "%s%s%s@%s%s:%s%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    self.sock.getsockname()[0],
                    self.sock.getsockname()[1],
                    Fore.RESET,
                    msg["quote"],
                )
            )


secure_server = SecureServer()
secure_server.start()
