import socket
import sys
import time
import threading
import json

from colorama import init, Fore

from seraphim.key_agreement.key_agreement import KeyAgreement

# https://github.com/grakshith/p2p-chat-python/blob/master/p2p.py
class SecureClient(threading.Thread):
    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        self.sock.send(msg.encode("utf-8"))

    def receive(self):
        return self.sock.recv(4096).decode("utf-8")

    def run(self):
        

        host = input("Target Hostname:\n>>%s" % (Fore.BLUE))
        print(Fore.RESET)
        port = int(input("Target Port:\n>>%s" % (Fore.BLUE)))
        print(Fore.RESET)
        domain = "curve25519"
        domain = input("Domain:\n>>%s" % (Fore.BLUE))

        


        print("Connecting with <%s%s:%d%s>" % (Fore.BLUE, host, port, Fore.RESET))
        self.connect(host, port)
        print("     write: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        print("     reade: %sSUCCESSFUL%s\n" % (Fore.GREEN, Fore.RESET))

        print("Key agreement via ECDH<%s%s%s>" % (Fore.BLUE, "ACTIVE", Fore.RESET))
        self.send(domain)
        if self.receive() == domain:
            print(
                "     agreed on domain-parameter: %sSUCCESSFUL%s"
                % (Fore.GREEN, Fore.RESET)
            )
        else:
            print("     agreed on domain-parameter: %sFAILD%s" % (Fore.RED, Fore.RESET))

        keyAgreement = KeyAgreement(domain)
        print("     compute local_point: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        local_key = keyAgreement.compute_local_key()
        self.send(local_key)
        if self.receive() == local_key:
            print("     submitted local_key: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))
        else:
            print("     submitted local_key: %sFAILD%s" % (Fore.RED, Fore.RESET))

        foreign_key = self.receive()
        self.send(foreign_key)
        print("     received foreign_key: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET))

        
        print(
            "     established shared_key: %sSUCCESSFUL%s" % (Fore.GREEN, Fore.RESET)
        )
        shared_key = keyAgreement.compute_shared_key(foreign_key)
        
        print("\nShared key is <%s%s%s>\n" % (Fore.CYAN, shared_key, Fore.RESET))

        while True:

            msg_raw = input("")
            msg = {
                "author": "Klaus",
                "quote": keyAgreement.encrypt(msg_raw),
            }

            print(
                "\033[1A%s%s%s@%s%s:%d%s: %s\033[K"
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
                "%s%s%s@%s%s:%d%s: %s"
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

            if msg_raw == "exit":
                break

            if msg_raw == "":
                continue

            self.send(json.dumps(msg))
            msg = self.receive()
            msg = json.loads(msg)
            print(
                "%s%s%s@%s%s:%d%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    host,
                    port,
                    Fore.RESET,
                    msg["quote"],
                )
            )
            print(
                "%s%s%s@%s%s:%d%s: %s"
                % (
                    Fore.RED,
                    msg["author"],
                    Fore.RESET,
                    Fore.BLUE,
                    host,
                    port,
                    Fore.RESET,
                    keyAgreement.decrypt(msg["quote"]),
                )
            )


secure_client = SecureClient()
secure_client.start()
