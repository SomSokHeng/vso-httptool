import os
import random
import socket
import threading


class Relay:
    def __init__(self, target, drop=0.0, seed=3):
        self.target = target
        self.drop = drop
        self.rnd = random.Random(seed)
        self.s2c_off = False
        self.reset_tok = None
        self.c2s = 0
        self.cl = None
        self.stop = threading.Event()
        self.a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.a.bind(("127.0.0.1", 0))
        self.a.settimeout(0.2)
        self.port = self.a.getsockname()[1]
        self.b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.b.settimeout(0.2)
        threading.Thread(target=self.fwd, daemon=True).start()
        threading.Thread(target=self.back, daemon=True).start()

    def fwd(self):
        while not self.stop.is_set():
            try:
                d, self.cl = self.a.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.c2s += len(d)
            if self.reset_tok:
                self.a.sendto(bytes([0x41]) + os.urandom(40) + self.reset_tok, self.cl)
                continue
            if self.drop and self.rnd.random() < self.drop:
                continue
            self.b.sendto(d, ("127.0.0.1", self.target))

    def back(self):
        while not self.stop.is_set():
            try:
                d, _ = self.b.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if self.s2c_off or (self.drop and self.rnd.random() < self.drop) or not self.cl:
                continue
            self.a.sendto(d, self.cl)

    def close(self):
        self.stop.set()
        for s in (self.a, self.b):
            try:
                s.close()
            except OSError:
                pass
