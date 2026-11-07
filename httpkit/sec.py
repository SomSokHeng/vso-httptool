import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

from .err import SecError


@dataclass
class Lim:
    max_hdr_b: int = 65536
    max_hdrs: int = 256
    max_body: int = 64 << 20
    max_redirs: int = 10
    max_cookies: int = 180
    max_streams: int = 100
    max_ctl: int = 2000
    tmo: float = 30.0


vso_lim = Lim()

inf_priv_nets = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
))


def chk_ip(ip, d=0):
    if d > 2:
        return True
    if ip.version == 6:
        m = ip.ipv4_mapped
        if m:
            return chk_ip(m, d + 1)
        sf = ip.sixtofour
        if sf:
            return chk_ip(sf, d + 1)
        t = ip.teredo
        if t:
            return chk_ip(t[0], d + 1) or chk_ip(t[1], d + 1)
        pk = ip.packed
        if pk[:12] == bytes.fromhex("0064ff9b0000000000000000"):
            return chk_ip(ipaddress.IPv4Address(pk[12:]), d + 1)
        if 1 < int(ip) < (1 << 32):
            return chk_ip(ipaddress.IPv4Address(int(ip)), d + 1)
    return (not ip.is_global) or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_loopback or ip.is_link_local or any(ip in n for n in inf_priv_nets)


def is_priv(addr):
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return True
    return chk_ip(ip)


class InfGuard:
    def __init__(self, blk_priv=True, allow_downgrade=False, ttl=30.0):
        self.blk_priv = blk_priv
        self.allow_downgrade = allow_downgrade
        self.ttl = ttl
        self.cache = {}
        self.lk = threading.Lock()

    def resolve(self, host, port):
        now = time.monotonic()
        k = (host, port)
        with self.lk:
            hit = self.cache.get(k)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        try:
            rs = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SecError("dns failure for %s: %s" % (host, e)) from e
        out = []
        seen = set()
        for fam, _, _, _, sa in rs:
            if sa[0] not in seen:
                seen.add(sa[0])
                out.append((fam, sa[0]))
        if not out:
            raise SecError("no addresses for %s" % host)
        with self.lk:
            self.cache[k] = (now, out)
            while len(self.cache) > 256:
                self.cache.pop(next(iter(self.cache)))
        return out

    def src_priv(self, host, port):
        return all(is_priv(a) for _, a in self.resolve(host, port))

    def chk_redir(self, src, dst):
        if dst.scheme not in ("http", "https"):
            raise SecError("redirect to disallowed scheme: %s" % dst.scheme)
        if src.scheme == "https" and dst.scheme == "http" and not self.allow_downgrade:
            raise SecError("https to http redirect blocked")
        if self.blk_priv:
            sp = self.src_priv(src.host, src.port)
            if not sp:
                for _, a in self.resolve(dst.host, dst.port):
                    if is_priv(a):
                        raise SecError("redirect to private address blocked: %s" % dst.host)
        return True

    def chk_len(self, n, lim):
        if n > lim:
            raise SecError("size %d exceeds limit %d" % (n, lim))
