import platform
import random
import re
import threading

from .hdr import chk

VSO_UA = "vso-httptool/1.0"

PRD = re.compile(r"([^\s/()]+)(?:/([^\s()]+))?")


def ua_str(name="vso-httptool", ver="1.0", cmt=None, extra=None):
    s = "%s/%s" % (name, ver)
    if cmt:
        s += " (%s)" % "; ".join(cmt)
    for n, v in (extra or []):
        s += " %s/%s" % (n, v)
    return s


def sys_cmt():
    return [platform.system() or "unknown", "py%s" % platform.python_version()]


def parse_ua(s):
    prods = []
    cmts = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "(":
            d = 1
            j = i + 1
            while j < n and d:
                if s[j] == "(":
                    d += 1
                elif s[j] == ")":
                    d -= 1
                j += 1
            cmts.append(s[i + 1:j - 1 if d == 0 else j].strip())
            i = j
        elif c.isspace():
            i += 1
        else:
            m = PRD.match(s, i)
            if not m or m.end() == i:
                i += 1
                continue
            prods.append((m.group(1), m.group(2) or ""))
            i = m.end()
    return {"products": prods, "comments": cmts}


UA_MODES = ("round-robin", "random", "sticky")


class UaPool:
    def __init__(self, items, mode="round-robin"):
        if mode not in UA_MODES:
            raise ValueError("ua_rotate must be one of: %s" % ", ".join(UA_MODES))
        items = [items] if isinstance(items, str) else list(items)
        if not items:
            raise ValueError("empty user-agent list")
        self.items = [chk("User-Agent", s)[1] for s in items]
        self.mode = mode
        self.n = 0
        self.stick = {}
        self.lk = threading.Lock()

    def pick(self, origin=None):
        with self.lk:
            if self.mode == "random":
                return random.choice(self.items)
            if self.mode == "sticky" and origin in self.stick:
                return self.items[self.stick[origin]]
            i = self.n % len(self.items)
            self.n += 1
            if self.mode == "sticky":
                self.stick[origin] = i
            return self.items[i]
