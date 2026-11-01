import platform
import re

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
