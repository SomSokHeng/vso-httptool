import contextlib
import contextvars
import re
import time

cv = contextvars.ContextVar("vso_trace", default=None)
MAXEV = 400
CTL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x9b]")


class Trace:
    def __init__(self, sink=None):
        self.t0 = time.monotonic()
        self.ev = []
        self.prob = []
        self.tm = {}
        self.sink = sink

    def add(self, kind, msg, bad=False, **d):
        e = {"t": round((time.monotonic() - self.t0) * 1000, 1), "kind": kind, "msg": msg, "bad": bad, "d": d}
        if len(self.ev) < MAXEV:
            self.ev.append(e)
        if bad:
            self.prob.append(e)
        if self.sink is not None:
            try:
                self.sink(e)
            except Exception:
                pass
        return e

    @contextlib.contextmanager
    def span(self, name):
        t = time.monotonic()
        try:
            yield
        finally:
            self.tm[name] = self.tm.get(name, 0.0) + (time.monotonic() - t) * 1000


def cur():
    return cv.get()


def note(kind, msg, bad=False, **d):
    t = cv.get()
    if t is not None:
        t.add(kind, msg, bad, **d)


def span(name):
    t = cv.get()
    return t.span(name) if t is not None else contextlib.nullcontext()


def fmt_ev(e):
    return "[%8.1f ms] %s %-8s %s" % (e["t"], "!" if e["bad"] else " ", e["kind"], CTL.sub("?", str(e["msg"])))


def stderr_sink(e):
    import sys
    sys.stderr.write(fmt_ev(e) + "\n")
    sys.stderr.flush()
