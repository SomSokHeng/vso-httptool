import asyncio
import math
import re
import signal
import sys
import time
from collections import Counter, deque

from . import _vso
from .aio import AsyncClient, vso_thr_max
from .err import ClientError
from .sec import Lim
from .url import parse as parse_url

vso_speeds = {"slow": (4, 5.0), "medium": (16, 25.0), "fast": (vso_thr_max, 100.0)}
vso_rate_max = 200.0
vso_rate_min = 0.1
vso_dur_max = 7 * 86400
vso_n_max = 10 ** 9
vso_fail_def = 500
inf_ctl = re.compile(r"[\x00-\x1f\x7f\x9b]")


def inf_clean(s):
    return inf_ctl.sub("?", str(s))


def parse_speed(sp):
    if isinstance(sp, str) and sp.lower() in vso_speeds:
        return vso_speeds[sp.lower()]
    try:
        rate = float(sp)
    except (TypeError, ValueError):
        raise ClientError("speed must be slow, medium, fast or a rate in requests per second") from None
    if not math.isfinite(rate) or rate < vso_rate_min or rate > vso_rate_max:
        raise ClientError("speed rate must be between %s and %s requests per second" % (vso_rate_min, vso_rate_max))
    return max(1, min(vso_thr_max, int(math.ceil(rate / 2)))), rate


def inf_pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(len(s) * p))]


class InfRate:
    def __init__(self, rate):
        self.iv = 1.0 / rate
        self.nxt = time.monotonic()

    async def wait(self):
        now = time.monotonic()
        if self.nxt < now:
            self.nxt = now
        d = self.nxt - now
        self.nxt += self.iv
        if d > 0:
            await asyncio.sleep(d)


class InfStats:
    def __init__(self):
        self.t0 = time.monotonic()
        self.t1 = None
        self.sent = 0
        self.ok = 0
        self.http_err = 0
        self.fail = 0
        self.byt = 0
        self.protos = Counter()
        self.codes = Counter()
        self.errs = Counter()
        self.lat = deque(maxlen=2048)
        self.lat_sum = 0.0
        self.lat_min = None
        self.lat_max = 0.0
        self.run_fail = 0
        self.stop_why = None

    def add_res(self, r, ms):
        self.sent += 1
        self.run_fail = 0
        self.byt += len(r.body)
        self.protos[r.proto] += 1
        self.codes[r.status] += 1
        if r.status < 400:
            self.ok += 1
        else:
            self.http_err += 1
        self.lat.append(ms)
        self.lat_sum += ms
        self.lat_min = ms if self.lat_min is None else min(self.lat_min, ms)
        self.lat_max = max(self.lat_max, ms)

    def add_err(self, e):
        self.sent += 1
        self.fail += 1
        self.run_fail += 1
        k = "%s: %s" % (type(e).__name__, inf_clean(str(e))[:80])
        if k in self.errs or len(self.errs) < 20:
            self.errs[k] += 1
        else:
            self.errs["(other)"] += 1

    def el(self):
        return (self.t1 or time.monotonic()) - self.t0

    def rps(self):
        e = self.el()
        return self.sent / e if e > 0 else 0.0

    def as_dict(self):
        lat = list(self.lat)
        return {
            "sent": self.sent, "ok": self.ok, "http_err": self.http_err, "fail": self.fail,
            "elapsed": round(self.el(), 3), "rps": round(self.rps(), 2), "bytes": self.byt,
            "protos": dict(self.protos), "codes": {str(k): v for k, v in self.codes.items()},
            "errors": dict(self.errs), "stopped": self.stop_why,
            "lat_ms": {
                "min": self.lat_min, "avg": (self.lat_sum / (self.sent - self.fail)) if self.sent > self.fail else None,
                "p50": inf_pct(lat, 0.5), "p95": inf_pct(lat, 0.95), "p99": inf_pct(lat, 0.99), "max": self.lat_max or None,
            },
        }

    def line(self):
        lat = list(self.lat)
        p50 = inf_pct(lat, 0.5)
        p95 = inf_pct(lat, 0.95)
        pr = " ".join("%s=%d" % (k, v) for k, v in sorted(self.protos.items())) or "-"
        return "[stream] t=%.0fs sent=%d ok=%d http_err=%d fail=%d rps=%.1f p50=%s p95=%s proto: %s" % (
            self.el(), self.sent, self.ok, self.http_err, self.fail, self.rps(),
            "%.0fms" % p50 if p50 is not None else "-", "%.0fms" % p95 if p95 is not None else "-", pr)

    def text(self):
        d = self.as_dict()
        lm = d["lat_ms"]
        out = [self.line().replace("[stream]", "[stream] done")]
        out.append("  bytes=%d elapsed=%.1fs stopped=%s" % (d["bytes"], d["elapsed"], d["stopped"] or "-"))
        if lm["p50"] is not None:
            out.append("  latency ms: min=%.0f avg=%.0f p50=%.0f p95=%.0f p99=%.0f max=%.0f" % (lm["min"], lm["avg"], lm["p50"], lm["p95"], lm["p99"], lm["max"]))
        if d["codes"]:
            out.append("  status: " + " ".join("%s=%d" % (k, v) for k, v in sorted(d["codes"].items())))
        for k, v in self.errs.most_common(5):
            out.append("  error x%d: %s" % (v, k))
        return "\n".join(out)


class InfStream:
    def __init__(self, url, speed="medium", threads=None, n=None, dur=None, mth="GET", hdrs=None, body=None, json=None,
                 tick=2.0, max_fail=vso_fail_def, sink=None, **ckw):
        _vso.inf_warn()
        self.url = url
        parse_url(url)
        self.wk, self.rate = parse_speed(speed)
        if threads is not None:
            if isinstance(threads, bool) or not isinstance(threads, int) or threads < 1 or threads > vso_thr_max:
                raise ClientError("threads must be between 1 and %d" % vso_thr_max)
            self.wk = threads
        if n is not None and (not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > vso_n_max):
            raise ClientError("count must be between 1 and %d" % vso_n_max)
        if dur is not None:
            try:
                dur = float(dur)
            except (TypeError, ValueError):
                raise ClientError("duration must be a number of seconds") from None
            if not math.isfinite(dur) or dur <= 0 or dur > vso_dur_max:
                raise ClientError("duration must be between 0 and %d seconds" % vso_dur_max)
        if not isinstance(mth, str) or not re.fullmatch(r"[A-Za-z]{1,16}", mth):
            raise ClientError("bad method")
        self.mth = mth.upper()
        self.n = n
        self.dur = dur
        self.hdrs = hdrs
        self.body = body
        self.json = json
        self.tick = max(0.5, float(tick))
        self.max_fail = max(0, int(max_fail))
        self.sink = sink
        ckw.setdefault("lim", Lim(max_body=8 << 20))
        ckw.setdefault("follow", False)
        self.ckw = ckw
        self.st = InfStats()
        self.stp = False
        self.tasks = []
        self.claimed = 0
        self.end = None

    def stop(self, why="stopped"):
        if self.stp:
            for t in self.tasks:
                t.cancel()
            return
        self.stp = True
        if self.st.stop_why is None:
            self.st.stop_why = why

    def done(self):
        if self.stp:
            return True
        if self.end is not None and time.monotonic() >= self.end:
            self.stop("duration reached")
            return True
        if self.n is not None and self.claimed >= self.n:
            return True
        if self.max_fail and self.st.run_fail >= self.max_fail:
            self.stop("%d consecutive failures" % self.max_fail)
            return True
        return False

    async def one(self, ac):
        kw = {}
        if self.hdrs:
            kw["hdrs"] = self.hdrs
        if self.body is not None:
            kw["body"] = self.body
        if self.json is not None:
            kw["json"] = self.json
        t0 = time.monotonic()
        try:
            r = await ac.req(self.mth, self.url, **kw)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.st.add_err(e)
            return
        self.st.add_res(r, (time.monotonic() - t0) * 1000)

    async def worker(self, ac, rl):
        while not self.done():
            await rl.wait()
            if self.done():
                break
            self.claimed += 1
            await self.one(ac)

    async def ticker(self):
        while True:
            await asyncio.sleep(self.tick)
            if self.sink:
                self.sink(self.st.line())

    async def run(self):
        loop = asyncio.get_running_loop()
        hooked = False
        try:
            loop.add_signal_handler(signal.SIGINT, self.stop, "interrupted")
            hooked = True
        except (NotImplementedError, RuntimeError, ValueError):
            pass
        rl = InfRate(self.rate)
        tk = None
        try:
            async with AsyncClient(workers=self.wk, **self.ckw) as ac:
                self.st.t0 = time.monotonic()
                if self.dur is not None:
                    self.end = self.st.t0 + self.dur
                if self.n is None or self.n > 0:
                    self.claimed += 1
                    await self.one(ac)
                if self.sink:
                    tk = asyncio.ensure_future(self.ticker())
                self.tasks = [asyncio.ensure_future(self.worker(ac, rl)) for _ in range(self.wk)]
                try:
                    await asyncio.gather(*self.tasks, return_exceptions=True)
                except KeyboardInterrupt:
                    self.stop("interrupted")
                self.st.t1 = time.monotonic()
        finally:
            if tk is not None:
                tk.cancel()
            if hooked:
                try:
                    loop.remove_signal_handler(signal.SIGINT)
                except Exception:
                    pass
        if self.st.t1 is None:
            self.st.t1 = time.monotonic()
        if self.st.stop_why is None:
            self.st.stop_why = "count reached" if self.n is not None else "finished"
        return self.st


def run_stream(url, **kw):
    s = InfStream(url, **kw)
    try:
        return asyncio.run(s.run())
    except KeyboardInterrupt:
        s.st.t1 = time.monotonic()
        s.st.stop_why = "interrupted"
        return s.st


def stderr_line(s):
    sys.stderr.write(s + "\n")
    sys.stderr.flush()
