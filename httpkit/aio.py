import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor

from . import _vso
from .client import Client
from .err import ClientError

vso_thr_max = 50
vso_thr_def = 16


def inf_thr(n):
    if isinstance(n, bool) or not isinstance(n, int):
        raise ClientError("workers must be an integer")
    if n < 1 or n > vso_thr_max:
        raise ClientError("workers must be between 1 and %d" % vso_thr_max)
    return n


class AsyncClient:
    def __init__(self, workers=vso_thr_def, **kw):
        _vso.inf_warn()
        self.workers = inf_thr(workers)
        self.c = Client(**kw)
        self.ex = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="inf-aio")
        self.sem = None
        self.shut = False

    @property
    def client(self):
        return self.c

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        await self.aclose()

    async def aclose(self):
        if self.shut:
            return
        self.shut = True
        self.ex.shutdown(wait=False, cancel_futures=True)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.c.close)

    def lim(self):
        if self.sem is None:
            self.sem = asyncio.Semaphore(self.workers)
        return self.sem

    async def req(self, mth, url, **kw):
        if self.shut:
            raise ClientError("AsyncClient is closed")
        loop = asyncio.get_running_loop()
        async with self.lim():
            return await loop.run_in_executor(self.ex, functools.partial(self.c.req, mth, url, **kw))

    async def get(self, url, **kw):
        return await self.req("GET", url, **kw)

    async def head(self, url, **kw):
        return await self.req("HEAD", url, **kw)

    async def post(self, url, **kw):
        return await self.req("POST", url, **kw)

    async def put(self, url, **kw):
        return await self.req("PUT", url, **kw)

    async def patch(self, url, **kw):
        return await self.req("PATCH", url, **kw)

    async def delete(self, url, **kw):
        return await self.req("DELETE", url, **kw)

    async def options(self, url, **kw):
        return await self.req("OPTIONS", url, **kw)

    def feedback(self, x, text=False, events=False):
        return self.c.feedback(x, text, events)

    async def gather(self, urls, exc=False, **kw):
        async def go(x):
            if isinstance(x, tuple):
                return await self.req(x[0], x[1], **kw)
            return await self.req("GET", x, **kw)
        return await asyncio.gather(*[go(x) for x in urls], return_exceptions=exc)

    async def imap(self, urls, win=None, **kw):
        win = max(1, min(win or self.workers * 2, 4096))
        it = iter(urls)
        run = set()

        def spawn():
            try:
                x = next(it)
            except StopIteration:
                return False
            if isinstance(x, tuple):
                run.add(asyncio.ensure_future(self.req(x[0], x[1], **kw)))
            else:
                run.add(asyncio.ensure_future(self.req("GET", x, **kw)))
            return True

        try:
            while len(run) < win and spawn():
                pass
            while run:
                dn, _ = await asyncio.wait(run, return_when=asyncio.FIRST_COMPLETED)
                for t in dn:
                    run.discard(t)
                    try:
                        yield t.result()
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        yield e
                while len(run) < win and spawn():
                    pass
        finally:
            for t in run:
                t.cancel()
