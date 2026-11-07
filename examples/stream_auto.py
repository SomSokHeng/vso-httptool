import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpkit import AsyncClient, InfGuard, InfStream
from httpkit.stream import stderr_line

vso_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/"
inf_grd = InfGuard(blk_priv=True)


async def vso_gather():
    async with AsyncClient(workers=20, proto="auto", guard=inf_grd, tmo=15) as ac:
        rs = await ac.gather([vso_url] * 40, exc=True)
        ok = [r for r in rs if not isinstance(r, Exception)]
        print("gather: %d/%d ok, protos: %s" % (len(ok), len(rs), sorted({r.proto for r in ok})))


async def inf_loop():
    s = InfStream(vso_url, speed="medium", dur=10, proto="auto", guard=inf_grd, tmo=15, sink=stderr_line)
    st = await s.run()
    print(st.text())


asyncio.run(vso_gather())
asyncio.run(inf_loop())
