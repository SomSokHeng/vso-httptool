import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpkit import Client, HttpkitError, fb_err, fb_text

vso_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/"
inf_log = []

print("-- live trace on stderr, report on stdout")
with Client(verbose=True, tmo=10) as cl:
    try:
        res = cl.get(vso_url)
        print(res.feedback(text=True))
    except (HttpkitError, OSError) as e:
        print(fb_text(fb_err(e)))

print("-- your own event handler")
with Client(verbose=inf_log.append, tmo=10) as cl:
    try:
        cl.get(vso_url)
    except (HttpkitError, OSError):
        pass
print(len(inf_log), "events:", sorted({e["kind"] for e in inf_log}))

print("-- a failure with stage and hint")
with Client(tmo=5) as cl:
    try:
        cl.get("http://no-such-host.invalid/")
    except HttpkitError as e:
        print(fb_text(fb_err(e)))
