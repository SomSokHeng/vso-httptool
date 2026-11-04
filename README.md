# vso-httptool

HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) client and protocol toolkit. Pure Python. The core has zero dependencies; HTTP/3 needs `cryptography`.

The QUIC transport, TLS 1.3 handshake, QPACK, HPACK and the HTTP/2 frame engine are all implemented in this repo, not wrapped from another library.

```
git clone https://github.com/SomSokHeng/vso-httptool.git
cd vso-httptool
python install.py          # installs the library, works from any folder
python install.py --h3     # also installs cryptography for HTTP/3
```

After that, `from httpkit import Client` works anywhere, and so does the `httpkit` command. No PyPI needed.

| command | does |
|---|---|
| `python install.py -e` | link to the clone, so `git pull` and your edits apply at once |
| `python install.py --update` | `git pull --ff-only`, then reinstall |
| `python install.py --check` | show whether it imports from any folder, and whether h3 is usable |
| `python install.py --uninstall` | remove it |

The installer refuses a copy that fails the integrity seal, retries with `--break-system-packages` on externally-managed Pythons, and builds from a temporary copy so the clone stays clean. Plain `pip install .` and `pip install -r requirements.txt` still work.

On Termux, if the pip build of `cryptography` fails to load, run `pip uninstall cryptography` and `pkg install python-cryptography`. h1 and h2 work without it.

## Use

```python
from httpkit import Client

with Client() as c:
    r = c.get("https://example.com")
    print(r.status, r.proto, r.elapsed)
    print(r.json())

with Client(proto="h3", ca="my-ca.pem") as c:
    r = c.req("POST", "https://localhost:4433/api", json={"a": 1})

with Client(proto="h2") as c:
    rs = c.map(["https://example.com/%d" % i for i in range(50)])
```

`proto` is `auto` (default), `h1`, `h2` or `h3`. In `auto`, ALPN picks h2 or h1, and an `Alt-Svc: h3` response upgrades later requests to HTTP/3. A failed h3 attempt falls back to TCP and is not retried for 5 minutes.

CLI:

```
python -m httpkit -L -i --h3 https://example.com
python -m httpkit -X POST --json '{"a":1}' -H 'X-Key: v' https://example.com/api
python -m httpkit tls example.com:443
python -m httpkit ua "vso-httptool/1.0 (Linux) Mozilla/5.0"
```

## Proxies and user agents

```python
from httpkit import Client

with Client(proxies=["http://u:p@10.0.0.1:8080", "socks5h://127.0.0.1:9050"],
            rotate="round-robin",
            uas=["MyTool/1.0", "MyTool/2.0"], ua_rotate="random") as c:
    r = c.get("https://example.com")
    print(r.proxy, r.ua)
```

| option | does |
|---|---|
| `proxy="URL"` / `proxies=[...]` | one proxy or a list; `proxy="env"` reads `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` |
| `proxies={"http": ..., "https": ..., "all": ...}` | different proxies (or rotating lists) for `http://` and `https://` targets |
| `rotate=` | `round-robin` (default), `random` or `sticky` (one proxy per origin) |
| `no_proxy="a.com,.b.com,10.0.0.0/8"` | hosts that skip the proxy |
| `uas=[...]` or `uas=callable` | user-agent list or your own function; `ua_rotate=` takes the same three modes |
| `req(..., proxy="URL")` or `proxy="direct"` | override for one request |
| an explicit `User-Agent` header | wins over rotation |

Accepted forms: `http://user:pass@host:port`, `host:port`, `host:port:user:pass` and `user:pass@host:port`.

Proxy types: `http`, `https` (TLS to the proxy, including TLS inside TLS for https targets), `socks4`, `socks4a`, `socks5`, `socks5h`, each with optional `user:pass@`. `load_list(path)` reads one entry per line.

The library only accepts and rotates what you give it. It does not check proxy health, skip dead proxies, retry on another proxy, or judge user-agent age or quality. A dead proxy raises `ProxyError` or `ConnError`, and a proxy that answers 407 or 502 to a plain-http request returns that response. Handling that is your tool's job.

Notes:
- HTTP/3 does not go through proxies, so `proto="h3"` with a proxy is refused and `auto` stays on TCP.
- The target's certificate is still verified through the tunnel. An `http://` target through a proxy is visible to that proxy.
- `socks4` and `socks5` resolve the target locally. `socks4a`, `socks5h` and http(s) proxies resolve it at the proxy. The private-redirect guard always resolves locally for its own check.
- Proxy passwords are never printed. `Proxy` repr and `res.proxy` mask them.

CLI: `python -m httpkit -v -n 5 --proxy-file proxies.txt --rotate random --ua-file agents.txt https://example.com`

## Verbose, problems and feedback

```python
from httpkit import Client, fb_err, fb_text

with Client(verbose=True) as c:
    try:
        r = c.get("https://example.com")
        print(r.feedback(text=True))
        data = r.feedback()
    except Exception as e:
        print(fb_text(fb_err(e)))
```

- `verbose=True` prints every step live to stderr: DNS, TCP, proxy handshake, TLS, connection reuse, request, response, redirects, retries, cookies, decoding. `verbose=fn` sends each event dict to your function instead.
- `r.feedback()` returns a report dict (`text=True` gives a printable report): timing (dns, tcp, proxy, tls, ttfb, total), TLS version, cipher and certificate days left, body size and decoding, redirects, problems and notes.
- A problem is something that went wrong or looks wrong: 4xx/5xx and 407/429, a retried stale connection, slow first byte, an expiring certificate, disabled verification. A note is an observation about the server, such as a missing HSTS header, a version in the Server banner, or cookies without Secure/HttpOnly/SameSite.
- Failures carry the same trace: `fb_err(exc)` gives the stage (`dns`, `tcp`, `proxy`, `tls`, `http2`, ...), the cause chain and a hint. `exc.vso_trace` and `r.trace` hold the raw events.
- This only reports. It never skips a proxy, retries elsewhere or changes behavior.

CLI: `-v` streams every step and ends with a problem summary, `-fb` prints the feedback report after each result or failure, and `--feedback-json` prints it as JSON. All of it goes to stderr, so the body on stdout stays clean. With `-n`, a failed request does not stop the rest.

## Layout

| module | role |
|---|---|
| `client.py` | pooling, protocol selection, Alt-Svc, cookies, redirects, retries |
| `h1.py` `body.py` | HTTP/1.1 wire format, chunked, content-encoding with bomb limits |
| `h2.py` `hpack.py` | HTTP/2 multiplexed client, flow control, full HPACK |
| `quic.py` `tls13.py` | QUIC v1 transport (RFC 9000/9001/9002) and TLS 1.3 client handshake |
| `h3.py` `qpack.py` | HTTP/3 (RFC 9114) and QPACK static-table codec |
| `sec.py` `follow.py` | limits, SSRF guard, redirect policy |
| `trace.py` `feedback.py` | step events, timings, problems, notes, hints |
| `proxy.py` | proxy parsing, rotation, HTTP CONNECT, SOCKS4/4a/5/5h, TLS-in-TLS |
| `cookie.py` `url.py` `hdr.py` `msg.py` `ua.py` | supporting pieces |
| `tls.py` `conn.py` | TCP/TLS connect and TLS session inspection |

## Hardening

- Header names and values are validated on every add. CR, LF and NUL are rejected, which blocks header injection and response splitting.
- HTTP/1.1 parsing rejects `Content-Length` with `Transfer-Encoding`, conflicting or malformed `Content-Length`, obfuscated or stacked transfer-codings, obs-fold and bare control characters. This closes the usual request-smuggling vectors.
- DNS is resolved once and the connection is pinned to that IP.
- Redirects cannot downgrade https to http or change scheme. They cannot move from a public host into private, loopback or link-local space, which blocks redirect-based SSRF. Credentials and cookies are stripped on cross-origin hops, with loop detection and a hop limit.
- Certificates and hostnames are verified by default on all three protocols. `verify=False` is explicit.
- Decompression has a size cap, a ratio cap and a layer cap.
- HTTP/2: PUSH_PROMISE is refused, control-frame floods, CONTINUATION floods and HPACK bombs are bounded, window overflows are enforced, and response headers are validated (pseudo-header order, uppercase names, connection-specific headers, content-length vs received bytes).
- QUIC and HTTP/3: flow-control violations, final-size changes, stream-limit abuse, crypto-buffer overflow, transport-parameter mismatches, and malformed or forbidden HTTP/3 frames close the connection.
- The CLI escapes terminal control sequences in headers and bodies when writing to a TTY.

## Author seal and notice

The author and license notice are constants in `httpkit/_vso.py`, and the package seals itself. Every module in `httpkit/` is hashed into `_seal.py`, and a root hash is stored in `_vso.py`. `import httpkit` raises `ImportError` if any file, the notice, or the seal has been changed. Using the tool (`Client()`, `tls.insp()`, the CLI) prints the authorized-use warning and the notice once per process to stderr, so piped output stays clean.

The license is still MIT. MIT allows modification, so the seal is tamper-evidence, not a lock. If you edit the code, run `python tools/seal.py` and keep the copyright notice and `LICENSE` as MIT requires. A determined person can remove the check in minutes, so the legal protection is the MIT copyright notice, not the code.

## Status and limits

Tested: 84 tests (live and QUIC tests skip themselves if `cryptography` is unusable). They cover the RFC 7541 and RFC 9001 vectors, wire-level attack cases, a malicious HTTP/2 server, and live interop against `hypercorn` (aioquic) over h1, h2 and h3. The h3 live tests include a 3 MB download, a 300 KB upload, 30 concurrent streams, Alt-Svc upgrade, and downloads that complete under 5% and 15% simulated packet loss.

Not yet tested against large public HTTP/3 servers. Interop so far is with aioquic.

Not implemented:
- QPACK dynamic table: capacity is advertised as 0, so servers send literals and static references only.
- 0-RTT, session resumption, connection migration, HelloRetryRequest (x25519 only), server push, client certificates.
- QUIC congestion control. The client sends small requests and relies on flow control and the server's pacing.
- Certificate verification uses `cryptography`'s WebPKI verifier, so private CAs passed via `ca=` need a normal leaf profile (SAN, Authority Key Identifier).

```
python -m unittest discover -s tests
```
