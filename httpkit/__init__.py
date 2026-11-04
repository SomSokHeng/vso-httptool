from . import _vso

_vso.inf_chk()

from .client import Client
from .cookie import Cookie, Jar
from .feedback import fb_err, fb_json, fb_res, fb_text
from .err import (ClientError, ConnError, H2Error, H3Error, HdrError, HpackError, HttpkitError,
                  ProxyError, QpackError, QuicError, SecError, TlsError, UrlError, BodyError)
from .hdr import Hdrs, parse_hdrs
from .msg import Req, Resp
from .proxy import InfPool as ProxyPool, Proxy, load_list, parse_proxy
from .sec import InfGuard, Lim, vso_lim
from .trace import Trace
from .ua import UaPool, VSO_UA, parse_ua, ua_str

VSO_VER = "1.2.0"
__version__ = VSO_VER
__author__ = _vso.VSO_AUTHOR
__license__ = _vso.VSO_LICENSE
VSO_NOTICE = _vso.VSO_NOTICE

__all__ = [
    "Client", "Cookie", "Jar", "Hdrs", "parse_hdrs", "Req", "Resp", "InfGuard", "Lim", "vso_lim",
    "VSO_UA", "VSO_VER", "VSO_NOTICE", "parse_ua", "ua_str", "HttpkitError", "HdrError", "UrlError", "SecError",
    "BodyError", "ConnError", "TlsError", "ClientError", "HpackError", "H2Error", "QpackError",
    "QuicError", "H3Error", "ProxyError", "Trace", "fb_res", "fb_err", "fb_text", "fb_json", "Proxy", "ProxyPool", "UaPool", "parse_proxy", "load_list",
]
