from . import _vso

_vso.inf_chk()

from .client import Client
from .cookie import Cookie, Jar
from .err import (ClientError, ConnError, H2Error, H3Error, HdrError, HpackError, HttpkitError,
                  QpackError, QuicError, SecError, TlsError, UrlError, BodyError)
from .hdr import Hdrs, parse_hdrs
from .msg import Req, Resp
from .sec import InfGuard, Lim, vso_lim
from .ua import VSO_UA, parse_ua, ua_str

VSO_VER = "1.0.3"
__version__ = VSO_VER
__author__ = _vso.VSO_AUTHOR
__license__ = _vso.VSO_LICENSE
VSO_NOTICE = _vso.VSO_NOTICE

__all__ = [
    "Client", "Cookie", "Jar", "Hdrs", "parse_hdrs", "Req", "Resp", "InfGuard", "Lim", "vso_lim",
    "VSO_UA", "VSO_VER", "VSO_NOTICE", "parse_ua", "ua_str", "HttpkitError", "HdrError", "UrlError", "SecError",
    "BodyError", "ConnError", "TlsError", "ClientError", "HpackError", "H2Error", "QpackError",
    "QuicError", "H3Error",
]
