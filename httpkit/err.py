class HttpkitError(Exception):
    pass


class HdrError(HttpkitError):
    pass


class UrlError(HttpkitError):
    pass


class SecError(HttpkitError):
    pass


class BodyError(HttpkitError):
    pass


class ConnError(HttpkitError):
    pass


class TlsError(ConnError):
    pass


class ClientError(HttpkitError):
    pass


class ProxyError(ConnError):
    pass


class HpackError(HttpkitError):
    pass


class H2Error(HttpkitError):
    def __init__(self, msg, code=1):
        super().__init__(msg)
        self.code = code


class QpackError(HttpkitError):
    pass


class QuicError(ConnError):
    def __init__(self, msg, code=0):
        super().__init__(msg)
        self.code = code


class QuicReset(QuicError):
    pass


class H3Error(HttpkitError):
    def __init__(self, msg, code=0x101):
        super().__init__(msg)
        self.code = code
