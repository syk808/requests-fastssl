"""Make ``requests`` reuse one preloaded SSLContext for the whole process.

Background (measured with requests 2.33.1 / urllib3 2.6.3 / OpenSSL 3.0.16 on Windows):
for every new HTTPS connection urllib3 calls ``load_verify_locations`` on a fresh
SSLContext with certifi's ``cacert.pem``. That is roughly 136k small reads and
0.5-0.75 s of CPU per connection. Code that calls ``requests.get`` / ``requests.post``
without a Session opens a new connection on every call, so the cost is paid every time.

What this module does is the "preloaded SSLContext" approach that requests 2.32.0 shipped
and 2.32.5 reverted: the default CA bundle is loaded once per process, and every connection
that uses ``verify=True`` with the default CA bundle shares that context. Verification
is unchanged (CERT_REQUIRED + hostname check); only the repeated file loading goes away.

Left untouched (they take the stock code path): ``verify=False``, ``verify="/some/path"``,
client certificates (``cert=``), and processes where the ``REQUESTS_CA_BUNDLE`` or
``CURL_CA_BUNDLE`` environment variable is set.

Usage: ``import requests_fastssl`` as early as possible in the process entry point.
Importing is enough; importing again is a no-op.
Set the environment variable ``REQUESTS_FASTSSL=0`` to turn the whole thing off.
"""
from __future__ import annotations

import os
import threading

import requests
from requests import adapters as _adapters

try:
    from urllib3.util.ssl_ import create_urllib3_context
except Exception:  # pragma: no cover - urllib3 layout changed: stay disabled
    create_urllib3_context = None

__all__ = ["install", "STATS"]

_LOCK = threading.Lock()
_CTX = None
_INSTALLED = False
STATS = {"shared": 0, "fallback": 0}


def _shared_context():
    """Load the default CA bundle exactly once. Raises if loading fails; callers fall back."""
    global _CTX
    if _CTX is None:
        with _LOCK:
            if _CTX is None:
                ctx = create_urllib3_context()
                ctx.load_verify_locations(_adapters.DEFAULT_CA_BUNDLE_PATH)
                _CTX = ctx
    return _CTX


def _eligible(url, verify, cert) -> bool:
    return (
        verify is True
        and not cert
        and str(url).lower().startswith("https")
        and not os.environ.get("REQUESTS_CA_BUNDLE")
        and not os.environ.get("CURL_CA_BUNDLE")
    )


def install() -> bool:
    """Patch ``requests.adapters.HTTPAdapter``. Returns True if the patch is active."""
    global _INSTALLED
    if _INSTALLED:
        return True
    if os.environ.get("REQUESTS_FASTSSL", "1") == "0" or create_urllib3_context is None:
        return False
    adapter = _adapters.HTTPAdapter
    orig_init_poolmanager = adapter.init_poolmanager
    orig_proxy_manager_for = adapter.proxy_manager_for
    orig_cert_verify = adapter.cert_verify

    def init_poolmanager(self, connections, maxsize, block=_adapters.DEFAULT_POOLBLOCK, **pool_kwargs):
        try:
            pool_kwargs.setdefault("ssl_context", _shared_context())
        except Exception:
            pool_kwargs.pop("ssl_context", None)
        return orig_init_poolmanager(self, connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        # Through an HTTP(S) proxy the TLS session to the target host uses the same context.
        # SOCKS proxy managers are left alone.
        if not str(proxy).lower().startswith("socks"):
            try:
                proxy_kwargs.setdefault("ssl_context", _shared_context())
            except Exception:
                proxy_kwargs.pop("ssl_context", None)
        return orig_proxy_manager_for(self, proxy, **proxy_kwargs)

    def cert_verify(self, conn, url, verify, cert):
        orig_cert_verify(self, conn, url, verify, cert)
        shared = getattr(conn, "conn_kw", {}).get("ssl_context") if hasattr(conn, "conn_kw") else None
        if _eligible(url, verify, cert) and shared is not None and shared is _CTX:
            # The context already holds the default CA bundle; stop urllib3 from re-reading
            # the file for every connection. cert_reqs stays CERT_REQUIRED.
            conn.ca_certs = None
            conn.ca_cert_dir = None
            STATS["shared"] += 1
        else:
            if str(url).lower().startswith("https"):
                STATS["fallback"] += 1
            if shared is not None and shared is _CTX and not _eligible(url, verify, cert):
                # verify=False / custom CA / client cert: the shared context must not be
                # modified, so this pool goes back to letting urllib3 build its own.
                conn.conn_kw.pop("ssl_context", None)

    adapter.init_poolmanager = init_poolmanager
    adapter.proxy_manager_for = proxy_manager_for
    adapter.cert_verify = cert_verify
    _INSTALLED = True
    return True


install()
