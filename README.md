# requests-fastssl

A single-file monkeypatch that makes `requests` reuse one preloaded `SSLContext`
for the whole process.

## The problem

With requests 2.33 / urllib3 2.x, every new HTTPS connection builds a fresh
`SSLContext` and calls `load_verify_locations()` on certifi's `cacert.pem`.
Parsing that bundle is not free. Code that calls `requests.get()` /
`requests.post()` directly (no `Session`) opens a new connection per call, so it
pays that cost on every call.

Measured on one Windows machine with requests 2.33.1, urllib3 2.6.3 and
OpenSSL 3.0.16: about 0.5-0.75 s of CPU per new HTTPS connection. That is a
single measurement on a single machine, not a benchmark; the cost on other
platforms and versions may be much smaller. Measure before assuming you need this.

requests 2.32 shipped a preloaded default context and 2.33 removed it. This
module does the same thing from the outside: the default CA bundle is loaded once,
and connections that use `verify=True` with the default bundle share that context.
Certificate verification is unchanged (`CERT_REQUIRED` plus hostname check).

## Usage

Copy `requests_fastssl.py` into your project and import it once, as early as
possible in the process entry point:

```python
import requests_fastssl  # importing is enough; importing again is a no-op

import requests

requests.get("https://example.com")   # shares the preloaded context
print(requests_fastssl.STATS)         # {'shared': 1, 'fallback': 0}
```

`STATS` counts HTTPS requests that used the shared context (`shared`) and those
that took the stock path (`fallback`). The counters are plain ints updated without
a lock, so treat them as approximate under threads.

## Disabling

Set the environment variable `REQUESTS_FASTSSL=0` before the process starts.
The module then patches nothing.

## What is left untouched

These requests take the normal requests/urllib3 code path:

- `verify=False`
- `verify="/path/to/ca.pem"` (custom CA file or directory)
- client certificates (`cert=...`)
- any request while `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` is set
- plain `http://` URLs
- SOCKS proxies (HTTP/HTTPS proxies do get the shared context)

If loading the default CA bundle fails, the patch falls back to stock behaviour.

## Caveats

- It patches `requests.adapters.HTTPAdapter` methods (`init_poolmanager`,
  `proxy_manager_for`, `cert_verify`) at import time, for the whole process.
  Subclasses that override these methods without calling `super()` are not covered.
- It depends on requests/urllib3 internals. It was written against requests 2.33.1
  and urllib3 2.6.3; other versions are untested. If
  `urllib3.util.ssl_.create_urllib3_context` cannot be imported, nothing is patched.
- The CA bundle is read once. If the bundle file changes while the process is
  running, the change is not picked up until restart.
- Using a `requests.Session` already avoids most of the cost for repeated calls to
  the same host, because connections are reused. This module mainly helps code that
  cannot easily be changed to use sessions.

## Tests

The tests use `unittest` only and make no network connections.

```
python -m unittest discover -s tests
```

## License

MIT
