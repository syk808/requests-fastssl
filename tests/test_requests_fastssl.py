"""Tests for requests_fastssl. No network access: only pools and adapters are built."""
import os
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.pop("REQUESTS_FASTSSL", None)

import requests  # noqa: E402
from requests import adapters  # noqa: E402

import requests_fastssl  # noqa: E402

URL = "https://example.invalid/path"
_CA_ENV = {"REQUESTS_CA_BUNDLE": "", "CURL_CA_BUNDLE": ""}


def _pool(adapter, url=URL):
    return adapter.poolmanager.connection_from_url(url)


class InstallTests(unittest.TestCase):
    def test_installed_on_import_and_idempotent(self):
        self.assertTrue(requests_fastssl._INSTALLED)
        before = adapters.HTTPAdapter.cert_verify
        self.assertTrue(requests_fastssl.install())
        self.assertIs(adapters.HTTPAdapter.cert_verify, before)

    def test_shared_context_is_loaded_once_and_still_verifies(self):
        ctx = requests_fastssl._shared_context()
        self.assertIs(requests_fastssl._shared_context(), ctx)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)

    def test_pool_manager_gets_the_shared_context(self):
        adapter = adapters.HTTPAdapter()
        self.assertIs(adapter.poolmanager.connection_pool_kw.get("ssl_context"),
                      requests_fastssl._shared_context())

    def test_session_adapters_get_the_shared_context(self):
        with requests.Session() as session:
            adapter = session.get_adapter(URL)
            self.assertIs(adapter.poolmanager.connection_pool_kw.get("ssl_context"),
                          requests_fastssl._shared_context())

    def test_http_proxy_manager_gets_the_shared_context_and_socks_is_skipped(self):
        adapter = adapters.HTTPAdapter()
        manager = adapter.proxy_manager_for("http://proxy.invalid:3128")
        self.assertIs(manager.connection_pool_kw.get("ssl_context"), requests_fastssl._shared_context())
        with mock.patch.object(requests_fastssl, "_shared_context") as shared:
            try:
                adapter.proxy_manager_for("socks5://proxy.invalid:1080")
            except requests.exceptions.InvalidSchema:
                pass  # PySocks is not installed; only the branch taken matters here
            shared.assert_not_called()

    def test_load_failure_falls_back_to_stock_behaviour(self):
        with mock.patch.object(requests_fastssl, "_shared_context", side_effect=OSError("no bundle")):
            adapter = adapters.HTTPAdapter()
        self.assertNotIn("ssl_context", adapter.poolmanager.connection_pool_kw)


class CertVerifyTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, _CA_ENV)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.adapter = adapters.HTTPAdapter()
        self.addCleanup(self.adapter.close)
        self.shared = requests_fastssl._shared_context()
        self.before = dict(requests_fastssl.STATS)

    def _delta(self, key):
        return requests_fastssl.STATS[key] - self.before[key]

    def test_default_verify_uses_shared_context_without_reloading_the_bundle(self):
        conn = _pool(self.adapter)
        self.adapter.cert_verify(conn, URL, True, None)
        self.assertEqual(conn.cert_reqs, "CERT_REQUIRED")
        self.assertIsNone(conn.ca_certs)
        self.assertIsNone(conn.ca_cert_dir)
        self.assertIs(conn.conn_kw.get("ssl_context"), self.shared)
        self.assertEqual(self._delta("shared"), 1)
        self.assertEqual(self._delta("fallback"), 0)

    def test_verify_false_is_left_alone(self):
        conn = _pool(self.adapter)
        self.adapter.cert_verify(conn, URL, False, None)
        self.assertEqual(conn.cert_reqs, "CERT_NONE")
        self.assertNotIn("ssl_context", conn.conn_kw)
        self.assertEqual(self._delta("shared"), 0)
        self.assertEqual(self._delta("fallback"), 1)
        # the shared context itself was not weakened
        self.assertEqual(self.shared.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self.shared.check_hostname)

    def test_custom_ca_path_is_left_alone(self):
        bundle = adapters.DEFAULT_CA_BUNDLE_PATH
        conn = _pool(self.adapter)
        self.adapter.cert_verify(conn, URL, bundle, None)
        self.assertEqual(conn.cert_reqs, "CERT_REQUIRED")
        self.assertEqual(conn.ca_certs, bundle)
        self.assertNotIn("ssl_context", conn.conn_kw)
        self.assertEqual(self._delta("fallback"), 1)

    def test_client_cert_is_left_alone(self):
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as fh:
            fh.write(b"placeholder")
            cert_path = fh.name
        self.addCleanup(os.unlink, cert_path)
        conn = _pool(self.adapter)
        self.adapter.cert_verify(conn, URL, True, cert_path)
        self.assertEqual(conn.cert_file, cert_path)
        self.assertEqual(conn.ca_certs, adapters.DEFAULT_CA_BUNDLE_PATH)
        self.assertNotIn("ssl_context", conn.conn_kw)
        self.assertEqual(self._delta("shared"), 0)
        self.assertEqual(self._delta("fallback"), 1)

    def test_env_ca_bundle_is_left_alone(self):
        for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            with self.subTest(env=name), mock.patch.dict(os.environ, {name: adapters.DEFAULT_CA_BUNDLE_PATH}):
                conn = _pool(self.adapter, "https://%s.example.invalid/" % name.lower().replace("_", "-"))
                self.adapter.cert_verify(conn, URL, True, None)
                self.assertEqual(conn.ca_certs, adapters.DEFAULT_CA_BUNDLE_PATH)
                self.assertNotIn("ssl_context", conn.conn_kw)
        self.assertEqual(self._delta("shared"), 0)
        self.assertEqual(self._delta("fallback"), 2)

    def test_plain_http_is_not_counted(self):
        url = "http://example.invalid/"
        conn = _pool(self.adapter, url)
        self.adapter.cert_verify(conn, url, True, None)
        self.assertEqual(self._delta("shared"), 0)
        self.assertEqual(self._delta("fallback"), 0)

    def test_eligibility_rules(self):
        ok = requests_fastssl._eligible
        self.assertTrue(ok(URL, True, None))
        self.assertTrue(ok("HTTPS://EXAMPLE.INVALID", True, None))
        self.assertFalse(ok(URL, False, None))
        self.assertFalse(ok(URL, "/some/ca.pem", None))
        self.assertFalse(ok(URL, True, "client.pem"))
        self.assertFalse(ok(URL, True, ("client.pem", "client.key")))
        self.assertFalse(ok("http://example.invalid", True, None))
        with mock.patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "/x.pem"}):
            self.assertFalse(ok(URL, True, None))
        with mock.patch.dict(os.environ, {"CURL_CA_BUNDLE": "/x.pem"}):
            self.assertFalse(ok(URL, True, None))


class DisableSwitchTests(unittest.TestCase):
    def _run(self, value):
        code = (
            "from requests import adapters\n"
            "orig = adapters.HTTPAdapter.cert_verify\n"
            "import requests_fastssl\n"
            "print(requests_fastssl.install(), adapters.HTTPAdapter.cert_verify is orig)\n"
        )
        env = dict(os.environ)
        env.pop("REQUESTS_FASTSSL", None)
        if value is not None:
            env["REQUESTS_FASTSSL"] = value
        env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                env=env, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_env_zero_disables_the_patch(self):
        self.assertEqual(self._run("0"), "False True")

    def test_enabled_by_default_and_for_other_values(self):
        self.assertEqual(self._run(None), "True False")
        self.assertEqual(self._run("1"), "True False")


if __name__ == "__main__":
    unittest.main()
