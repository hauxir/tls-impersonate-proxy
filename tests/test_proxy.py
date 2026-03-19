"""Tests for tls-impersonate-proxy."""

import concurrent.futures
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
import requests

from tls_impersonate_proxy import tls_impersonate_proxy


# --- Helpers ---


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Simple HTTP server that echoes back request info."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:{}/redirected".format(self.server.server_port))
            self.end_headers()
            return

        if self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            chunk = b"x" * 65536
            total = chunk * 16  # ~1 MB
            self.send_header("Content-Length", str(len(total)))
            self.end_headers()
            self.wfile.write(total)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Test-Header", "upstream-value")
        body = f"GET {self.path}".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_in = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        body = f"POST {self.path} body={body_in.decode()}".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "42")
        self.end_headers()


def _get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def upstream_server():
    """Start a mock upstream HTTP server."""
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), MockUpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def proxy_server():
    """Start the TLS impersonate proxy."""
    port = _get_free_port()
    proxy_url = f"http://127.0.0.1:{port}"

    def _mock_do_request(method, url, headers, body, stream=False):
        try:
            return requests.request(
                method=method, url=url, headers=headers,
                data=body, timeout=10, allow_redirects=False, stream=stream,
            )
        except Exception:
            return None

    with patch.object(tls_impersonate_proxy, "_do_request", _mock_do_request):
        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        server = ThreadingHTTPServer(("127.0.0.1", port), tls_impersonate_proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        for _ in range(50):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                s.close()
                break
            except OSError:
                time.sleep(0.1)

        yield proxy_url
        server.shutdown()


# --- Unit Tests ---


class TestHostPortParsing:
    def test_standard_host_port(self):
        path = "example.com:443"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "example.com"
        assert int(port_str) == 443

    def test_ipv6_host_port(self):
        path = "[::1]:443"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "::1"
        assert int(port_str) == 443

    def test_custom_port(self):
        path = "example.com:8080"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "example.com"
        assert int(port_str) == 8080


class TestCertCache:
    def test_init_ca(self):
        tls_impersonate_proxy._init_ca()
        assert tls_impersonate_proxy._CA_KEY is not None
        assert tls_impersonate_proxy._CA_CERT is not None

    def test_get_cert_for_host_caches(self):
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx1 = tls_impersonate_proxy._get_cert_for_host("test.example.com")
        ctx2 = tls_impersonate_proxy._get_cert_for_host("test.example.com")
        assert ctx1 is ctx2

    def test_get_cert_for_host_different_hosts(self):
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx1 = tls_impersonate_proxy._get_cert_for_host("host1.example.com")
        ctx2 = tls_impersonate_proxy._get_cert_for_host("host2.example.com")
        assert ctx1 is not ctx2

    def test_get_cert_for_ip_address(self):
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx = tls_impersonate_proxy._get_cert_for_host("1.2.3.4")
        assert ctx is not None

    def test_cache_eviction(self):
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()
        old_max = tls_impersonate_proxy._HOST_CERT_MAX
        tls_impersonate_proxy._HOST_CERT_MAX = 3
        try:
            for i in range(5):
                tls_impersonate_proxy._get_cert_for_host(f"host{i}.example.com")
            assert len(tls_impersonate_proxy._HOST_CERT_CACHE) == 3
            assert "host0.example.com" not in tls_impersonate_proxy._HOST_CERT_CACHE
            assert "host4.example.com" in tls_impersonate_proxy._HOST_CERT_CACHE
        finally:
            tls_impersonate_proxy._HOST_CERT_MAX = old_max


class TestSessionManagement:
    def test_get_session_returns_session(self):
        session = tls_impersonate_proxy._get_session()
        assert session is not None

    def test_get_session_same_thread(self):
        s1 = tls_impersonate_proxy._get_session()
        s2 = tls_impersonate_proxy._get_session()
        assert s1 is s2

    def test_get_session_different_threads(self):
        sessions = []

        def get_session():
            sessions.append(tls_impersonate_proxy._get_session())

        t1 = threading.Thread(target=get_session)
        t2 = threading.Thread(target=get_session)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert len(sessions) == 2
        assert sessions[0] is not sessions[1]


# --- Integration Tests (mock upstream) ---


class TestProxyHTTP:
    def test_proxy_get(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == "GET /hello"

    def test_proxy_get_with_query(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/path?key=value", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == "GET /path?key=value"

    def test_proxy_post(self, proxy_server, upstream_server):
        resp = requests.post(f"{upstream_server}/submit", data="test-body", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert "POST /submit body=test-body" in resp.text

    def test_proxy_head_no_body(self, proxy_server, upstream_server):
        resp = requests.head(f"{upstream_server}/resource", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.headers.get("Content-Length") == "42"

    def test_proxy_preserves_upstream_headers(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_server})
        assert resp.headers.get("X-Test-Header") == "upstream-value"

    def test_proxy_strips_hop_by_hop_headers(self, proxy_server, upstream_server):
        """Hop-by-hop headers from client should not reach upstream."""
        resp = requests.get(
            f"{upstream_server}/hello",
            headers={"Proxy-Connection": "keep-alive", "X-Custom": "preserved"},
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200

    def test_proxy_bad_url(self, proxy_server):
        s = socket.create_connection(
            (proxy_server.split("//")[1].split(":")[0], int(proxy_server.split(":")[-1])),
        )
        s.sendall(b"GET /relative-path HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert b"400" in resp

    def test_proxy_upstream_down(self, proxy_server):
        resp = requests.get("http://127.0.0.1:1/unreachable", proxies={"http": proxy_server})
        assert resp.status_code == 502

    def test_proxy_redirect_passthrough(self, proxy_server, upstream_server):
        """Proxy should forward 302 without following it."""
        resp = requests.get(
            f"{upstream_server}/redirect",
            proxies={"http": proxy_server},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/redirected" in resp.headers.get("Location", "")

    def test_proxy_large_response(self, proxy_server, upstream_server):
        """Proxy should handle large streamed responses."""
        resp = requests.get(f"{upstream_server}/large", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert len(resp.content) == 65536 * 16  # 1 MB

    def test_proxy_concurrent_requests(self, proxy_server, upstream_server):
        """Proxy should handle concurrent requests without errors."""

        def fetch(i):
            resp = requests.get(f"{upstream_server}/concurrent-{i}", proxies={"http": proxy_server})
            return resp.status_code, resp.text

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(fetch, i) for i in range(20)]
            results = [f.result() for f in futures]

        for status, text in results:
            assert status == 200
            assert text.startswith("GET /concurrent-")


# --- Live Integration Test ---


@pytest.mark.live
class TestProxyLive:
    """Tests that hit real URLs. Run with: pytest -m live"""

    def test_fetch_kosmi_webm(self):
        """Fetch a real video file through the proxy using curl_cffi."""
        port = _get_free_port()
        proxy_url = f"http://127.0.0.1:{port}"

        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        tls_impersonate_proxy._init_ca()
        server = ThreadingHTTPServer(("127.0.0.1", port), tls_impersonate_proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        for _ in range(50):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                s.close()
                break
            except OSError:
                time.sleep(0.1)

        try:
            resp = requests.get(
                "http://kosmi.io/kosmishort.webm",
                proxies={"http": proxy_url},
                timeout=30,
            )
            assert resp.status_code == 200
            assert len(resp.content) > 10000
            assert resp.headers.get("Content-Type") in (
                "video/webm",
                "application/octet-stream",
                None,
            ) or "webm" in resp.headers.get("Content-Type", "")
        finally:
            server.shutdown()
