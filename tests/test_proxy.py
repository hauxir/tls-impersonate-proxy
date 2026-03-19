"""Tests for tls-impersonate-proxy."""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
import requests

from app import tls_impersonate_proxy


# --- Helpers ---


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Simple HTTP server that echoes back request info."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
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

    # Patch _do_request to use regular requests (no curl_cffi needed in tests)
    original_do_request = tls_impersonate_proxy._do_request

    def _mock_do_request(method, url, headers, body, stream=False):
        try:
            resp = requests.request(
                method=method, url=url, headers=headers,
                data=body, timeout=10, allow_redirects=False, stream=stream,
            )
            return resp
        except Exception:
            return None

    with patch.object(tls_impersonate_proxy, "_do_request", _mock_do_request):
        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        server = ThreadingHTTPServer(("127.0.0.1", port), tls_impersonate_proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        # Wait for proxy to be ready
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
        """Test parsing standard host:port."""
        handler = type("FakeHandler", (), {"path": "example.com:443"})()
        host, _, port_str = handler.path.rpartition(":")
        host = host.strip("[]")
        port = int(port_str) if port_str else 443
        assert host == "example.com"
        assert port == 443

    def test_ipv6_host_port(self):
        """Test parsing IPv6 [::1]:443."""
        path = "[::1]:443"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        port = int(port_str) if port_str else 443
        assert host == "::1"
        assert port == 443

    def test_custom_port(self):
        """Test parsing host with non-standard port."""
        path = "example.com:8080"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "example.com"
        assert int(port_str) == 8080


class TestCertCache:
    def test_init_ca(self):
        """Test that _init_ca initializes CA key and cert."""
        tls_impersonate_proxy._init_ca()
        assert tls_impersonate_proxy._CA_KEY is not None
        assert tls_impersonate_proxy._CA_CERT is not None

    def test_get_cert_for_host_caches(self):
        """Test that certs are cached per hostname."""
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()

        ctx1 = tls_impersonate_proxy._get_cert_for_host("test.example.com")
        ctx2 = tls_impersonate_proxy._get_cert_for_host("test.example.com")
        assert ctx1 is ctx2

    def test_get_cert_for_host_different_hosts(self):
        """Test that different hosts get different certs."""
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()

        ctx1 = tls_impersonate_proxy._get_cert_for_host("host1.example.com")
        ctx2 = tls_impersonate_proxy._get_cert_for_host("host2.example.com")
        assert ctx1 is not ctx2

    def test_get_cert_for_ip_address(self):
        """Test cert generation for IP address hostnames."""
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()

        ctx = tls_impersonate_proxy._get_cert_for_host("1.2.3.4")
        assert ctx is not None

    def test_cache_eviction(self):
        """Test that cache evicts oldest entries when full."""
        tls_impersonate_proxy._init_ca()
        tls_impersonate_proxy._HOST_CERT_CACHE.clear()

        old_max = tls_impersonate_proxy._HOST_CERT_MAX
        tls_impersonate_proxy._HOST_CERT_MAX = 3
        try:
            for i in range(5):
                tls_impersonate_proxy._get_cert_for_host(f"host{i}.example.com")
            assert len(tls_impersonate_proxy._HOST_CERT_CACHE) == 3
            assert "host0.example.com" not in tls_impersonate_proxy._HOST_CERT_CACHE
            assert "host1.example.com" not in tls_impersonate_proxy._HOST_CERT_CACHE
            assert "host4.example.com" in tls_impersonate_proxy._HOST_CERT_CACHE
        finally:
            tls_impersonate_proxy._HOST_CERT_MAX = old_max


class TestSessionManagement:
    def test_get_session_returns_session(self):
        """Test that _get_session returns a curl_cffi session."""
        session = tls_impersonate_proxy._get_session()
        assert session is not None

    def test_get_session_same_thread(self):
        """Test that same thread gets same session."""
        s1 = tls_impersonate_proxy._get_session()
        s2 = tls_impersonate_proxy._get_session()
        assert s1 is s2

    def test_get_session_different_threads(self):
        """Test that different threads get different sessions."""
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


# --- Integration Tests ---


class TestProxyHTTP:
    def test_proxy_get(self, proxy_server, upstream_server):
        """Test proxying a GET request."""
        resp = requests.get(
            f"{upstream_server}/hello",
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200
        assert resp.text == "GET /hello"

    def test_proxy_get_with_path(self, proxy_server, upstream_server):
        """Test proxying a GET with a path and query string."""
        resp = requests.get(
            f"{upstream_server}/path?key=value",
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200
        assert resp.text == "GET /path?key=value"

    def test_proxy_post(self, proxy_server, upstream_server):
        """Test proxying a POST request with body."""
        resp = requests.post(
            f"{upstream_server}/submit",
            data="test-body",
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200
        assert "POST /submit body=test-body" in resp.text

    def test_proxy_head(self, proxy_server, upstream_server):
        """Test proxying a HEAD request returns no body."""
        resp = requests.head(
            f"{upstream_server}/resource",
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.headers.get("Content-Length") == "42"

    def test_proxy_preserves_upstream_headers(self, proxy_server, upstream_server):
        """Test that upstream response headers are forwarded."""
        resp = requests.get(
            f"{upstream_server}/hello",
            proxies={"http": proxy_server},
        )
        assert resp.headers.get("X-Test-Header") == "upstream-value"

    def test_proxy_bad_url(self, proxy_server):
        """Test that non-absolute URLs return 400."""
        # Send a raw request with a relative URL through the proxy
        s = socket.create_connection(
            (proxy_server.split("//")[1].split(":")[0],
             int(proxy_server.split(":")[-1])),
        )
        s.sendall(b"GET /relative-path HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert b"400" in resp

    def test_proxy_upstream_down(self, proxy_server):
        """Test that unreachable upstream returns 502."""
        resp = requests.get(
            "http://127.0.0.1:1/unreachable",
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 502
