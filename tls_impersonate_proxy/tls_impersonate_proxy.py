#!/usr/bin/env python3
"""HTTP/HTTPS proxy that impersonates browser TLS fingerprints.

Uses curl_cffi to re-issue every request with a browser TLS fingerprint
(JA3/JA4), defeating CDN fingerprint-based blocking of non-browser clients.

Supports both plain HTTP proxy requests and HTTPS CONNECT tunnels via
MITM with an auto-generated CA certificate installed into the system
trust store.

Usage:
    tls-impersonate-proxy [--port PORT] [--host HOST] [--impersonate BROWSER]

    # As an HTTP proxy for curl:
    curl -x http://127.0.0.1:8899 https://example.com

    # As an HTTP proxy for ffmpeg:
    ffmpeg -http_proxy http://127.0.0.1:8899 -i https://stream.example.com/live.m3u8 output.mp4

Environment variables:
    TLS_PROXY_PORT          Port to listen on (default: 8899)
    TLS_PROXY_HOST          Host to bind to (default: 127.0.0.1)
    TLS_PROXY_IMPERSONATE   Browser to impersonate (default: chrome)
"""

import argparse
import contextlib
import datetime
import http.client
import ipaddress
import os
import platform
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from curl_cffi import requests as cffi_requests

CHUNK_SIZE = 65536

_CA_KEY = None
_CA_CERT = None
_HOST_CERT_CACHE: OrderedDict = OrderedDict()
_HOST_CERT_LOCK = threading.Lock()
_HOST_CERT_MAX = 256
_SESSION_LOCAL = threading.local()
_IMPERSONATE = "chrome"


def _install_ca_cert(cert_path):
    """Install the MITM CA cert into the system trust store."""
    system = platform.system()
    if system == "Darwin":
        try:
            subprocess.run(
                ["security", "add-trusted-cert", "-d", "-r", "trustRoot",
                 "-k", "/Library/Keychains/System.keychain", cert_path],
                check=True,
            )
            print("CA cert installed to macOS system keychain", flush=True)
        except Exception:
            print("Failed to install CA cert. Install manually:", flush=True)
            print(f"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_path}", flush=True)
    elif system == "Linux":
        dest = "/usr/local/share/ca-certificates/tls_impersonate_proxy_ca.crt"
        try:
            subprocess.run(["cp", cert_path, dest], check=True)
            subprocess.run(["update-ca-certificates"], check=True)
            print("CA cert installed to system trust store", flush=True)
        except Exception:
            print("Failed to install CA cert. Install manually:", flush=True)
            print(f"  cp {cert_path} {dest} && update-ca-certificates", flush=True)
    else:
        print(f"CA cert written to: {cert_path}", flush=True)
        print("Install it manually into your system trust store.", flush=True)


def _init_ca():
    """Create an in-memory self-signed CA for MITM CONNECT handling."""
    global _CA_KEY, _CA_CERT
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        _CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "TLS Impersonate Proxy CA"),
        ])
        _CA_CERT = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(_CA_KEY.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(_CA_KEY, hashes.SHA256())
        )
        ca_cert_file = os.path.join(tempfile.gettempdir(), "tls_impersonate_proxy_ca.pem")
        with open(ca_cert_file, "wb") as f:
            f.write(_CA_CERT.public_bytes(serialization.Encoding.PEM))
        print("MITM CA initialized (CONNECT support enabled)", flush=True)
        _install_ca_cert(ca_cert_file)
    except Exception as e:
        print(f"WARNING: MITM CA init failed ({e}) — CONNECT will fall back to raw tunnel", flush=True)


def _get_cert_for_host(hostname):
    """Get or create a cached SSL context for the given hostname."""
    with _HOST_CERT_LOCK:
        ctx = _HOST_CERT_CACHE.get(hostname)
        if ctx is not None:
            return ctx

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    try:
        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_CA_CERT.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
        .sign(_CA_KEY, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = key_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_pem)
            cert_file = cf.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
            kf.write(key_pem)
            key_file = kf.name
        ctx.load_cert_chain(cert_file, key_file)
    finally:
        if cert_file:
            with contextlib.suppress(OSError):
                os.unlink(cert_file)
        if key_file:
            with contextlib.suppress(OSError):
                os.unlink(key_file)

    with _HOST_CERT_LOCK:
        existing = _HOST_CERT_CACHE.get(hostname)
        if existing is not None:
            return existing
        _HOST_CERT_CACHE[hostname] = ctx
        while len(_HOST_CERT_CACHE) > _HOST_CERT_MAX:
            _HOST_CERT_CACHE.popitem(last=False)
    return ctx


def _get_session():
    """Get a thread-local curl_cffi session."""
    if not hasattr(_SESSION_LOCAL, "session"):
        _SESSION_LOCAL.session = cffi_requests.Session(impersonate=_IMPERSONATE)
    return _SESSION_LOCAL.session


def _do_request(method, url, headers, body):
    """Issue a request via curl_cffi with TLS impersonation."""
    try:
        return _get_session().request(
            method=method, url=url, headers=headers,
            data=body, timeout=30,
            allow_redirects=False, stream=True,
        )
    except Exception as e:
        print(f"tls-impersonate-proxy error: {e}", flush=True)
        return None


def _raw_tunnel(client_sock, host, port):
    """Relay bytes between client and upstream without inspection."""
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"Raw tunnel connect failed for {host}:{port}: {e}", flush=True)
        return
    try:
        while True:
            readable, _, _ = select.select([client_sock, upstream], [], [], 30)
            if not readable:
                break
            for sock in readable:
                data = sock.recv(CHUNK_SIZE)
                if not data:
                    raise ConnectionError("closed")
                if sock is client_sock:
                    upstream.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            upstream.shutdown(socket.SHUT_RDWR)
        upstream.close()


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        host, _, port_str = self.path.rpartition(":")
        host = host.strip("[]")
        port = int(port_str) if port_str else 443

        self.send_response(200, "Connection established")
        self.end_headers()

        if _CA_KEY is None:
            print(f"CONNECT {host}:{port} (raw tunnel, no impersonation)", flush=True)
            _raw_tunnel(self.connection, host, port)
            self.close_connection = True
            return

        # MITM: wrap the client socket with TLS using a cached forged cert
        try:
            ctx = _get_cert_for_host(host)
            client_tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            print(f"MITM TLS wrap error for {host}: {e}", flush=True)
            self.close_connection = True
            return

        # Read HTTP requests from the decrypted TLS stream and proxy via curl_cffi
        rfile = wfile = None
        try:
            rfile = client_tls.makefile("rb")
            wfile = client_tls.makefile("wb")

            while True:
                req_line = rfile.readline(65537)
                if not req_line or req_line.strip() == b"":
                    break

                parts = req_line.decode("latin-1").strip().split(" ", 2)
                if len(parts) < 2:
                    break
                method = parts[0]
                path = parts[1]

                # Read headers
                headers = {}
                while True:
                    hline = rfile.readline(65537)
                    if hline in (b"\r\n", b"\n", b""):
                        break
                    if b":" in hline:
                        k, v = hline.decode("latin-1").split(":", 1)
                        headers[k.strip()] = v.strip()

                # Read body if present
                body = None
                cl = headers.get("Content-Length")
                if cl:
                    body = rfile.read(int(cl))

                # Build full URL
                scheme = "https"
                if port == 443:
                    url = f"{scheme}://{host}{path}"
                else:
                    url = f"{scheme}://{host}:{port}{path}"

                # Filter hop-by-hop headers
                skip = {"host", "proxy-connection", "connection", "keep-alive",
                        "transfer-encoding", "te", "trailer", "upgrade",
                        "proxy-authorization", "proxy-authenticate"}
                fwd_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

                r = _do_request(method, url, fwd_headers, body)
                if r is None:
                    wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    wfile.flush()
                    break

                # Write response
                reason = http.client.responses.get(r.status_code, "Unknown")
                status_line = f"HTTP/1.1 {r.status_code} {reason}\r\n".encode()
                wfile.write(status_line)
                skip_h = {"transfer-encoding", "content-encoding", "content-length"}
                for k, v in r.headers.items():
                    if k.lower() not in skip_h:
                        wfile.write(f"{k}: {v}\r\n".encode())

                # Collect all data then send with Content-Length
                # (curl_cffi stream=True means r.content is empty, must use iter_content)
                body_parts = list(r.iter_content())
                body_data = b"".join(body_parts)
                wfile.write(f"Content-Length: {len(body_data)}\r\n".encode())
                wfile.write(b"Connection: keep-alive\r\n")
                wfile.write(b"\r\n")
                wfile.write(body_data)
                wfile.flush()
                print(f"CONNECT-MITM {method} {url} -> {r.status_code}", flush=True)

        except Exception as e:
            print(f"MITM handler error: {e}", flush=True)
        finally:
            if rfile:
                with contextlib.suppress(Exception):
                    rfile.close()
            if wfile:
                with contextlib.suppress(Exception):
                    wfile.close()
            with contextlib.suppress(Exception):
                client_tls.shutdown(socket.SHUT_RDWR)
            client_tls.close()

        self.close_connection = True

    def _proxy(self):
        url = self.path
        if not url.startswith("http"):
            self.send_error(400, "Absolute URL required")
            return

        skip = {
            "host", "proxy-connection", "connection", "keep-alive",
            "transfer-encoding", "te", "trailer", "upgrade",
            "proxy-authorization", "proxy-authenticate",
        }
        headers = {}
        for key, val in self.headers.items():
            if key.lower() not in skip:
                headers[key] = val

        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        resp = _do_request(self.command, url, headers, body)
        if resp is None:
            self.send_error(502, "Upstream request failed")
            return

        try:
            self.send_response(resp.status_code)
            is_head = self.command == "HEAD"
            skip_resp = {"transfer-encoding", "content-encoding", "content-length"}
            for key, val in resp.headers.items():
                if key.lower() not in skip_resp:
                    self.send_header(key, val or "")
            if is_head:
                # Forward Content-Length for HEAD so clients can probe size
                cl = resp.headers.get("content-length")
                if cl:
                    self.send_header("Content-Length", cl)
                self.end_headers()
            else:
                body_data = b"".join(resp.iter_content())
                self.send_header("Content-Length", str(len(body_data)))
                self.end_headers()
                self.wfile.write(body_data)
            self.wfile.flush()
        finally:
            resp.close()

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_HEAD = _proxy
    do_OPTIONS = _proxy


def run(host="127.0.0.1", port=8899, impersonate="chrome"):
    global _IMPERSONATE
    _IMPERSONATE = impersonate

    _init_ca()

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadingHTTPServer((host, port), ProxyHandler)
    print(f"tls-impersonate-proxy listening on {host}:{port} (impersonating {impersonate})", flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="HTTP/HTTPS proxy that impersonates browser TLS fingerprints"
    )
    parser.add_argument(
        "--port", "-p", type=int,
        default=int(os.environ.get("TLS_PROXY_PORT", "8899")),
        help="Port to listen on (default: 8899)",
    )
    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("TLS_PROXY_HOST", "127.0.0.1"),
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--impersonate", "-i",
        default=os.environ.get("TLS_PROXY_IMPERSONATE", "chrome"),
        help="Browser to impersonate (default: chrome)",
    )
    args = parser.parse_args()
    run(host=args.host, port=args.port, impersonate=args.impersonate)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    main()
