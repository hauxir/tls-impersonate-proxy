# tls-impersonate-proxy

HTTP/HTTPS proxy that impersonates browser TLS fingerprints using [curl_cffi](https://github.com/lexiforest/curl_cffi). Defeats JA3/JA4 TLS fingerprinting used by CDNs to block non-browser clients.

## How it works

Many CDNs use TLS fingerprinting (JA3/JA4) to distinguish real browsers from tools like ffmpeg, curl, wget, etc. This proxy sits between your client and the internet, re-issuing every request with a browser TLS fingerprint via curl_cffi.

- **HTTP requests**: Proxied directly with browser TLS fingerprint
- **HTTPS requests**: MITM with auto-generated certificates signed by a local CA, then re-issued with browser TLS fingerprint

## Install

```bash
pip install git+https://github.com/hauxir/tls-impersonate-proxy.git
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv pip install git+https://github.com/hauxir/tls-impersonate-proxy.git
```

## Usage

```bash
# Start the proxy (default: 127.0.0.1:8899)
tls-impersonate-proxy

# Custom port and host
tls-impersonate-proxy --port 9000 --host 0.0.0.0

# Different browser fingerprint
tls-impersonate-proxy --impersonate edge101
```

### With ffmpeg

```bash
ffmpeg -http_proxy http://127.0.0.1:8899 -i https://stream.example.com/live.m3u8 output.mp4
```

### With curl

```bash
curl -x http://127.0.0.1:8899 https://example.com
```

### With any HTTP client

Set the `http_proxy` / `https_proxy` environment variables:

```bash
export http_proxy=http://127.0.0.1:8899
export https_proxy=http://127.0.0.1:8899
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `TLS_PROXY_PORT` | `8899` | Port to listen on |
| `TLS_PROXY_HOST` | `127.0.0.1` | Host to bind to |
| `TLS_PROXY_IMPERSONATE` | `chrome` | Browser to impersonate |

## How HTTPS works

For HTTPS, the proxy uses MITM (Man-in-the-Middle):

1. On startup, generates a self-signed CA certificate and installs it in the system trust store
2. When a client sends a CONNECT request, the proxy accepts it and wraps the connection with a forged certificate signed by the CA
3. The proxy then reads the decrypted HTTP requests and re-issues them via curl_cffi with browser TLS fingerprinting
4. If the CA can't be initialized, falls back to a raw TCP tunnel (no TLS impersonation for HTTPS)
