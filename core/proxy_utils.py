"""Utilities for parsing and auto-detecting proxy type (HTTP vs SOCKS5).

This module allows users to input proxies in simplified forms like:
- "user:pass@host:port"
- "host:port"
- Or full URLs with schemes (http://..., socks5://..., socks5h://...)

When scheme is missing, we try to detect whether the endpoint speaks SOCKS5 or HTTP proxy.
"""
from __future__ import annotations
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse, quote, unquote


def _tcp_connect(host: str, port: int, timeout: float = 1.0) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
        return s
    except Exception:
        return None


def _looks_like_http_status_line(b: bytes) -> bool:
    try:
        s = b.decode("ascii", errors="ignore").strip()
        return s.startswith("HTTP/1.")
    except Exception:
        return False


def detect_proxy_scheme(host: str, port: int, *, has_auth: bool = False, timeout: float = 1.0) -> Optional[str]:
    """Try to detect proxy scheme by probing SOCKS5 and HTTP.

    Returns one of: 'socks5h', 'http', or None if detection failed.
    """
    # 1) Try SOCKS5 greeting
    s = _tcp_connect(host, port, timeout=timeout)
    if s is not None:
        try:
            # greet: VER=5, NMETHODS=2, METHODS=(userpass, noauth) if auth expected; else (noauth, userpass)
            methods = bytes([0x02, 0x00]) if has_auth else bytes([0x00, 0x02])
            greet = bytes([0x05, len(methods)]) + methods
            s.sendall(greet)
            resp = s.recv(2)
            if len(resp) == 2 and resp[0] == 0x05 and resp[1] in (0x00, 0x02, 0x01, 0x03):
                s.close()
                return "socks5h"
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    # 2) Try HTTP CONNECT (we don't care about status code, only that it's HTTP)
    s = _tcp_connect(host, port, timeout=timeout)
    if s is not None:
        try:
            req = (
                "CONNECT 1.1.1.1:443 HTTP/1.1\r\n"
                "Host: 1.1.1.1:443\r\n"
                "Proxy-Connection: Keep-Alive\r\n\r\n"
            ).encode("ascii")
            s.sendall(req)
            data = s.recv(16)
            if _looks_like_http_status_line(data):
                return "http"
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return None


def normalize_proxy_input(raw: Optional[str], *, timeout: float = 1.0) -> Optional[str]:
    """Normalize a user-supplied proxy string to a URL with scheme.

    Accepts formats:
      - None or empty -> None
      - "user:pass@host:port"
      - "host:port"
      - Full URLs (returned as-is)

    Returns string like 'socks5h://user:pass@host:port' or 'http://host:port'.
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    if "://" in s:
        # Already has scheme, return as-is
        return s
    # Parse as [user[:pass]@]host:port
    user, passwd = None, None
    hostport = s
    if "@" in s:
        creds, hostport = s.split("@", 1)
        if ":" in creds:
            user, passwd = creds.split(":", 1)
        else:
            user = creds
            passwd = None
    if ":" not in hostport:
        # No port provided; cannot detect reliably; assume http without port
        return f"http://{s}"
    host, port_str = hostport.rsplit(":", 1)
    try:
        port = int(port_str)
    except Exception:
        # Fallback to http without strict validation
        return f"http://{s}"
    # Try detection
    scheme = detect_proxy_scheme(host, port, has_auth=bool(user), timeout=timeout) or "http"
    auth = ""
    if user is not None:
        # Preserve special characters safely
        u = quote(user, safe="")
        p = quote(passwd or "", safe="")
        auth = f"{u}:{p}@"
    return f"{scheme}://{auth}{host}:{port}"
