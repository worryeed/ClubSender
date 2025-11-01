"""PPPoker TCP client for pb.* frames over gate."""
from __future__ import annotations
import socket
import logging
import struct
from typing import Optional, Tuple, Callable
from urllib.parse import urlparse, unquote
import base64

from .protocol import build_frame, varint_encode, parse_frame, parse_top_fields
from core.proxy_utils import normalize_proxy_input

log = logging.getLogger(__name__)


class PPPokerTCPClient:
    def __init__(self, host: str, port: int, *, timeout: float = 5.0, proxy: Optional[str] = None):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.proxy_url = proxy
        self.sock: Optional[socket.socket] = None

    # ---- proxy helpers (HTTP CONNECT / SOCKS5 via PySocks optional) ----
    def _parse_proxy(self, proxy: Optional[str]):
        if not proxy:
            return None
        norm = normalize_proxy_input(proxy)
        u = urlparse(norm)
        if not u.hostname or not u.port:
            raise OSError(f"Некорректный прокси URL: {proxy}")
        return {
            "scheme": (u.scheme or "http").lower(),
            "host": u.hostname,
            "port": u.port,
            "username": unquote(u.username) if u.username else None,
            "password": unquote(u.password) if u.password else None,
        }

    def _connect_via_http_proxy(self, info) -> socket.socket:
        ph, pp = info["host"], info["port"]
        s = socket.create_connection((ph, pp), timeout=self.timeout)
        s.settimeout(self.timeout)
        lines = [
            f"CONNECT {self.host}:{self.port} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Proxy-Connection: Keep-Alive",
        ]
        if info["username"] is not None:
            userpass = f"{info['username']}:{info['password'] or ''}".encode("utf-8")
            auth = base64.b64encode(userpass).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {auth}")
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        s.sendall(req)
        buff = b""
        while b"\r\n\r\n" not in buff and len(buff) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buff += chunk
        ok = buff.startswith(b"HTTP/1.1 200") or buff.startswith(b"HTTP/1.0 200")
        if not ok:
            try:
                msg = buff.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
            except Exception:
                msg = str(buff[:64])
            s.close(); raise OSError(f"HTTP proxy CONNECT failed: {msg}")
        return s

    def _connect_via_socks(self, info) -> socket.socket:
        try:
            import socks  # PySocks
        except Exception:
            raise OSError("Для socks5/socks5h требуется PySocks (pip install PySocks)")
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, info['host'], info['port'], username=info['username'], password=info['password'], rdns=(info['scheme'] == 'socks5h'))
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def connect(self) -> None:
        if self.proxy_url:
            info = self._parse_proxy(self.proxy_url)
            sch = info["scheme"]
            if sch in ("http", "https"):
                self.sock = self._connect_via_http_proxy(info)
            elif sch in ("socks5", "socks5h"):
                self.sock = self._connect_via_socks(info)
            else:
                raise OSError(f"Неподдерживаемая схема прокси для TCP: {sch}")
        else:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.settimeout(self.timeout)
        log.info(f"Connected to {self.host}:{self.port}")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ---- frame recv helper ----
    def _recvn(self, n: int) -> bytes:
        assert self.sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("socket closed")
            buf.extend(chunk)
        return bytes(buf)

    def recv_one(self, timeout: float = 2.0) -> Optional[Tuple[str, bytes]]:
        assert self.sock is not None
        self.sock.settimeout(timeout)
        try:
            head4 = self._recvn(4)
            (length,) = struct.unpack(">I", head4)
            body = self._recvn(length)
            (tlen,) = struct.unpack(">H", body[:2])
            tstr = body[2:2+tlen].decode("ascii", "replace")
            payload = body[2+tlen+4:]
            return tstr, payload
        except Exception:
            return None

    # ---- pb builders ----
    def build_user_login_req(self, *, uid: int, token: str, clientver: str = "4.2.41", clientip: str = "", os_name: str = "windows", platform_type: int = 1, entry: Optional[str] = None, country: str = "Russia") -> bytes:
        b = bytearray()
        # 1 uid
        b += varint_encode((1 << 3) | 0) + varint_encode(int(uid))
        # 2 token
        tb = token.encode("utf-8"); b += varint_encode((2 << 3) | 2) + varint_encode(len(tb)) + tb
        # 3 client ver
        cv = clientver.encode("utf-8"); b += varint_encode((3 << 3) | 2) + varint_encode(len(cv)) + cv
        # 4 client ip
        cip = (clientip or '').encode('utf-8'); b += varint_encode((4 << 3) | 2) + varint_encode(len(cip)) + cip
        # 6 flag
        b += varint_encode((6 << 3) | 0) + varint_encode(0)
        # 7 os
        osb = os_name.encode('utf-8'); b += varint_encode((7 << 3) | 2) + varint_encode(len(osb)) + osb
        # 8 platform type
        b += varint_encode((8 << 3) | 0) + varint_encode(int(platform_type))
        # 9 entry host:port
        if entry:
            eb = entry.encode('utf-8'); b += varint_encode((9 << 3) | 2) + varint_encode(len(eb)) + eb
        # 10 country
        ctry = country.encode('utf-8'); b += varint_encode((10 << 3) | 2) + varint_encode(len(ctry)) + ctry
        return bytes(b)

    def build_join_club_req(self, *, club_id: int, remark: str, apply_source: int = 0) -> bytes:
        b = bytearray()
        b += varint_encode((1 << 3) | 0) + varint_encode(int(club_id))
        rb = (remark or '').encode('utf-8'); b += varint_encode((2 << 3) | 2) + varint_encode(len(rb)) + rb
        b += varint_encode((3 << 3) | 0) + varint_encode(int(apply_source))
        return bytes(b)

    # ---- high-level ops ----
    def tcp_login(self, *, uid: int, token: str, clientip: str, entry_host: str, entry_port: int) -> Tuple[bool, str]:
        if not self.sock:
            self.connect()
        payload = self.build_user_login_req(uid=uid, token=token, clientip=clientip, entry=f"{entry_host}:{entry_port}")
        frame = build_frame('pb.UserLoginREQ', payload)
        assert self.sock is not None
        self.sock.sendall(frame)
        # read few frames to catch RSP
        for _ in range(5):
            r = self.recv_one(timeout=2.0)
            if not r:
                continue
            t, p = r
            if t == 'pb.UserLoginRSP':
                fields = parse_top_fields(p)
                code = next((f.get('val') for f in fields if f.get('wt') == 0), None)
                return (code == 0), f"code={code}"
        return False, "no UserLoginRSP"

    def join_club(self, *, club_id: int, remark: str = '', apply_source: int = 0) -> Tuple[bool, str]:
        if not self.sock:
            self.connect()
        payload = self.build_join_club_req(club_id=club_id, remark=remark or '', apply_source=apply_source)
        frame = build_frame('pb.JoinClubREQ', payload)
        assert self.sock is not None
        self.sock.sendall(frame)
        # wait for JoinClubRSP/JoinClubResultRSP
        for _ in range(15):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t in ('pb.JoinClubRSP', 'pb.JoinClubResultRSP'):
                fields = parse_top_fields(p)
                code = next((f.get('val') for f in fields if f.get('wt') == 0), None)
                reason = next((f.get('str') for f in fields if f.get('wt') == 2 and f.get('str')), '')
                ok = (code == 0) or (code == 1)  # 0=ok, 1=pending (примерно)
                msg = reason or (f"status={code}" if code is not None else "")
                return ok, msg
        return False, "no JoinClubRSP"