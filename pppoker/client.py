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
        # Default client version; API layer may override via tcp.clientver
        self.clientver: str = '4.2.41'
        # Optional external cancel event (threading.Event-like)
        self._cancel_event = None

    def set_cancel_event(self, ev) -> None:
        self._cancel_event = ev

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
        # allow external cancellation to break long waits
        if self._cancel_event is not None:
            try:
                if getattr(self._cancel_event, 'is_set', lambda: False)():
                    return None
            except Exception:
                pass
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
    def build_user_login_req(self, *, uid: int, token: str, clientver: Optional[str] = None, clientip: str = "", os_name: str = "windows", platform_type: int = 1, entry: Optional[str] = None, country: str = "Russia") -> bytes:
        b = bytearray()
        # 1 uid
        b += varint_encode((1 << 3) | 0) + varint_encode(int(uid))
        # 2 token
        tb = token.encode("utf-8"); b += varint_encode((2 << 3) | 2) + varint_encode(len(tb)) + tb
        # 3 client ver (fallback to self.clientver if not provided)
        use_cv = clientver or getattr(self, 'clientver', '4.2.41')
        cv = use_cv.encode("utf-8"); b += varint_encode((3 << 3) | 2) + varint_encode(len(cv)) + cv
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

    def build_club_brief_info_req(self, *, club_id: int) -> bytes:
        """Build pb.ClubBriefInfoREQ payload: field1=club_id (varint), field2=0."""
        b = bytearray()
        b += bytes([0x08]) + varint_encode(int(club_id))  # field1 varint club_id
        b += bytes([0x10, 0x00])  # field2=0
        return bytes(b)

    def get_club_brief_info(self, *, club_id: int) -> Tuple[bool, dict]:
        """Send ClubBriefInfoREQ and determine if club exists.
        Returns (exists, info_dict).
        Not-found signature (per dump): 08 ff..ff 01 (unsigned -1) possibly followed by 28 00.
        """
        if not self.sock:
            self.connect()
        payload = self.build_club_brief_info_req(club_id=club_id)
        frame = build_frame('pb.ClubBriefInfoREQ', payload)
        self.sock.sendall(frame)  # type: ignore[union-attr]
        info: dict = {"club_id": int(club_id)}
        # read a few frames until RSP
        for _ in range(6):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == 'pb.ClubBriefInfoRSP':
                fields = parse_top_fields(p)
                # any varint much greater than int64_max -> treat as signed -1
                code_signed = None
                for f in fields:
                    if f.get('wt') == 0 and isinstance(f.get('val'), int):
                        v = int(f['val'])
                        if v > 0x7fffffffffffffff:
                            code_signed = -1
                            break
                # Mark presence of strings (e.g. http url)
                has_str = any(isinstance(f.get('str'), str) for f in fields)
                info.update({"fields": fields, "has_str": has_str, "code_signed": code_signed})
                exists = (code_signed != -1)
                return exists, info
        return False, {"club_id": int(club_id), "timeout": True}

    # ---- high-level ops ----
    def tcp_login(self, *, uid: int, token: str, clientip: str, entry_host: str, entry_port: int) -> Tuple[bool, str]:
        if not self.sock:
            self.connect()
        payload = self.build_user_login_req(uid=uid, token=token, clientver=getattr(self, 'clientver', '4.2.41'), clientip=clientip, entry=f"{entry_host}:{entry_port}")
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
                # Normalize potential 64-bit two's complement -1 encoded as unsigned varint
                code_signed = code
                try:
                    if isinstance(code, int) and code > 0x7fffffffffffffff:
                        code_signed = code - (1 << 64)
                except Exception:
                    pass
                # Treat -1 and 1002 as 'club not found' per observed behavior
                if code_signed in (-1, 1002):
                    return False, "Клуб не найден"
                ok = (code_signed == 0) or (code_signed == 1)  # 0=ok, 1=pending
                msg = reason or (f"status={code_signed}" if code_signed is not None else "")
                return ok, msg
        return False, "no JoinClubRSP"

    # ---- profile ops ----
    def build_change_username_req(self, *, nickname: str) -> bytes:
        # Observed pb.ChangeUserNameREQ; field 1 appears to be the new name (string)
        nb = nickname.encode('utf-8')
        return varint_encode((1 << 3) | 2) + varint_encode(len(nb)) + nb

    def change_username(self, *, nickname: str) -> Tuple[bool, str]:
        if not self.sock:
            self.connect()
        payload = self.build_change_username_req(nickname=nickname)
        frame = build_frame('pb.ChangeUserNameREQ', payload)
        assert self.sock is not None
        self.sock.sendall(frame)
        # Server may send intermediate frames (e.g., DiamondRSP, HeartBeatRSP). Wait for ChangeUserNameRSP
        for _ in range(20):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == 'pb.ChangeUserNameRSP':
                fields = parse_top_fields(p)
                # success if echoed string equals nickname or if any field present
                new_name = next((f.get('str') for f in fields if f.get('wt') == 2 and f.get('str')), '')
                ok = (new_name == nickname) or bool(fields)
                return ok, (new_name or 'ok')
        return False, 'no ChangeUserNameRSP'
