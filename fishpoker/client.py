"""FishPoker TCP client for pb.* frames over gate server."""

from __future__ import annotations

import base64
import socket
import struct
from typing import Any, Optional, Tuple
from urllib.parse import unquote, urlparse

from core.proxy_utils import normalize_proxy_input

from .protocol import build_frame, parse_top_fields, varint_encode


class FishPokerTCPClient:
    def __init__(self, host: str, port: int, *, timeout: float = 5.0, proxy: Optional[str] = None):
        self.host = str(host)
        self.port = int(port)
        self.timeout = float(timeout)
        self.proxy_url = proxy
        self.sock: Optional[socket.socket] = None

        # These can be overridden by API layer
        self.clientver: str = "1.0.49"
        self.country: str = "CN"

        self._cancel_event = None

    def set_cancel_event(self, ev) -> None:
        self._cancel_event = ev

    # ---- proxy helpers (HTTP CONNECT / SOCKS5 via PySocks optional) ----
    def _parse_proxy(self, proxy: Optional[str]):
        if not proxy:
            return None
        norm = normalize_proxy_input(proxy)
        if not norm:
            return None
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
            s.close()
            raise OSError(f"HTTP proxy CONNECT failed: {msg}")
        return s

    def _connect_via_socks(self, info) -> socket.socket:
        try:
            import socks  # PySocks
        except Exception:
            raise OSError("Для socks5/socks5h требуется PySocks (pip install PySocks)")
        s = socks.socksocket()
        s.set_proxy(
            socks.SOCKS5,
            info["host"],
            info["port"],
            username=info["username"],
            password=info["password"],
            rdns=(info["scheme"] == "socks5h"),
        )
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def connect(self) -> None:
        if self.proxy_url:
            info = self._parse_proxy(self.proxy_url)
            if not info:
                raise OSError(f"Некорректный прокси: {self.proxy_url}")
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
            # allow external cancellation to break long waits
            if self._cancel_event is not None:
                try:
                    if getattr(self._cancel_event, "is_set", lambda: False)():
                        raise OSError("cancelled")
                except Exception:
                    pass
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
            tstr = body[2 : 2 + tlen].decode("ascii", "replace")
            payload = body[2 + tlen + 4 :]
            return tstr, payload
        except Exception:
            return None

    def send_frame(self, type_str: str, payload: bytes = b"") -> None:
        if not self.sock:
            raise OSError("Not connected")
        self.sock.sendall(build_frame(type_str, payload))  # type: ignore[union-attr]

    def send_frames_burst(self, frames: list[tuple[str, bytes]]) -> None:
        if not self.sock:
            raise OSError("Not connected")
        blob = b"".join(build_frame(t, p) for t, p in frames)
        self.sock.sendall(blob)  # type: ignore[union-attr]

    # ---- protobuf builders ----
    def build_user_login_req(
        self,
        *,
        uid: int,
        token: str,
        clientver: Optional[str] = None,
        clientip: str = "",
        os_name: str = "windows",
        platform_type: int = 1,
        entry: Optional[str] = None,
        country: Optional[str] = None,
    ) -> bytes:
        b = bytearray()
        # 1 uid
        b += varint_encode((1 << 3) | 0) + varint_encode(int(uid))
        # 2 token
        tb = token.encode("utf-8")
        b += varint_encode((2 << 3) | 2) + varint_encode(len(tb)) + tb
        # 3 client ver
        use_cv = (clientver or self.clientver or "1.0.49").strip() or "1.0.49"
        cv = use_cv.encode("utf-8")
        b += varint_encode((3 << 3) | 2) + varint_encode(len(cv)) + cv
        # 4 client ip
        cip = (clientip or "").encode("utf-8")
        b += varint_encode((4 << 3) | 2) + varint_encode(len(cip)) + cip
        # 6 flag
        b += varint_encode((6 << 3) | 0) + varint_encode(0)
        # 7 os
        osb = os_name.encode("utf-8")
        b += varint_encode((7 << 3) | 2) + varint_encode(len(osb)) + osb
        # 8 platform type
        b += varint_encode((8 << 3) | 0) + varint_encode(int(platform_type))
        # 9 entry host:port
        if entry:
            eb = entry.encode("utf-8")
            b += varint_encode((9 << 3) | 2) + varint_encode(len(eb)) + eb
        # 10 country
        ctry = (country or self.country or "CN").encode("utf-8")
        b += varint_encode((10 << 3) | 2) + varint_encode(len(ctry)) + ctry
        return bytes(b)

    def build_join_club_req(self, *, club_id: int, remark: str, apply_source: int = 0) -> bytes:
        b = bytearray()
        b += varint_encode((1 << 3) | 0) + varint_encode(int(club_id))
        rb = (remark or "").encode("utf-8")
        b += varint_encode((2 << 3) | 2) + varint_encode(len(rb)) + rb
        b += varint_encode((3 << 3) | 0) + varint_encode(int(apply_source))
        return bytes(b)

    def build_club_brief_info_req(self, *, club_id: int) -> bytes:
        b = bytearray()
        b += bytes([0x08]) + varint_encode(int(club_id))
        b += bytes([0x10, 0x00])
        return bytes(b)

    # ---- high-level ops ----
    def tcp_login(self, *, uid: int, token: str, clientip: str, entry_host: str, entry_port: int) -> Tuple[bool, str]:
        if not self.sock:
            self.connect()
        payload = self.build_user_login_req(
            uid=uid,
            token=token,
            clientver=self.clientver,
            clientip=clientip,
            entry=f"{entry_host}:{int(entry_port)}",
            country=self.country,
        )
        self.send_frame("pb.UserLoginREQ", payload)
        # read a few frames to catch RSP
        for _ in range(10):
            r = self.recv_one(timeout=2.0)
            if not r:
                continue
            t, p = r
            if t == "pb.UserLoginRSP":
                fields = parse_top_fields(p)
                code = next((f.get("val") for f in fields if f.get("wt") == 0), None)
                code_signed = code
                try:
                    if isinstance(code, int) and code > 0x7FFFFFFFFFFFFFFF:
                        code_signed = code - (1 << 64)
                except Exception:
                    pass
                ok = (code_signed == 0) or (code_signed is None)
                return ok, f"code={code_signed}"
        return False, "no UserLoginRSP"

    def get_club_brief_info(self, *, club_id: int) -> Tuple[bool, dict[str, Any]]:
        payload = self.build_club_brief_info_req(club_id=club_id)
        self.send_frame("pb.ClubBriefInfoREQ", payload)
        info: dict[str, Any] = {"club_id": int(club_id)}
        for _ in range(6):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == "pb.ClubBriefInfoRSP":
                fields = parse_top_fields(p)
                code_signed = None
                for f in fields:
                    if f.get("wt") == 0 and isinstance(f.get("val"), int):
                        v = int(f["val"])  # type: ignore[index]
                        if v > 0x7FFFFFFFFFFFFFFF:
                            code_signed = -1
                            break
                has_str = any(isinstance(f.get("str"), str) for f in fields)
                info.update({"fields": fields, "has_str": has_str, "code_signed": code_signed})
                exists = (code_signed != -1)
                return exists, info
        return False, {"club_id": int(club_id), "timeout": True}

    def join_club(self, *, club_id: int, remark: str, apply_source: int = 0) -> Tuple[bool, str]:
        payload = self.build_join_club_req(club_id=club_id, remark=remark, apply_source=apply_source)
        self.send_frame("pb.JoinClubREQ", payload)
        for _ in range(20):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t in ("pb.JoinClubRSP", "pb.JoinClubResultRSP"):
                fields = parse_top_fields(p)
                code = next((f.get("val") for f in fields if f.get("wt") == 0), None)
                reason = next((f.get("str") for f in fields if f.get("wt") == 2 and f.get("str")), "")
                code_signed = code
                try:
                    if isinstance(code, int) and code > 0x7FFFFFFFFFFFFFFF:
                        code_signed = code - (1 << 64)
                except Exception:
                    pass
                if code_signed in (-1, 1002):
                    return False, "Клуб не найден"
                ok = (code_signed == 0) or (code_signed == 1)
                msg = reason or (f"status={code_signed}" if code_signed is not None else "")
                return ok, msg
        return False, "no JoinClubRSP"

    def change_username(self, *, nickname: str) -> Tuple[bool, str]:
        nb = nickname.encode("utf-8")
        payload = varint_encode((1 << 3) | 2) + varint_encode(len(nb)) + nb
        self.send_frame("pb.ChangeUserNameREQ", payload)
        for _ in range(25):
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == "pb.ChangeUserNameRSP":
                fields = parse_top_fields(p)
                str_fields = [
                    f.get("str")
                    for f in fields
                    if f.get("wt") == 2 and isinstance(f.get("str"), str) and f.get("str")
                ]
                # Prefer strict confirmation: server echoed the new nickname
                for s in str_fields:
                    if s == nickname:
                        return True, s
                # Fallback: if server only returns a code and no strings
                code = next((f.get("val") for f in fields if f.get("wt") == 0 and isinstance(f.get("val"), int)), None)
                code_signed = code
                try:
                    if isinstance(code, int) and code > 0x7FFFFFFFFFFFFFFF:
                        code_signed = code - (1 << 64)
                except Exception:
                    pass
                if not str_fields and code_signed == 0:
                    return True, "ok"
                # Otherwise treat as failure and surface best-effort reason
                reason = str_fields[0] if str_fields else ""
                if reason:
                    return False, reason
                return False, (f"code={code_signed}" if code_signed is not None else "ChangeUserName failed")
        return False, "no ChangeUserNameRSP"

    def send_post_login_bursts(self, *, uid: int) -> None:
        """Best-effort warmup burst as observed in official clients.

        Not required for join, but improves compatibility for profile ops.
        """
        u = int(uid)
        uid_pb = bytes([0x08]) + varint_encode(u)
        burst1 = [
            ("pb.HeartBeatREQ", b""),
            ("pb.SelfUserInfoREQ", b""),
            ("pb.MoneyREQ", b""),
            ("pb.DiamondREQ", b""),
            ("pb.RebateREQ", b""),
            ("pb.RiskGetUserSettingREQ", uid_pb),
            ("pb.ChatGetUserSettingREQ", b""),
            ("pb.EvchopGetUserSettingREQ", b""),
            ("pb.HandReviewUrlREQ", b""),
            ("pb.GetChipReplenishmentSettingREQ", b""),
            ("pb.UserCroupierInUsingREQ", b""),
        ]
        try:
            self.send_frames_burst(burst1)
            self.send_frame("pb.GoalREQ", uid_pb)
            self.send_frames_burst([
                ("pb.DiamondREQ", b""),
                ("pb.SelUserVipInfoREQ", uid_pb),
            ])
        except Exception:
            # Warmup must never be fatal
            return
