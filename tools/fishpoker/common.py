from __future__ import annotations

import argparse
import hashlib
import mimetypes
import os
import re
import secrets
import socket
import struct
import threading
import time
from typing import Any, Optional

import urllib3
import requests

# Ensure repo root on sys.path (tools/fishpoker/common.py -> repo root)
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.proxy_utils import normalize_proxy_input
from pppoker.protocol import varint_encode, parse_top_fields

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_URL_DEFAULT = "https://wwb.fishpoker.net"
CLIENT_VER_HINT = "1.0.49"  # captured; server may respond with latest_version


_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+){0,4}\b")


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().lower()


def double_md5(s: str) -> str:
    """FishPoker uses md5(md5(password)) for registration and login."""
    return md5_hex(md5_hex(s))


def gen_random_imei() -> str:
    """FishPoker uses a MAC-like string (6 bytes hex with hyphens) in captured requests."""
    b = secrets.token_bytes(6)
    return "-".join(f"{x:02X}" for x in b)


def to_requests_proxies(proxy: Optional[str]) -> Optional[dict[str, str]]:
    if not proxy:
        return None
    norm = normalize_proxy_input(proxy)
    if not norm:
        return None
    return {"http": norm, "https": norm}


def _extract_client_version(j: Any, fallback: str) -> str:
    """Extract version from server JSON, preferring version-like keys.

    Avoids mistaking IP addresses for versions.
    """
    if not isinstance(j, dict):
        return fallback

    # 1) Common direct keys
    for k in (
        "latest_version",
        "latestVersion",
        "client_version",
        "clientVersion",
        "clientvar",
        "version",
        "ver",
    ):
        if k in j and j.get(k):
            s = str(j.get(k)).strip()
            m = _VERSION_RE.search(s)
            if m:
                return m.group(0)

    # 2) Look at keys that contain 'ver'
    for k, v in j.items():
        lk = str(k).lower()
        if "ver" not in lk and "version" not in lk:
            continue
        if isinstance(v, str):
            m = _VERSION_RE.search(v)
            if m:
                return m.group(0)
        elif isinstance(v, (int, float)):
            s = str(v)
            m = _VERSION_RE.search(s)
            if m:
                return m.group(0)

    return fallback


def _extract_client_ip(j: Any) -> str:
    if not isinstance(j, dict):
        return ""
    for k in ("clientip", "client_ip", "clientIp", "ip"):
        v = j.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _dedupe_endpoints(eps: list[tuple[str, int]]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for h, p in eps:
        h = str(h or "").strip()
        if not h:
            continue
        try:
            p = int(p)
        except Exception:
            continue
        item = (h, p)
        if item not in out:
            out.append(item)
    return out


class FishPokerHTTP:
    def __init__(
        self,
        *,
        base_url: str = BASE_URL_DEFAULT,
        proxy: Optional[str] = None,
        timeout: int = 30,
        user_agent: str = "libcurl",
    ):
        self.base_url = (base_url or BASE_URL_DEFAULT).rstrip("/")
        self.timeout = int(timeout)
        self.proxy_raw = proxy
        self.proxies = to_requests_proxies(proxy)

        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )

        self.client_version: str = CLIENT_VER_HINT
        self.client_ip: str = ""

        self.uid: Optional[int] = None
        self.rdkey: Optional[str] = None
        self.tcp_endpoints: list[tuple[str, int]] = []

    def fetch_version(
        self,
        *,
        imei: str,
        ver_hint: str = CLIENT_VER_HINT,
        region: int = 2,
        os_name: str = "windows",
        distributor: int = 0,
        sub_distributor: int = 0,
        appid: str = "globle",
        uid: int = 0,
        app_type: int = 1,
    ) -> dict[str, Any]:
        url = self.base_url + "/poker/api/version.php"
        params = {
            "ver": str(ver_hint),
            "region": str(region),
            "os": str(os_name),
            "distributor": str(distributor),
            "sub_distributor": str(sub_distributor),
            "appid": str(appid),
            "uid": str(uid),
            "openUid": str(imei),
            "app_type": str(app_type),
        }
        r = self.session.get(url, params=params, proxies=self.proxies, timeout=self.timeout)
        r.raise_for_status()
        j = r.json()
        self.client_version = _extract_client_version(j, self.client_version)
        self.client_ip = _extract_client_ip(j) or self.client_ip
        return j

    def register(
        self,
        *,
        username: str,
        password_md5: str,
        imei: str,
        clientvar: Optional[str] = None,
        region: int = 2,
        os_name: str = "windows",
        distributor: int = 0,
        sub_distributor: int = 0,
        appid: str = "globle",
        country: str = "CN",
        app_type: int = 1,
    ) -> dict[str, Any]:
        url = self.base_url + "/poker/api/register.php"
        params = {
            "username": username,
            "password": password_md5,
            "distributor": str(distributor),
            "sub_distributor": str(sub_distributor),
            "country": str(country),
            "appid": str(appid),
            "os": str(os_name),
            "imei": str(imei),
            "clientvar": str(clientvar or self.client_version),
            "region": str(region),
            "app_type": str(app_type),
        }
        r = self.session.get(url, params=params, proxies=self.proxies, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def login(
        self,
        *,
        username: str,
        password_md5: str,
        imei: str,
        clientvar: Optional[str] = None,
        region: int = 2,
        os_name: str = "windows",
        distributor: int = 0,
        sub_distributor: int = 0,
        appid: str = "globle",
        country: str = "CN",
        platform_type: int = 1,
        app_type: int = 1,
        type_code: int = 4,
    ) -> dict[str, Any]:
        url = self.base_url + "/poker/api/login.php"
        data = {
            "type": str(type_code),
            "region": str(region),
            "code": "",
            "username": username,
            "password": password_md5,
            "uid": "",
            "rdkey": "",
            "os": str(os_name),
            "distributor": str(distributor),
            "sub_distributor": str(sub_distributor),
            "country": str(country),
            "appid": str(appid),
            "imei": str(imei),
            "clientvar": str(clientvar or self.client_version),
            "device_token": "",
            "platform_type": str(platform_type),
            "app_type": str(app_type),
        }
        r = self.session.post(url, data=data, proxies=self.proxies, timeout=self.timeout)
        r.raise_for_status()
        j = r.json()

        # Capture auth + TCP endpoints
        try:
            if int(j.get("code", -1)) == 0:
                self.uid = int(j.get("uid")) if j.get("uid") is not None else None
                self.rdkey = str(j.get("rdkey") or "")
        except Exception:
            pass

        eps: list[tuple[str, int]] = []
        try:
            h = j.get("gserver_ip")
            p = j.get("gserver_port")
            if h:
                eps.append((str(h), int(p or 4000)))
        except Exception:
            pass

        # entry_server: list of dicts like {ip, port} (best-effort)
        ent = j.get("entry_server")
        if isinstance(ent, list):
            for it in ent:
                if isinstance(it, dict):
                    ip = it.get("ip") or it.get("host")
                    pt = it.get("port")
                    if ip:
                        try:
                            eps.append((str(ip), int(pt or 4000)))
                        except Exception:
                            pass
                elif isinstance(it, str) and ":" in it:
                    host, port_s = it.rsplit(":", 1)
                    try:
                        eps.append((host, int(port_s)))
                    except Exception:
                        pass

        sb = j.get("standby_server")
        if isinstance(sb, dict):
            ip = sb.get("ip") or sb.get("host")
            pt = sb.get("port")
            if ip:
                try:
                    eps.append((str(ip), int(pt or 4000)))
                except Exception:
                    pass

        self.tcp_endpoints = _dedupe_endpoints(eps)
        return j

    def upload_avatar(self, *, uid: int, rdkey: str, image_path: str) -> Optional[str]:
        """Upload avatar via icon_up.php; returns icon URL.

        FishPoker server only accepts JPEG.
        Non-JPEG images are auto-converted in memory.
        """
        url = self.base_url + "/poker/api/icon_up.php"
        params = {
            "rdkey": str(rdkey),
            "uid": str(uid),
            "type": "user",
            "clubid": "0",
        }

        # Always send as JPEG (server rejects PNG and other formats)
        import io
        try:
            from PIL import Image
            img = Image.open(image_path).convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=85)
            jpg_bytes = buf.getvalue()
        except ImportError:
            # Pillow not installed — send raw file and hope it's JPEG
            with open(image_path, "rb") as f:
                jpg_bytes = f.read()

        fn = f"{uid}.jpg"
        files = {"icon": (fn, jpg_bytes, "image/jpeg")}
        data = {"act": "upload", "submit": "upload"}
        r = self.session.post(
            url,
            params=params,
            data=data,
            files=files,
            timeout=self.timeout,
            proxies=self.proxies,
            verify=False,
        )
        r.raise_for_status()
        try:
            j = r.json()
        except Exception:
            return None
        if isinstance(j, dict) and int(j.get("code", -1)) == 0:
            icon = str(j.get("icon") or "")
            return icon or None
        return None


# ---------------- TCP (pb.* frames) ----------------


def build_pb_frame(type_str: str, payload: bytes, *, pad4: bytes = b"\x00\x00\x00\x00") -> bytes:
    t = type_str.encode("ascii")
    if len(pad4) != 4:
        raise ValueError("pad4 must be 4 bytes")
    total = 2 + len(t) + 4 + len(payload)
    return struct.pack(">I", total) + struct.pack(">H", len(t)) + t + pad4 + payload


class FishPokerTCPClient:
    def __init__(self, host: str, port: int, *, timeout: float = 5.0, proxy: Optional[str] = None):
        self.host = str(host)
        self.port = int(port)
        self.timeout = float(timeout)
        self.proxy_url = proxy
        self.sock: Optional[socket.socket] = None
        self.clientver: str = CLIENT_VER_HINT
        self.country: str = "CN"

        self._send_lock = threading.Lock()
        self._hb_stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    # ---- proxy helpers (HTTP CONNECT / SOCKS5 via PySocks optional) ----
    def _parse_proxy(self, proxy: Optional[str]):
        if not proxy:
            return None
        norm = normalize_proxy_input(proxy)
        if not norm:
            return None
        from urllib.parse import urlparse, unquote

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
            import base64

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
        try:
            self.stop_heartbeat()
        except Exception:
            pass
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

    def _recvn(self, n: int) -> bytes:
        assert self.sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("socket closed")
            buf.extend(chunk)
        return bytes(buf)

    def recv_one(self, timeout: float = 2.0) -> Optional[tuple[str, bytes]]:
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
        frame = build_pb_frame(type_str, payload)
        with self._send_lock:
            self.sock.sendall(frame)

    def send_frames_burst(self, frames: list[tuple[str, bytes]]) -> None:
        if not self.sock:
            raise OSError("Not connected")
        blob = b"".join(build_pb_frame(t, p) for t, p in frames)
        with self._send_lock:
            self.sock.sendall(blob)

    # ---- protobuf payload builders ----
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
        use_cv = (clientver or self.clientver or CLIENT_VER_HINT).strip() or CLIENT_VER_HINT
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

    def tcp_login(
        self,
        *,
        uid: int,
        token: str,
        clientip: str,
        entry_host: str,
        entry_port: int,
    ) -> tuple[bool, str]:
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
                # Some builds return only a JSON string (no varint code). Treat as ok.
                ok = (code == 0) or (code is None)
                return ok, f"code={code}"
        return False, "no UserLoginRSP"

    # ---- warmup (captured post-login) ----
    def send_post_login_bursts(self, *, uid: int) -> None:
        u = int(uid)
        uid_pb = bytes([0x08]) + varint_encode(u)

        # Burst 1 (single sendall with many frames)
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
        self.send_frames_burst(burst1)

        # GoalREQ
        self.send_frame("pb.GoalREQ", uid_pb)

        # Burst 2
        self.send_frames_burst(
            [
                ("pb.DiamondREQ", b""),
                ("pb.SelUserVipInfoREQ", uid_pb),
            ]
        )

        # Burst 3
        self.send_frames_burst(
            [
                ("pb.DiamondREQ", b""),
                ("pb.SelUserVipInfoREQ", uid_pb),
                ("pb.UserTryToGetNewPictureFrameREQ", b""),
                ("pb.UserGetPictureFrameRedPointREQ", b""),
            ]
        )

        # Burst 4
        self.send_frames_burst(
            [
                ("pb.SelUserShopInfoREQ", uid_pb),
                ("pb.EmojiPackageREQ", uid_pb),
            ]
        )

        # Burst 5
        self.send_frames_burst(
            [
                ("pb.ClubListREQ", b""),
                ("pb.WaitListSeatInfoREQ", b""),
                ("pb.RoundHintMultipleTableREQ", b""),
            ]
        )

        # Burst 6
        self.send_frame("pb.NewMailNumREQ", b"")

    # ---- profile ops ----
    def rename_cost(self) -> Optional[int]:
        self.send_frame("pb.RenameCostREQ", b"")
        end = time.time() + 3.0
        while time.time() < end:
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == "pb.RenameCostRSP":
                fields = parse_top_fields(p)
                v = next((f.get("val") for f in fields if f.get("wt") == 0), None)
                try:
                    return int(v) if v is not None else 0
                except Exception:
                    return None
        return None

    def change_username(self, *, nickname: str) -> tuple[bool, str]:
        nb = nickname.encode("utf-8")
        payload = varint_encode((1 << 3) | 2) + varint_encode(len(nb)) + nb
        self.send_frame("pb.ChangeUserNameREQ", payload)
        end = time.time() + 5.0
        while time.time() < end:
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == "pb.ChangeUserNameRSP":
                fields = parse_top_fields(p)
                new_name = next((f.get("str") for f in fields if f.get("wt") == 2 and f.get("str")), "")
                ok = (new_name == nickname) or bool(fields)
                return ok, (new_name or "ok")
        return False, "no ChangeUserNameRSP"

    # ---- club ops ----
    def build_club_brief_info_req(self, *, club_id: int) -> bytes:
        b = bytearray()
        b += bytes([0x08]) + varint_encode(int(club_id))
        b += bytes([0x10, 0x00])
        return bytes(b)

    def get_club_brief_info(self, *, club_id: int) -> tuple[bool, dict[str, Any]]:
        payload = self.build_club_brief_info_req(club_id=club_id)
        self.send_frame("pb.ClubBriefInfoREQ", payload)

        info: dict[str, Any] = {"club_id": int(club_id)}
        end = time.time() + 4.0
        while time.time() < end:
            r = self.recv_one(timeout=1.0)
            if not r:
                continue
            t, p = r
            if t == "pb.ClubBriefInfoRSP":
                fields = parse_top_fields(p)
                code_signed = None
                for f in fields:
                    if f.get("wt") == 0 and isinstance(f.get("val"), int):
                        v = int(f["val"])
                        if v > 0x7FFFFFFFFFFFFFFF:
                            code_signed = -1
                            break
                has_str = any(isinstance(f.get("str"), str) for f in fields)
                info.update({"fields": fields, "has_str": has_str, "code_signed": code_signed})
                exists = (code_signed != -1)
                return exists, info
        return False, {"club_id": int(club_id), "timeout": True}

    def join_club(self, *, club_id: int, remark: str, apply_source: int = 0) -> tuple[bool, str]:
        # pb.JoinClubREQ: field1=club_id (varint), field2=remark (string), field3=apply_source (varint)
        b = bytearray()
        b += varint_encode((1 << 3) | 0) + varint_encode(int(club_id))
        rb = (remark or "").encode("utf-8")
        b += varint_encode((2 << 3) | 2) + varint_encode(len(rb)) + rb
        b += varint_encode((3 << 3) | 0) + varint_encode(int(apply_source))

        self.send_frame("pb.JoinClubREQ", bytes(b))
        end = time.time() + 6.0
        while time.time() < end:
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

    # ---- heartbeat ----
    def start_heartbeat(self, *, interval: float = 3.0) -> None:
        self.stop_heartbeat()
        self._hb_stop.clear()

        def _loop():
            while not self._hb_stop.is_set():
                try:
                    self.send_frame("pb.HeartBeatREQ", b"")
                except Exception:
                    break
                # sleep in small chunks to react quickly to stop
                end = time.time() + float(interval)
                while time.time() < end:
                    if self._hb_stop.is_set():
                        break
                    time.sleep(0.05)

        t = threading.Thread(target=_loop, name="fishpoker-hb", daemon=True)
        self._hb_thread = t
        t.start()

    def stop_heartbeat(self) -> None:
        self._hb_stop.set()
        if self._hb_thread and self._hb_thread.is_alive():
            self._hb_thread.join(timeout=1.5)
        self._hb_thread = None
