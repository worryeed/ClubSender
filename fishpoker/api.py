"""FishPoker HTTP+TCP API compatible with Worker expectations.

Implements:
- register/login over HTTP
- join clubs over TCP (pb.*)
- avatar upload via icon_up.php (JPEG only; auto-convert)

FishPoker is a PPPoker fork; password is md5(md5(password)).
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
import urllib3

from core.proxy_utils import normalize_proxy_input

from .client import FishPokerTCPClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://wwb.fishpoker.net"
CLIENT_VER_HINT = "1.0.49"

_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+){0,4}\b")


class ApiError(Exception):
    pass


def to_requests_proxies(proxy: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy:
        return None
    norm = normalize_proxy_input(proxy)
    if not norm:
        return None
    return {"http": norm, "https": norm}


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().lower()


def double_md5(s: str) -> str:
    # FishPoker client uses md5(md5(password))
    return md5_hex(md5_hex(s))


def _extract_client_version(j: Any, fallback: str) -> str:
    if not isinstance(j, dict):
        return fallback
    for k in ("latest_version", "latestVersion", "client_version", "clientVersion", "clientvar", "version", "ver"):
        if k in j and j.get(k):
            s = str(j.get(k)).strip()
            m = _VERSION_RE.search(s)
            if m:
                return m.group(0)
    for k, v in j.items():
        lk = str(k).lower()
        if "ver" not in lk and "version" not in lk:
            continue
        if isinstance(v, str):
            m = _VERSION_RE.search(v)
            if m:
                return m.group(0)
        elif isinstance(v, (int, float)):
            m = _VERSION_RE.search(str(v))
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


def _dedupe_endpoints(eps: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
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


def gen_random_imei() -> str:
    """FishPoker uses a MAC-like string (6 bytes hex with hyphens)."""
    import secrets

    b = secrets.token_bytes(6)
    return "-".join(f"{x:02X}" for x in b)


class FishPokerAPI:
    def __init__(self, proxy: Optional[str] = None, timeout: int = 30, base_url: str = BASE_URL):
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.timeout = int(timeout)
        self.proxies = to_requests_proxies(proxy)
        self.proxy_url = proxy

        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False
        self.session.headers.update(
            {
                "User-Agent": "libcurl",
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )

        # server-provided client version and client IP
        self.client_version: str = CLIENT_VER_HINT
        self.client_ip: str = ""
        self._version_fetched: bool = False

        # Auth
        self.token: Optional[str] = None  # rdkey
        self.refresh_token: Optional[str] = None
        self.access_token_expire: Optional[int] = None
        self.refresh_token_expire: Optional[int] = None
        self.device_id: Optional[str] = None
        self.uid: Optional[int] = None

        # TCP endpoints from last login
        self.tcp_entries: List[Tuple[str, int]] = []
        self.tcp_host: Optional[str] = None
        self.tcp_port: Optional[int] = None

        # Defaults
        self.country: str = "CN"
        self.region: int = 2
        self.os_name: str = "windows"

    # ---- HTTP helpers ----
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
    ) -> Dict[str, Any]:
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
        self._version_fetched = True
        return j

    def _ensure_version(self, imei: str) -> None:
        if self._version_fetched:
            return
        try:
            self.fetch_version(imei=imei)
        except Exception:
            # Non-fatal; keep hint
            self._version_fetched = True

    def register(
        self,
        *,
        username: str,
        password: str,
        device_id: str,
        clientvar: Optional[str] = None,
        region: int = 2,
        os_name: str = "windows",
        distributor: int = 0,
        sub_distributor: int = 0,
        appid: str = "globle",
        country: str = "CN",
        app_type: int = 1,
    ) -> Dict[str, Any]:
        imei = (device_id or "").strip() or gen_random_imei()
        self.device_id = imei
        self._ensure_version(imei)

        url = self.base_url + "/poker/api/register.php"
        params = {
            "username": str(username),
            "password": double_md5(password),
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
        try:
            return r.json()
        except Exception as e:
            raise ApiError(f"Register parse error: {e}")

    def login(
        self,
        *,
        username: str,
        password: str,
        device_id: str,
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
    ) -> Dict[str, Any]:
        imei = (device_id or "").strip() or gen_random_imei()
        self.device_id = imei
        self.country = country or self.country
        self.region = int(region)
        self.os_name = os_name or self.os_name

        self._ensure_version(imei)

        url = self.base_url + "/poker/api/login.php"
        data = {
            "type": str(type_code),
            "region": str(region),
            "code": "",
            "username": str(username),
            "password": double_md5(password),
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
        try:
            j = r.json()
        except Exception as e:
            raise ApiError(f"Login parse error: {e}")

        # Capture auth + TCP endpoints
        try:
            if int(j.get("code", -1)) == 0:
                self.uid = int(j.get("uid")) if j.get("uid") is not None else None
                self.token = str(j.get("rdkey") or "")
        except Exception:
            pass

        eps: List[Tuple[str, int]] = []
        try:
            h = j.get("gserver_ip")
            p = j.get("gserver_port")
            if h:
                eps.append((str(h), int(p or 4000)))
        except Exception:
            pass

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

        self.tcp_entries = _dedupe_endpoints(eps)
        if self.tcp_entries:
            try:
                self.tcp_host, self.tcp_port = self.tcp_entries[0]
            except Exception:
                pass

        # Some responses include clientip
        try:
            self.client_ip = str(j.get("clientip") or self.client_ip)
        except Exception:
            pass

        return j

    def logout(self, *args, **kwargs) -> Dict[str, Any]:
        # No explicit logout required for our purposes
        self.token = None
        return {"ok": True}

    def get_uid_from_login_response(self, data: Dict[str, Any]) -> Optional[int]:
        try:
            uid = data.get("uid")
            return int(uid) if uid is not None else None
        except Exception:
            return None

    # ---- avatar upload ----
    def upload_avatar(self, *, uid: int, rdkey: str, image_path: str) -> Optional[str]:
        """Upload avatar via icon_up.php; returns icon URL.

        FishPoker server only accepts JPEG. Non-JPEG images are auto-converted in memory.
        """
        url = self.base_url + "/poker/api/icon_up.php"
        params = {
            "rdkey": str(rdkey),
            "uid": str(int(uid)),
            "type": "user",
            "clubid": "0",
        }

        # Always send as JPEG
        import io

        jpg_bytes: bytes
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

        files = {"icon": (f"{int(uid)}.jpg", jpg_bytes, "image/jpeg")}
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

    # ---- TCP join ----
    def join_club_tcp(self, club_id: int, uid: Optional[int] = None, auth_token: Optional[str] = None, message_text: Optional[str] = None) -> Tuple[bool, str]:
        ok, results = self.join_clubs_tcp([int(club_id)], uid=uid, auth_token=auth_token, message_text=message_text)
        if results:
            _, o, m = results[0]
            return o, m
        return ok, "No result"

    def join_clubs_tcp(
        self,
        club_ids: List[int],
        uid: Optional[int] = None,
        auth_token: Optional[str] = None,
        keepalive: bool = False,
        progress_cb: Optional[Callable] = None,
        result_cb: Optional[Callable] = None,
        cancel_event: Optional[object] = None,
        message_text: Optional[str] = None,
    ) -> Tuple[bool, List[Tuple[int, bool, str]]]:
        token = auth_token or self.token
        if not token or uid is None or not club_ids:
            # best-effort callback reporting for consistency with Worker
            results: List[Tuple[int, bool, str]] = []
            total = len(club_ids)
            for idx, cid in enumerate(club_ids):
                try:
                    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                        break
                except Exception:
                    pass
                if progress_cb is not None:
                    try:
                        if progress_cb(int(cid), idx, total) is False:
                            break
                    except Exception:
                        pass
                msg = "No auth token" if not token else ("UID is required" if uid is None else "No clubs")
                results.append((int(cid), False, msg))
                if result_cb is not None:
                    try:
                        result_cb(int(cid), False, msg, idx, total)
                    except Exception:
                        pass
            return False, results

        # Ensure version/client IP if device_id is known
        try:
            if self.device_id:
                self._ensure_version(self.device_id)
        except Exception:
            pass

        endpoints = list(self.tcp_entries or [])
        # Allow passing endpoints via extra attribute (set by Worker)
        try:
            if not endpoints and hasattr(self, "tcp_endpoints"):
                endpoints = list(getattr(self, "tcp_endpoints") or [])
        except Exception:
            pass
        if not endpoints:
            # No server to connect to — still report per-club results via callbacks
            results = [(int(cid), False, "No TCP endpoints") for cid in club_ids]
            total = len(results)
            for idx, (cid, ok, msg) in enumerate(results):
                try:
                    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                        break
                except Exception:
                    pass
                if progress_cb is not None:
                    try:
                        if progress_cb(int(cid), idx, total) is False:
                            break
                    except Exception:
                        pass
                if result_cb is not None:
                    try:
                        result_cb(int(cid), bool(ok), str(msg or ""), idx, total)
                    except Exception:
                        pass
            return False, results

        tcp: Optional[FishPokerTCPClient] = None
        last_err: Optional[Exception] = None
        max_login_attempts = 3
        for host, port in endpoints:
            # allow cancellation before attempting a potentially-blocking connect
            try:
                if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                    last_err = OSError("cancelled")
                    break
            except Exception:
                pass
            try:
                tcp = FishPokerTCPClient(host=host, port=int(port), timeout=5.0, proxy=self.proxy_url)
                try:
                    tcp.set_cancel_event(cancel_event)
                except Exception:
                    pass
                tcp.clientver = self.client_version or CLIENT_VER_HINT
                tcp.country = self.country or "CN"
                tcp.connect()
                ok_login = False
                msg_login = ""
                for att in range(1, max_login_attempts + 1):
                    try:
                        if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                            raise OSError("cancelled")
                    except Exception:
                        pass
                    ok_login, msg_login = tcp.tcp_login(
                        uid=int(uid),
                        token=str(token),
                        clientip=self.client_ip or "",
                        entry_host=host,
                        entry_port=int(port),
                    )
                    if ok_login:
                        break
                    low = (msg_login or "").lower()
                    transient_login = ("no userloginrsp" in low) or ("code=-1" in low)
                    if (not transient_login) or att >= max_login_attempts:
                        break
                    # small backoff before next attempt
                    try:
                        if cancel_event is not None and hasattr(cancel_event, "wait"):
                            cancel_event.wait(timeout=0.6)
                        else:
                            time.sleep(0.6)
                    except Exception:
                        time.sleep(0.6)
                if not ok_login:
                    raise OSError(f"tcp_login failed: {msg_login}")
                break
            except Exception as e:
                last_err = e
                try:
                    if tcp:
                        tcp.close()
                except Exception:
                    pass
                tcp = None
                continue

        if tcp is None:
            results = [(int(cid), False, f"TCP connect/login failed: {last_err}") for cid in club_ids]
            total = len(results)
            for idx, (cid, ok, msg) in enumerate(results):
                try:
                    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                        break
                except Exception:
                    pass
                if progress_cb is not None:
                    try:
                        if progress_cb(int(cid), idx, total) is False:
                            break
                    except Exception:
                        pass
                if result_cb is not None:
                    try:
                        result_cb(int(cid), bool(ok), str(msg or ""), idx, total)
                    except Exception:
                        pass
            return False, results

        results: List[Tuple[int, bool, str]] = []
        any_ok = False
        total = len(club_ids)
        try:
            for idx, cid in enumerate(club_ids):
                # cancellation
                try:
                    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                        break
                except Exception:
                    pass
                if progress_cb is not None:
                    try:
                        if progress_cb(int(cid), idx, total) is False:
                            break
                    except Exception:
                        pass
                exists = False
                try:
                    exists, _info = tcp.get_club_brief_info(club_id=int(cid))
                except Exception:
                    exists = False
                if not exists:
                    # Keep wording consistent with JoinResult.as_dict() not-found markers
                    ok, msg = False, "Клуб не найден"
                else:
                    remark = (message_text or f"fp{int(uid)}")
                    if len(remark) > 40:
                        remark = remark[:40]
                    ok, msg = tcp.join_club(club_id=int(cid), remark=remark, apply_source=0)
                results.append((int(cid), bool(ok), str(msg or "")))
                any_ok = any_ok or bool(ok)
                if result_cb is not None:
                    try:
                        result_cb(int(cid), bool(ok), str(msg or ""), idx, total)
                    except Exception:
                        pass
            return any_ok, results
        finally:
            if not keepalive:
                try:
                    tcp.close()
                except Exception:
                    pass

    # ---- profile ops (used in registration flow) ----
    def change_username_tcp(self, *, uid: int, token: str, nickname: str, endpoints: Optional[List[Tuple[str, int]]] = None, cancel_event: Optional[object] = None) -> Tuple[bool, str]:
        eps = list(endpoints or self.tcp_entries or [])
        if not eps:
            return False, "No TCP endpoints"
        last_err = None
        max_login_attempts = 3
        for host, port in eps:
            # allow cancellation before attempting a potentially-blocking connect
            try:
                if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                    return False, "cancelled"
            except Exception:
                pass
            tcp = FishPokerTCPClient(host=host, port=int(port), timeout=5.0, proxy=self.proxy_url)
            try:
                tcp.set_cancel_event(cancel_event)
            except Exception:
                pass
            tcp.clientver = self.client_version or CLIENT_VER_HINT
            tcp.country = self.country or "CN"
            try:
                tcp.connect()
                ok_login = False
                msg_login = ""
                for att in range(1, max_login_attempts + 1):
                    try:
                        if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                            raise OSError("cancelled")
                    except Exception:
                        pass
                    ok_login, msg_login = tcp.tcp_login(
                        uid=int(uid),
                        token=str(token),
                        clientip=self.client_ip or "",
                        entry_host=host,
                        entry_port=int(port),
                    )
                    if ok_login:
                        break
                    low = (msg_login or "").lower()
                    transient_login = ("no userloginrsp" in low) or ("code=-1" in low)
                    if (not transient_login) or att >= max_login_attempts:
                        break
                    try:
                        if cancel_event is not None and hasattr(cancel_event, "wait"):
                            cancel_event.wait(timeout=0.6)
                        else:
                            time.sleep(0.6)
                    except Exception:
                        time.sleep(0.6)
                if not ok_login:
                    raise OSError(f"tcp_login failed: {msg_login}")
                try:
                    tcp.send_post_login_bursts(uid=int(uid))
                except Exception:
                    pass
                ok, msg = tcp.change_username(nickname=nickname)
                return bool(ok), str(msg or "")
            except Exception as e:
                last_err = e
            finally:
                try:
                    tcp.close()
                except Exception:
                    pass
        return False, str(last_err) if last_err else "failed"
