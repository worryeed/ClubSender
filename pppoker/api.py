"""PPPoker HTTP+TCP API compatible with Worker expectations."""
from __future__ import annotations
import time
import json
import hashlib
import base64
from time import gmtime, strftime
from typing import Optional, Dict, Any, Tuple, List
import re
import requests
import urllib3
from core.proxy_utils import normalize_proxy_input
from .client import PPPokerTCPClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://www.pppoker.club"
LOGIN_PATH = "/poker/api/login.php"
CLIENT_VER = "4.2.41"


class ApiError(Exception):
    pass


def to_requests_proxies(proxy: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy:
        return None
    norm = normalize_proxy_input(proxy)
    if not norm:
        return None
    return {"http": norm, "https": norm}


def compute_crypto_password(password: str) -> str:
    md5_1 = hashlib.md5(password.encode('utf-8')).hexdigest().lower()
    return hashlib.md5(md5_1.encode('ascii')).hexdigest().lower()


def mmddhhmmss_from_epoch_beijing(epoch: int) -> str:
    return strftime("%m%d%H%M%S", gmtime(epoch + 8 * 3600))


def encrypt_password_exact(crypto_password_hex: str, epoch: int) -> str:
    DELTA = 0x9E3779B9

    def to_u32_le_blocks(b: bytes) -> list[int]:
        assert len(b) % 4 == 0
        return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]

    def from_u32_le_blocks(v: list[int]) -> bytes:
        return b''.join((x & 0xffffffff).to_bytes(4, 'little') for x in v)

    def xxtea_encrypt_blocks(v: list[int], k: list[int]) -> list[int]:
        n = len(v)
        if n < 2:
            return v
        z = v[n - 1]
        sum_ = 0
        q = 6 + 52 // n
        for _ in range(q):
            sum_ = (sum_ + DELTA) & 0xffffffff
            e = (sum_ >> 2) & 3
            for p in range(n - 1):
                y = v[p + 1]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] + mx) & 0xffffffff
                z = v[p]
            y = v[0]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (k[((n - 1) & 3) ^ e] ^ z))
            v[n - 1] = (v[n - 1] + mx) & 0xffffffff
            z = v[n - 1]
        return v

    t10 = mmddhhmmss_from_epoch_beijing(epoch)
    key16 = (t10 + "d56590").encode('ascii')  # 16 bytes
    pt = crypto_password_hex.encode('ascii')   # 32 bytes
    payload = pt + len(pt).to_bytes(4, 'little')
    v = to_u32_le_blocks(payload)
    k = to_u32_le_blocks(key16)
    ct = xxtea_encrypt_blocks(v, k)
    out = from_u32_le_blocks(ct)
    return base64.b64encode(out).decode('ascii')


def _normalize_imei(device_id: Optional[str], username: str) -> str:
    """Всегда формируем IMEI в нужном формате: 40-символьный hex (SHA1).
    Основано на device_id (без дефисов); если пусто — используем username.
    """
    s = (device_id or '').strip()
    seed = s.replace('-', '').strip() or (username or 'pppoker')
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()


class PPPokerAPI:
    def __init__(self, proxy: Optional[str] = None, timeout: int = 30):
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = timeout
        self.proxies = to_requests_proxies(proxy)
        self.proxy_url = proxy
        self.token: Optional[str] = None  # rdkey
        self.refresh_token: Optional[str] = None
        self.access_token_expire: Optional[int] = None
        self.refresh_token_expire: Optional[int] = None
        self.device_id: Optional[str] = None
        self.tcp_entries: List[tuple[str, int]] = []
        self.tcp_host: Optional[str] = None
        self.tcp_port: Optional[int] = None

    def login(self, *, username: str, password: str, device_id: str = "", **kwargs) -> Dict[str, Any]:
        url = BASE_URL + LOGIN_PATH
        crypto_pw = compute_crypto_password(password)
        t_epoch = int(time.time())
        enc_password = encrypt_password_exact(crypto_pw, t_epoch)
        data = {
            'type': '4','region': '2','code': '',
            'username': username,
            'password': enc_password,
            't': str(t_epoch),
            'uid': '', 'rdkey': '',
            'os': 'windows',
            'distributor': '0', 'sub_distributor': '0',
            'country': 'RU',
            'appid': 'globle', 'clientvar': CLIENT_VER,
'imei': _normalize_imei(device_id, username),
            'device_token': '', 'platform_type': '1',
            'lang': 'ru', 'languagecode': 'ru',
            'apple_full_name': '', 'apple_user': '', 'apple_identity_token': '',
            'app_build_code': '220','operating_company': 'unknow','app_type': '1',
        }
        r = self.session.post(url, data=data, proxies=self.proxies, timeout=self.timeout)
        r.raise_for_status()
        try:
            j = r.json()
        except Exception as e:
            raise ApiError(f"Login parse error: {e}")
        # expected fields: code, uid, rdkey, gserver_ip, gserver_port, clientip
        if int(j.get('code', -1)) == 0:
            self.token = str(j.get('rdkey') or '')
            try:
                self.tcp_host = str(j.get('gserver_ip') or '')
                self.tcp_port = int(j.get('gserver_port') or 4000)
                if self.tcp_host:
                    self.tcp_entries = [(self.tcp_host, self.tcp_port)]
            except Exception:
                pass
        return j

    def logout(self, *args, **kwargs) -> Dict[str, Any]:
        # PPPoker login flow does not require explicit logout for our purposes
        return {"ok": True}

    def get_uid_from_login_response(self, data: Dict[str, Any]) -> Optional[int]:
        try:
            uid = data.get('uid')
            return int(uid) if uid is not None else None
        except Exception:
            return None

    def join_club_tcp(self, club_id: int, uid: Optional[int] = None, auth_token: Optional[str] = None, message_text: Optional[str] = None) -> Tuple[bool, str]:
        ok, results = self.join_clubs_tcp([club_id], uid=uid, auth_token=auth_token, message_text=message_text)
        if results:
            _, o, m = results[0]
            return o, m
        return ok, "No result"

    def join_clubs_tcp(self,
                        club_ids: list[int],
                        uid: Optional[int] = None,
                        auth_token: Optional[str] = None,
                        keepalive: bool = False,
                        progress_cb: Optional[Callable] = None,
                        result_cb: Optional[Callable] = None,
                        cancel_event: Optional[object] = None,
                        message_text: Optional[str] = None) -> Tuple[bool, list[Tuple[int, bool, str]]]:
        token = auth_token or self.token
        if not token or uid is None or not club_ids:
            return False, []
        host = self.tcp_host or 'ali-entry.pppoker.club'
        port = int(self.tcp_port or 4000)
        clientip = ''  # optional; could fetch via /version.php if needed
        tcp = PPPokerTCPClient(host=host, port=port, timeout=5.0, proxy=self.proxy_url)
        results: list[Tuple[int, bool, str]] = []
        try:
            # Жёсткая отмена: при установке cancel_event закрыть сокет (разблокирует ожидания)
            try:
                if cancel_event is not None:
                    import threading as _th
                    def _closer():
                        try:
                            cancel_event.wait()
                            tcp.close()
                        except Exception:
                            pass
                    _th.Thread(target=_closer, daemon=True).start()
            except Exception:
                pass
            tcp.connect()
            ok_login, msg = tcp.tcp_login(uid=uid, token=token, clientip=clientip, entry_host=host, entry_port=port)
            if not ok_login:
                return False, [(cid, False, f"TCP login failed: {msg}") for cid in club_ids]
            any_ok = False
            total = len(club_ids)
            for idx, cid in enumerate(club_ids):
                # Проверка внешней отмены перед каждым клубом
                try:
                    if cancel_event is not None and getattr(cancel_event, 'is_set', lambda: False)():
                        break
                except Exception:
                    pass
                try:
                    if progress_cb and progress_cb(cid, idx, total) is False:
                        break
                except Exception:
                    pass
                # remark: cap to 40 chars similar to XPoker UI
                remark = (message_text or f"pp{uid}")
                if len(remark) > 40:
                    remark = remark[:40]
                ok, m = tcp.join_club(club_id=int(cid), remark=remark, apply_source=0)
                results.append((cid, ok, m))
                any_ok = any_ok or ok
                try:
                    if result_cb:
                        result_cb(cid, ok, m, idx, total)
                except Exception:
                    pass
            return any_ok, results
        finally:
            if not keepalive:
                try:
                    tcp.close()
                except Exception:
                    pass
