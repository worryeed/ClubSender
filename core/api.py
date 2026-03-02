"""HTTP API module for X-Poker client."""

from __future__ import annotations
import time
import json
import hashlib
import logging
import os
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from requests.packages.urllib3.util.retry import Retry
import ssl
import socket
from .proxy_utils import normalize_proxy_input

from .constants import (
    DEFAULT_BASE_URL, LOGIN_PATH, REGISTER_PATH, LOGOUT_PATH,
    JOIN_CLUB_PATH, SEARCH_CLUB_PATH, REFRESH_PATH,
    AVAILABLE_PATH, CAPTCHA_REG_CODE_PATH, MAX_CAPTCHA_RETRIES,
    DEFAULT_HEARTBEAT_INTERVAL, XPOKER_CLIENT_VERSION,
)
from .captcha_solver import solve_captcha_b64, CaptchaSolveError
from .client import XClubTCPClient
from .messages import Icons, decode_club_apply_status, format_tcp_step

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

# Dedicated HTTP trace logger -> logs/http_requests.log
_httptrace: Optional[logging.Logger] = None

def _get_httptrace() -> logging.Logger:
    global _httptrace
    if _httptrace is not None:
        return _httptrace
    logger = logging.getLogger('httptrace')
    if not getattr(logger, '_configured', False):
        try:
            trace_path = Path('logs')/ 'http_requests.log'
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(trace_path), encoding='utf-8')
            fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            logger.setLevel(logging.INFO)
            # Mark configured to avoid duplicates even across multiple API instances
            setattr(logger, '_configured', True)
        except Exception:
            pass
    _httptrace = logger
    return logger

# HTTP keys from Lua dump
HTTP_KEY_PROD = "aacadfb9b150ff8fa713bbe8431773fa"
HTTP_KEY_DEBUG = "a310e0b2838fb90f7f4b0e7d4d672f0c"


class ApiError(Exception):
    """API error exception."""
    pass


def default_headers() -> Dict[str, str]:
    """Get default HTTP headers matching working test_live_signs.py format."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8", 
        "User-Agent": "X-Poker/1.12.68 (Windows)",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": "https://xpoker.games",
        "Referer": "https://xpoker.games/",
        "Connection": "keep-alive"
    }


def md5(s: str) -> str:
    """Calculate single MD5 hash of string."""
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def double_md5(s: str) -> str:
    """Calculate double MD5 hash for X-Poker password.
    
    Args:
        s: Original password string
        
    Returns:
        Double MD5 hash string"""
    # First MD5: password -> hex string  
    first_md5 = hashlib.md5(s.encode('utf-8')).hexdigest()
    # Second MD5: hex string -> final hash
    second_md5 = hashlib.md5(first_md5.encode('ascii')).hexdigest()
    
    log.debug(f"Password double MD5: {s} -> {first_md5} -> {second_md5}")
    return second_md5


# 🚀 ТОЛЬКО САМОСТОЯТЕЛЬНАЯ ГЕНЕРАЦИЯ ПОДПИСЕЙ!
# Все живые подписи полностью удалены - программа генерирует подписи сама!

def generate_sign(payload: Dict[str, Any], timestamp: int, endpoint: str = "", body: bytes = None) -> str:
    """Генерация подписи по подтверждённой формуле (без URL-энкодинга значений)."""
    # 1) Сортируем параметры по ключам
    sorted_params = sorted(payload.items())
    # 2) Формируем k=v через & (значения как есть; для dict/list — компактный JSON)
    parts = []
    for k, v in sorted_params:
        if isinstance(v, (dict, list)):
            v_str = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        else:
            v_str = str(v)
        parts.append(f"{k}={v_str}")
    param_string = "&".join(parts)
    # 3) Первый MD5 по param_string + timestamp
    first = hashlib.md5((param_string + str(timestamp)).encode('utf-8')).hexdigest()
    # 4) Второй MD5 с HTTP_KEY (по умолчанию production)
    http_key = HTTP_KEY_PROD
    signature = hashlib.md5((first + http_key).encode('utf-8')).hexdigest()
    log.debug(f"sign({endpoint}) params='{param_string}' ts={timestamp} -> first={first[:8]}.. sign={signature[:8]}..")
    return signature


def mask_proxy_for_log(url: str) -> str:
    """Mask credentials in a proxy URL for safe logging.
    Example: http://user:pass@host:port -> http://user:***@host:port
    """
    try:
        from urllib.parse import urlparse
        u = urlparse(url)
        if u.username:
            masked_auth = f"{u.username}:***@"
            # netloc may include auth already; rebuild netloc without password
            hostport = u.hostname or ""
            if u.port:
                hostport = f"{hostport}:{u.port}"
            return f"{u.scheme}://{masked_auth}{hostport}"
        return url
    except Exception:
        return url


def to_requests_proxies(proxy: Optional[str]) -> Optional[Dict[str, str]]:
    """Convert user proxy string to requests format with autodetect.
    Accepts "user:pass@ip:port" or "ip:port" — scheme is auto-detected.
    """
    if not proxy:
        return None
    # Normalize and autodetect scheme (http/socks5h)
    norm = normalize_proxy_input(proxy)
    if not norm:
        return None
    log.debug(f"Using proxy: {mask_proxy_for_log(norm)}")
    return {"http": norm, "https": norm}


class TLSAdapter(HTTPAdapter):
    """HTTP adapter that forces TLS 1.2 to avoid SSL EOF errors."""
    
    def init_poolmanager(self, *args, **kwargs):
        # Create SSL context with TLS 1.2
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class XPokerAPI:
    """HTTP API client for X-Poker."""
    
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        *,
mobile_profile: bool = True,
    ):
        """Initialize API client.
        
        Args:
            base_url: Base URL for API
            proxy: Optional proxy string
            headers: Optional additional headers
            timeout: Request timeout in seconds"""
        self.base_url = base_url.rstrip("/")
        self.mobile_profile = bool(mobile_profile)
        # Disable TLS key logging if set in environment to avoid file handle leaks on massive handshakes
        try:
            if os.environ.get('SSLKEYLOGFILE'):
                os.environ.pop('SSLKEYLOGFILE', None)
                log.info("SSLKEYLOGFILE detected in environment — disabled for this process to prevent open-file exhaustion")
        except Exception:
            pass
        self.session = requests.Session()
        
        # Server-provided client version (used for TCP); fallback to constant
        self.client_version: str = XPOKER_CLIENT_VERSION
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=2,
            connect=2,
            read=2,
            status=2,
            backoff_factor=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            respect_retry_after_header=True
        )
        
        # Mount TLS adapter with retry strategy
        adapter = TLSAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        # Store retry policy for logging/user messages
        self._retry_total = 2
        self._retry_backoff = 3
        log.info(f"HTTP повторы настроены: попыток={self._retry_total}, backoff≈{self._retry_backoff}s")
        
        self.session.headers.update(default_headers())
        if self.mobile_profile:
            try:
                self.session.headers["User-Agent"] = f"X-Poker/{self.client_version} (Android)"
            except Exception:
                pass
        if headers:
            self.session.headers.update(headers)
        self.proxies = to_requests_proxies(proxy)
        self.proxy_url: Optional[str] = proxy  # сохраняем исходную строку для TCP
        self.timeout = timeout
        # Trace initial settings
        try:
            httptrace = _get_httptrace()
            masked = None
            if self.proxies:
                try:
                    masked = {k: mask_proxy_for_log(v) for k, v in self.proxies.items()}
                except Exception:
                    masked = {"http": "***", "https": "***"}
            httptrace.info(f"INIT base_url={self.base_url} proxy={masked if masked else 'None'} retries={getattr(self,'_retry_total', '2')} backoff≈{getattr(self,'_retry_backoff','30')}s")
        except Exception:
            pass
        self.token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.access_token_expire: Optional[int] = None
        self.refresh_token_expire: Optional[int] = None
        self.device_id: Optional[str] = None  # сохраняем последний device_id для refresh
        self._is_retrying: bool = False  # защита от бесконечных ретраев
        # список TCP-эндпоинтов (host, port) из последнего HTTP-логина
        self.tcp_entries: list[tuple[str, int]] = []

    def _request(
        self,
        method: str,
        path: str,
        *,
        params=None,
        json_body=None,
        auth_token: Optional[str] = None,
        retry_on_401: bool = True
    ) -> Dict[str, Any]:
        """Make HTTP request with detailed logging.
        
        Args:
            method: HTTP method
            path: Request path
            params: URL parameters
            json_body: JSON body
            auth_token: Authorization token
            
        Returns:
            Response data
            
        Raises:
            ApiError: If request fails"""
        url = self.base_url + path
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        # === Logging (compact INFO, verbose DEBUG) ===
        log.debug(f"🌐 HTTP {method} {url}")
        log.debug(f"   📤 Headers: {dict(self.session.headers)}")
        if headers:
            log.debug(f"   📤 Additional headers: {headers}")
        if params:
            log.debug(f"   📤 Query params: {params}")
        if json_body:
            log.debug(f"   📤 JSON body: {json.dumps(json_body, indent=2, ensure_ascii=False)}")
        if self.proxies:
            try:
                masked = {k: mask_proxy_for_log(v) for k, v in self.proxies.items()}
            except Exception:
                masked = {"http": "***", "https": "***"}
            log.debug(f"   🔀 Proxy: {masked}")
            
        start_time = time.time()
        # HTTP trace: request line (safe)
        try:
            httptrace = _get_httptrace()
            masked = None
            if self.proxies:
                try:
                    masked = {k: mask_proxy_for_log(v) for k, v in self.proxies.items()}
                except Exception:
                    masked = {"http": "***", "https": "***"}
            body_info = None
            if isinstance(json_body, dict):
                try:
                    body_info = f"keys={list(json_body.keys())}"
                except Exception:
                    body_info = "dict"
            elif json_body is not None:
                try:
                    body_info = f"type={type(json_body).__name__}"
                except Exception:
                    body_info = "payload"
            httptrace.info(f"REQ {method} {url} params={params} body={body_info} proxy={masked if masked else 'None'}")
        except Exception:
            pass
        try:
            r = self.session.request(
                method, url,
                params=params,
                json=json_body,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False
            )
        except requests.exceptions.ProxyError as e:
            # Ошибка прокси (аутентификация/недоступность)
            log.error(f"❌ Прокси-ошибка при обращении к {url}: {e}")
            raise ApiError(f"Proxy error: {e}")
        except requests.exceptions.ConnectTimeout as e:
            log.error(f"❌ Таймаут соединения при обращении к {url}: {e}")
            raise ApiError(f"Connect timeout: {e}")
        except requests.exceptions.RetryError as e:
            # Повторные 5xx/429 исчерпали лимит ретраев — считаем как API-ошибку для ротации прокси
            log.error(f"❌ HTTP повторы исчерпаны для {url}: {e} (политика: попыток={getattr(self,'_retry_total', 'N/A')}, backoff≈{getattr(self,'_retry_backoff','N/A')}s)")
            try:
                _get_httptrace().error(f"ERR {method} {url} -> RETRY-EXHAUSTED: {e}")
            except Exception:
                pass
            raise ApiError(f"Retry error: {e}")
        except urllib3.exceptions.MaxRetryError as e:
            # На всякий случай, если пробросится низкоуровневая ошибка urllib3
            log.error(f"❌ HTTP max retries for {url}: {e} (политика: попыток={getattr(self,'_retry_total', 'N/A')}, backoff≈{getattr(self,'_retry_backoff','N/A')}s)")
            try:
                _get_httptrace().error(f"ERR {method} {url} -> MAX-RETRIES: {e}")
            except Exception:
                pass
            raise ApiError(f"Retry error: {e}")
        except requests.exceptions.ConnectionError as e:
            # Если прокси задан, поясним, что проблема на стороне прокси
            if self.proxies:
                # Пытаемся извлечь адрес прокси из настроек
                proxy_url = self.proxies.get('https') or self.proxies.get('http') or ''
                log.error(f"❌ Не удалось соединиться через прокси ({mask_proxy_for_log(proxy_url)}): {e}")
                raise ApiError(f"Proxy connect error: {e}")
            log.error(f"❌ Ошибка соединения при обращении к {url}: {e}")
            raise ApiError(f"Connection error: {e}")
        request_time = time.time() - start_time
        
        # Compact response line
        log.info(f"HTTP {method} {path} -> {r.status_code} ({request_time:.3f}s)")
        try:
            httptrace = _get_httptrace()
            httptrace.info(f"RSP {method} {url} -> {r.status_code} in {request_time:.3f}s len={len(r.content) if hasattr(r,'content') else 'N/A'}")
        except Exception:
            pass
        # Verbose details to DEBUG
        log.debug(f"   📥 Response headers: {dict(r.headers)}")
        response_text = r.text
        if len(response_text) > 2000:
            log.debug(f"   📥 Response body (first 2000 chars): {response_text[:2000]}...")
            log.debug(f"   📥 Response body (last 500 chars): ...{response_text[-500:]}")
        else:
            log.debug(f"   📥 Response body: {response_text}")
        
        # Auto-refresh on 401 if possible
        if r.status_code == 401 and retry_on_401 and self.refresh_token:
            log.warning("🔄 Access token expired or unauthorized; attempting refresh...")
            try:
                ok, msg = self.refresh_access_token()
                if ok and self.token:
                    # Retry original request once with new token
                    headers_retry = headers.copy() if headers else {}
                    headers_retry["Authorization"] = f"Bearer {self.token}"
                    return self._request(
                        method,
                        path,
                        params=params,
                        json_body=json_body,
                        auth_token=self.token,
                        retry_on_401=False
                    )
                else:
                    log.error(f"❌ Refresh failed: {msg}")
            except Exception as re:
                log.error(f"❌ Refresh exception: {re}")
        
        if r.status_code >= 400:
            ct = str(r.headers.get('Content-Type', '') or '').lower()
            body_text = r.text or ''
            is_html = ('text/html' in ct) or body_text.lstrip().lower().startswith('<!doctype') or body_text.lstrip().lower().startswith('<html')
            if is_html:
                msg = f"{r.status_code} Доступ заблокирован сетевым фильтром (HTML-страница)"
                log.error(f"❌ HTTP Error {msg}")
                try:
                    httptrace = _get_httptrace()
                    httptrace.error(f"ERR {method} {url} -> {r.status_code} HTML len={len(body_text) if hasattr(body_text,'__len__') else 'N/A'}")
                except Exception:
                    pass
                raise ApiError(msg)
            else:
                short = body_text[:400]
                log.error(f"❌ HTTP Error {r.status_code}: {short}")
                try:
                    httptrace = _get_httptrace()
                    httptrace.error(f"ERR {method} {url} -> {r.status_code} body={short}...")
                except Exception:
                    pass
                raise ApiError(f"{r.status_code} {short}")
            
        try:
            response_data = r.json()
            log.info(f"   📥 Parsed JSON: {json.dumps(response_data, indent=2, ensure_ascii=False)}")
            return response_data
        except Exception as e:
            log.warning(f"   ⚠️ Failed to parse JSON: {e}")
            return {"text": r.text}

    def login(
        self,
        *,
        username: str,
        password: str,
        device_id: str,
        os_code: str = "3",
        device: str = "windows",
        lang: str = "ru",
        app_level: int = 0,
        timezone_id: str = "",
        device_token: str = ""
    ) -> Dict[str, Any]:
        """Login to X-Poker API.
        
        Args:
            username: Username
            password: Password (plain or MD5)
            password_is_md5: Whether password is already MD5
            device_id: Device identifier
            os_code: OS code (default "3" for Windows)
            device: Device type
            lang: Language code
            app_level: Application level
            timezone_id: Timezone
            device_token: Device token
            
        Returns:
            Login response data"""
        # Use working payload from analysis
        if self.mobile_profile:
            try:
                if os_code == "3":
                    os_code = "1"
                if device == "windows":
                    device = "android"
            except Exception:
                pass
        payload = {
            "timezoneId": timezone_id,
            "appLevel": app_level,
            "os": os_code,
            "device": device,
            "deviceId": device_id,
            "lang": lang,
            "username": username,
            # всегда используем double MD5 от чистого пароля
            "password": double_md5(password),
            "deviceToken": device_token
        }
        
        # Сохраняем контекст для refresh
        self.device_id = device_id
        
        # 🚀 Генерация подписи (без URL-энкодинга)
        timestamp = int(time.time())
        sign = generate_sign(payload, timestamp, LOGIN_PATH)
        params = {
            "timestamp": str(timestamp),
            "sign": sign
        }
        
        log.debug(f"Login attempt for {username}")
        data = self._request("POST", LOGIN_PATH, params=params, json_body=payload)
        
        # Extract tokens from response
        token = None
        if isinstance(data, dict) and data.get("code") == 0:
            if "data" in data and "auth" in data["data"]:
                auth_data = data["data"]["auth"]
                token = auth_data.get("accessToken")
                self.refresh_token = auth_data.get("refreshToken")
                self.access_token_expire = auth_data.get("accessTokenExpire") or auth_data.get("access_token_expire")
                self.refresh_token_expire = auth_data.get("refreshTokenExpire") or auth_data.get("refresh_token_expire")
            
            if not token:
                # Try alternative locations
                token = data.get("token") or data.get("access_token") or data.get("accessToken")
                
                if not token and "data" in data:
                    data_field = data["data"]
                    if isinstance(data_field, dict):
                        token = (
                            data_field.get("token") or
                            data_field.get("access_token") or
                            data_field.get("accessToken")
                        )
            # Try to detect client version from response
            try:
                self._maybe_update_client_version_from_response(data)
            except Exception:
                pass
        
        if token:
            self.token = token
            log.info(f"Login successful for {username}")
        else:
            log.warning(f"No token found in response for {username}")
            
        # Try to capture TCP entry host/port from login response
        try:
            if isinstance(data, dict):
                entry = data.get("data", {}).get("entry", {})
                # collect all available endpoints in preferred order
                endpoints: list[tuple[str, int]] = []
                try:
                    h1 = entry.get("gameBaseEntry")
                    p1 = entry.get("gameBasePort")
                    if h1:
                        endpoints.append((str(h1), int(p1 or 5000)))
                except Exception:
                    pass
                try:
                    h2 = entry.get("gameBaseEntry2")
                    p2 = entry.get("gameBasePort2")
                    if h2:
                        endpoints.append((str(h2), int(p2 or 5000)))
                except Exception:
                    pass
                try:
                    h3 = entry.get("gameBaseEntry3")
                    p3 = entry.get("gameBasePort3")
                    if h3:
                        endpoints.append((str(h3), int(p3 or 5000)))
                except Exception:
                    pass
                # de-duplicate while preserving order
                dedup: list[tuple[str, int]] = []
                for hp in endpoints:
                    if hp not in dedup:
                        dedup.append(hp)
                if dedup:
                    self.tcp_entries = dedup
                    # Set primary host/port for convenience
                    self.tcp_host, self.tcp_port = dedup[0]
                    log.info(f"🧭 TCP entry from login: {self.tcp_host}:{self.tcp_port}")
        except Exception as e:
            log.debug(f"Failed to capture TCP entry from login: {e}")
            
        return data

    def check_available(
        self,
        username: str,
        device_id: str,
        app_level: int = 0,
    ) -> bool:
        """Check if a username is available for registration.

        Returns True if username is available (code==0), False otherwise.
        """
        payload = {
            "username": username,
            "appLevel": app_level,
            "deviceId": device_id,
        }
        ts = int(time.time())
        sign = generate_sign(payload, ts, AVAILABLE_PATH)
        params = {"timestamp": str(ts), "sign": sign}
        log.info(f"Проверка доступности ника '{username}'")
        data = self._request("POST", AVAILABLE_PATH, params=params, json_body=payload, auth_token=None)
        code = data.get("code", -1) if isinstance(data, dict) else -1
        if code == 0:
            log.info(f"Ник '{username}' свободен")
            return True
        msg = data.get("msg", "") if isinstance(data, dict) else ""
        log.warning(f"Ник '{username}' недоступен: code={code} msg={msg}")
        return False

    def request_captcha(
        self,
        device_id: str,
        app_level: int = 0,
    ) -> tuple[str, str]:
        """Request a registration captcha image.

        Returns (image_base64, captcha_key).
        Raises ApiError if the request fails.
        """
        payload = {
            "appLevel": app_level,
            "deviceId": device_id,
        }
        ts = int(time.time())
        sign = generate_sign(payload, ts, CAPTCHA_REG_CODE_PATH)
        params = {"timestamp": str(ts), "sign": sign}
        log.info("Запрос капчи для регистрации")
        data = self._request("POST", CAPTCHA_REG_CODE_PATH, params=params, json_body=payload, auth_token=None)
        code = data.get("code", -1) if isinstance(data, dict) else -1
        if code != 0:
            msg = data.get("msg", "") if isinstance(data, dict) else ""
            raise ApiError(f"Ошибка запроса капчи: code={code} msg={msg}")
        captcha_data = data.get("data", {})
        img_b64 = captcha_data.get("img")
        captcha_key = captcha_data.get("key")
        if not img_b64:
            raise ApiError(f"Сервер не вернул изображение капчи (data keys: {list(captcha_data.keys())})")
        if not captcha_key:
            raise ApiError(f"Сервер не вернул ключ капчи (data keys: {list(captcha_data.keys())})")
        log.info(f"Капча получена: image={len(img_b64)} chars, key={captcha_key[:30]}...")
        return img_b64, captcha_key

    def register(
        self,
        *,
        username: str,
        password: str,
        device_id: str,
        os_code: str = "3",
        device: str = "windows",
        lang: str = "ru",
        app_level: int = 0,
        timezone_id: str = "",
        device_token: str = "",
        country: str = "UnKnown",
    ) -> Dict[str, Any]:
        """Register a new X-Poker account with automatic captcha solving.

        Flow:
          1. Request captcha from /api/common/captcha/regCode
          2. Solve captcha with ddddocr
          3. Submit registration with captcha answer
          4. If captcha wrong — retry (up to MAX_CAPTCHA_RETRIES attempts)

        The registration payload uses double MD5 password and timestamp/sign.
        On success, tokens and TCP entries are extracted from the response.
        """
        if self.mobile_profile:
            try:
                if os_code == "3":
                    os_code = "1"
                if device == "windows":
                    device = "android"
            except Exception:
                pass

        # keep last device_id for potential refresh
        self.device_id = device_id
        password_hash = double_md5(password)

        last_data: Dict[str, Any] = {}

        for attempt in range(1, MAX_CAPTCHA_RETRIES + 1):
            # --- Step 1: Request captcha ---
            try:
                img_b64, captcha_key = self.request_captcha(device_id, app_level)
            except (ApiError, Exception) as e:
                log.error(f"Ошибка получения капчи (попытка {attempt}/{MAX_CAPTCHA_RETRIES}): {e}")
                if attempt < MAX_CAPTCHA_RETRIES:
                    import time as _time
                    _time.sleep(1)
                    continue
                raise ApiError(f"Не удалось получить капчу после {MAX_CAPTCHA_RETRIES} попыток: {e}")

            # --- Step 2: Solve captcha ---
            try:
                captcha_text = solve_captcha_b64(img_b64, save_debug=True)
            except CaptchaSolveError as e:
                log.error(f"Ошибка решения капчи (попытка {attempt}/{MAX_CAPTCHA_RETRIES}): {e}")
                if attempt < MAX_CAPTCHA_RETRIES:
                    continue
                raise ApiError(f"Не удалось решить капчу после {MAX_CAPTCHA_RETRIES} попыток: {e}")

            # Validate: server requires at least 4 chars
            if len(captcha_text) < 4:
                log.warning(f"Капча слишком короткая: '{captcha_text}' ({len(captcha_text)} chars < 4). Запрашиваем новую (попытка {attempt}/{MAX_CAPTCHA_RETRIES})")
                if attempt < MAX_CAPTCHA_RETRIES:
                    continue
                raise ApiError(f"Капча не решена: ddddocr возвращает слишком короткие ответы")

            # --- Step 3: Register with captcha ---
            payload = {
                "timezoneId": timezone_id,
                "captcha": captcha_text,
                "captchaKey": captcha_key,
                "appLevel": app_level,
                "password": password_hash,
                "country": country,
                "lang": lang,
                "deviceId": device_id,
                "os": os_code,
                "device": device,
                "username": username,
                "deviceToken": device_token,
            }
            ts = int(time.time())
            sign = generate_sign(payload, ts, REGISTER_PATH)
            params = {"timestamp": str(ts), "sign": sign}
            log.info(f"Регистрация '{username}' с капчей='{captcha_text}' (попытка {attempt}/{MAX_CAPTCHA_RETRIES})")
            data = self._request("POST", REGISTER_PATH, params=params, json_body=payload, auth_token=None)
            last_data = data

            code = data.get("code", -1) if isinstance(data, dict) else -1
            msg = str(data.get("msg", "")) if isinstance(data, dict) else ""

            # --- Step 4: Check result ---
            if code == 0:
                log.info(f"Регистрация '{username}' успешна!")
                break

            # Check if captcha-related error -> retry
            is_captcha_error = (
                "captcha" in msg.lower()
                or "验证" in msg.lower()
                or code == 10000003
            )
            if is_captcha_error:
                log.warning(f"Ошибка капчи: code={code} msg={msg}. "
                            f"{'Запрашиваем новую...' if attempt < MAX_CAPTCHA_RETRIES else 'Попытки исчерпаны'}")
                if attempt < MAX_CAPTCHA_RETRIES:
                    continue
                # Return last failed data (caller handles error codes)
                return last_data

            # Non-captcha error — don't retry, return immediately
            log.warning(f"Регистрация отклонена (не капча): code={code} msg={msg}")
            return last_data

        data = last_data
        # Try to extract token/refresh/entry from successful response
        try:
            if isinstance(data, dict) and data.get("code") == 0:
                # token container can be in data.auth or at top-level
                auth = data.get("data", {}).get("auth", data.get("data", {}))
                tok = auth.get("accessToken") or data.get("accessToken") or data.get("token")
                if tok:
                    self.token = tok
                    self.refresh_token = auth.get("refreshToken") or self.refresh_token
                    self.access_token_expire = auth.get("accessTokenExpire") or self.access_token_expire
                    self.refresh_token_expire = auth.get("refreshTokenExpire") or self.refresh_token_expire
                # Best-effort: detect client version from response
                try:
                    self._maybe_update_client_version_from_response(data)
                except Exception:
                    pass
                # TCP entry
                entry = data.get("data", {}).get("entry", {})
                eps: list[tuple[str,int]] = []
                for k_host, k_port in (("gameBaseEntry","gameBasePort"),("gameBaseEntry2","gameBasePort2"),("gameBaseEntry3","gameBasePort3")):
                    try:
                        h = entry.get(k_host); p = entry.get(k_port)
                        if h:
                            eps.append((str(h), int(p or 5000)))
                    except Exception:
                        pass
                dedup: list[tuple[str,int]] = []
                for hp in eps:
                    if hp not in dedup:
                        dedup.append(hp)
                if dedup:
                    self.tcp_entries = dedup
                    self.tcp_host, self.tcp_port = dedup[0]
                    log.info(f"🧭 TCP entry from register: {self.tcp_host}:{self.tcp_port}")
        except Exception as e:
            log.debug(f"register(): post-parse failed: {e}")
        return data

    def logout(self, auth_token: Optional[str] = None, uid: Optional[int] = None, device_id: Optional[str] = None, app_level: int = 0) -> Dict[str, Any]:
        """Logout from X-Poker API with timestamp/sign and JSON body.
        
        Args:
            auth_token: Optional auth token (uses stored if not provided)
            uid: Optional user id for body
            device_id: Device ID for body (falls back to self.device_id)
            app_level: Application level"""
        token = auth_token or self.token
        if not token:
            raise ApiError("No auth token. Login first.")
        body = {
            "appLevel": app_level,
            "uid": uid or 0,
            "deviceId": device_id or self.device_id or ""
        }
        ts = int(time.time())
        sign = generate_sign(body, ts, LOGOUT_PATH)
        params = {"timestamp": str(ts), "sign": sign}
        return self._request("POST", LOGOUT_PATH, params=params, json_body=body, auth_token=token)

    def join_club(self, club_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Join a club via HTTP API (not used; TCP is required).
        
        Args:
            club_id: Club ID
            auth_token: Optional auth token
            
        Returns:
            Join response
            
        Raises:
            ApiError: If no token available
        """
        token = auth_token or self.token
        if not token:
            raise ApiError("No auth token. Login first.")
        payload = {"clubId": club_id}
        return self._request("POST", JOIN_CLUB_PATH, json_body=payload, auth_token=token)

    def search_club(self, query: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Search for clubs.
        
        Args:
            query: Search query
            auth_token: Optional auth token
            
        Returns:
            Search results
            
        Raises:
            ApiError: If no token available
        """
        token = auth_token or self.token
        if not token:
            raise ApiError("No auth token. Login first.")
        payload = {"q": query}
        return self._request("POST", SEARCH_CLUB_PATH, json_body=payload, auth_token=token)
    
    def get_uid_from_login_response(self, login_data: Dict[str, Any]) -> Optional[int]:
        """Extract UID from login response.
        
        Args:
            login_data: Login response data
            
        Returns:
            User ID or None
        """
        log.debug(f"Extracting UID from login response: {type(login_data)}")
        
        if isinstance(login_data, dict) and login_data.get("code") == 0:
            log.debug(f"Login response code: {login_data.get('code')}")
            
            if "data" in login_data:
                data_field = login_data["data"]
                log.debug(f"Data field type: {type(data_field)}")
                log.debug(f"Data field keys: {list(data_field.keys()) if isinstance(data_field, dict) else 'N/A'}")
                
                # Try to find uid in various locations
                if isinstance(data_field, dict):
                    # Check in user section
                    if "user" in data_field and isinstance(data_field["user"], dict):
                        uid = data_field["user"].get("uid") or data_field["user"].get("id")
                        if uid:
                            log.debug(f"Found UID in user section: {uid}")
                            return uid
                        log.debug(f"User section keys: {list(data_field['user'].keys())}")
                    
                    # Check in auth section
                    if "auth" in data_field and isinstance(data_field["auth"], dict):
                        uid = data_field["auth"].get("uid") or data_field["auth"].get("userId")
                        if uid:
                            log.debug(f"Found UID in auth section: {uid}")
                            return uid
                        log.debug(f"Auth section keys: {list(data_field['auth'].keys())}")
                    
                    # Try direct uid field
                    uid = data_field.get("uid") or data_field.get("userId") or data_field.get("id")
                    if uid:
                        log.debug(f"Found UID in direct field: {uid}")
                        return uid
                        
        log.debug("No UID found in login response")
        return None
    
    def join_club_tcp(
        self,
        club_id: int,
        uid: Optional[int] = None,
        auth_token: Optional[str] = None,
        message_text: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Join a club using TCP protocol with detailed logging (одноразовое соединение)."""
        token = auth_token or self.token
        if not token:
            return False, "No auth token. Login first."
        if uid is None:
            return False, "UID is required for TCP club join"
        log.info(f"{Icons.TARGET} Начинаем процесс TCP вступления в клуб {club_id} (uid={uid})")
        
        # Под капотом используем общий метод с многократной обработкой, но на один клуб
        ok_all, results = self.join_clubs_tcp([club_id], uid=uid, auth_token=token, message_text=message_text)
        # results: list of tuples (club_id, ok, msg)
        if results:
            _, ok, msg = results[0]
            return ok, msg
        return ok_all, "No result"

    def join_clubs_tcp(
        self,
        club_ids: list[int],
        uid: Optional[int] = None,
        auth_token: Optional[str] = None,
        keepalive: bool = False,
        progress_cb: Optional[callable] = None,
        result_cb: Optional[callable] = None,
        cancel_event: Optional[object] = None,
        message_text: Optional[str] = None,
    ) -> Tuple[bool, list[Tuple[int, bool, str]]]:
        """Join multiple clubs over a single TCP connection.
        
        - Создаёт одно TCP-соединение и выполняет TCP-логин (строгий bootstrap).
        - Обходит список club_ids, для каждого делает get_desc + apply на том же сокете.
        - Можно передать progress_cb(indexed_club_id, index, total) -> bool: если вернул False — прерываем цикл аккуратно.
        - Можно передать result_cb(cid, ok, msg, index, total) для потоковой отдачи результатов по мере выполнения.
        - Можно передать cancel_event: threading.Event, чтобы прервать текущую попытку максимально быстро.
        - По завершении закрывает соединение (если keepalive=False).
        
        Returns (any_success, [(club_id, ok, message), ...]).
        """
        token = auth_token or self.token
        if not token:
            return False, []
        if uid is None:
            return False, []
        if not club_ids:
            return False, []
        
        # Создаём один TCP клиент
        host = getattr(self, 'tcp_host', None)
        port = getattr(self, 'tcp_port', None)
        fallback_eps: list[tuple[str, int]] = []
        if host and port:
            log.info(f"🧭 Используем сервер из HTTP-логина: {host}:{port}")
            tcp_client = XClubTCPClient(host=host, port=port, timeout=4.5, proxy=self.proxy_url, fallback_endpoints=fallback_eps, disable_bootstrap=True, frida_strict=True, log_tx_hex=False, log_rx_hex=False)
        else:
            tcp_client = XClubTCPClient(timeout=4.5, proxy=self.proxy_url, fallback_endpoints=fallback_eps, disable_bootstrap=True, frida_strict=True, log_tx_hex=False, log_rx_hex=False)
        # Пробрасываем событие отмены внутрь TCP клиента (если есть)
        try:
            if cancel_event is not None and hasattr(tcp_client, 'set_cancel_event'):
                tcp_client.set_cancel_event(cancel_event)
        except Exception:
            pass
        # Жёсткая остановка: при установке cancel_event немедленно закрываем сокет,
        # чтобы мгновенно прервать любые блокирующие ожидания recv/handshake
        try:
            if cancel_event is not None:
                import threading as _th
                def _closer():
                    try:
                        cancel_event.wait()
                        tcp_client.close()
                    except Exception:
                        pass
                _th.Thread(target=_closer, daemon=True).start()
        except Exception:
            pass
        
        results: list[Tuple[int, bool, str]] = []
        try:
            # Подключение и TCP-логин
            log.info(f"{Icons.TCP} Открываем одно TCP соединение для {len(club_ids)} клубов...")
            try:
                tcp_client.connect()
            except socket.timeout as e:
                raise ApiError(f"tcp_connect: timed out ({e})")
            except Exception as e:
                raise ApiError(f"tcp_connect: {e}")
            log.info(format_tcp_step("TCP соединение установлено", True))
            log.info(f"{Icons.AUTH} TCP авторизация...")
            start_time = time.time()
            try:
                login_response = tcp_client.tcp_login(uid, token, version=getattr(self, 'client_version', XPOKER_CLIENT_VERSION))
            except socket.timeout as e:
                raise ApiError(f"tcp_login: timed out ({e})")
            except Exception as e:
                raise ApiError(f"tcp_login: {e}")
            login_time = time.time() - start_time
            if b"pk.UserLoginRSP" in login_response:
                log.info(format_tcp_step(f"TCP авторизация успешна ({login_time:.3f}с)", True, f"размер ответа: {len(login_response)} байт"))
                try:
                    setattr(tcp_client, "_no_prewarm", True)
                except Exception:
                    pass
            else:
                # Попытка refresh
                log.warning(format_tcp_step("TCP авторизация провалена", False, "UserLoginRSP не найден. Пробуем refresh"))
                if self.refresh_token:
                    ok, msg = self.refresh_access_token()
                    if ok and self.token:
                        tcp_client.close()
                        # Малый интервал перед повторным подключением для стабильности
                        time.sleep(0.5)
                        tcp_client.connect()
                        login_response = tcp_client.tcp_login(uid, self.token)
                if b"pk.UserLoginRSP" not in (login_response or b""):
                    tcp_client.close()
                    return False, [(cid, False, "❌ Ошибка TCP авторизации") for cid in club_ids]
            
            # Обходим клубы на одном соединении
            any_success = False
            total = len(club_ids)
            for idx, cid in enumerate(club_ids):
                # Проверка отмены перед началом следующего клуба
                try:
                    if cancel_event is not None and getattr(cancel_event, 'is_set', lambda: False)():
                        log.info("⏹️ Прерывание обработки клубов по cancel_event")
                        break
                except Exception:
                    pass
                # Колбэк прогресса/остановки
                if progress_cb is not None:
                    try:
                        if progress_cb(cid, idx, total) is False:
                            log.info("⏹️ Прерывание обработки клубов по сигналу progress_cb")
                            break
                    except Exception as e:
                        log.debug(f"progress_cb error ignored: {e}")
                log.info(f"{Icons.TARGET} Вступление в клуб {cid} на одном TCP-соединении...")
                try:
                    ok, msg = tcp_client.simple_club_join(uid, token, cid, message_text=message_text)
                except Exception as e:
                    ok, msg = False, f"Error: {e}"
                results.append((cid, ok, msg))
                any_success = any_success or ok
                if result_cb is not None:
                    try:
                        result_cb(cid, ok, msg, idx, total)
                    except Exception as e:
                        log.debug(f"result_cb error ignored: {e}")
            
            return any_success, results
        finally:
            if not keepalive:
                try:
                    tcp_client.close()
                except Exception:
                    pass

    def _maybe_update_client_version_from_response(self, data: Dict[str, Any]) -> None:
        """Scan response dict for a version-like value and update self.client_version and User-Agent.
        Non-fatal; updates only if a plausible version like '1.12.70' is found.
        """
        import re
        ver = None
        def _scan(obj: Any):
            nonlocal ver
            if ver is not None:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = str(k).lower()
                    if any(s in key for s in ("clientver", "clientversion", "version", "appversion")):
                        try:
                            sv = str(v)
                        except Exception:
                            sv = None
                        if sv:
                            m = re.search(r"\b(\d+\.\d+(?:\.\d+){0,2})\b", sv)
                            if m:
                                ver = m.group(1)
                                return
                    _scan(v)
            elif isinstance(obj, list):
                for it in obj:
                    _scan(it)
        _scan(data)
        if ver:
            try:
                if ver != self.client_version:
                    self.client_version = ver
                    # Update User-Agent to match
                    try:
                        ua = self.session.headers.get("User-Agent", "")
                        if ua.startswith("X-Poker/"):
                            platform_label = "Android" if getattr(self, 'mobile_profile', False) else "Windows"
                            new_ua = f"X-Poker/{ver} ({platform_label})"
                            self.session.headers["User-Agent"] = new_ua
                    except Exception:
                        pass
                    log.info(f"Detected server client version: {ver}")
            except Exception:
                pass

    def refresh_access_token(self, refresh_token: Optional[str] = None) -> Tuple[bool, str]:
        """Attempt to refresh the access token using refresh_token.
        Returns (ok, message)."""
        rt = refresh_token or self.refresh_token
        if not rt:
            return False, "No refresh token"
        body = {
            "refreshToken": rt,
            "deviceId": self.device_id or "",
        }
        ts = int(time.time())
        sign = generate_sign(body, ts, REFRESH_PATH)
        params = {"timestamp": str(ts), "sign": sign}
        try:
            data = self._request("POST", REFRESH_PATH, params=params, json_body=body, retry_on_401=False)
            if isinstance(data, dict) and data.get("code") == 0:
                auth = data.get("data", {}).get("auth", data.get("data", {}))
                new_token = auth.get("accessToken") or data.get("accessToken") or data.get("token")
                if new_token:
                    self.token = new_token
                    self.refresh_token = auth.get("refreshToken", self.refresh_token)
                    self.access_token_expire = auth.get("accessTokenExpire") or self.access_token_expire
                    self.refresh_token_expire = auth.get("refreshTokenExpire") or self.refresh_token_expire
                    log.info("🔄 Access token refreshed successfully")
                    return True, "ok"
            return False, "Unexpected refresh response"
        except Exception as e:
            return False, str(e)
