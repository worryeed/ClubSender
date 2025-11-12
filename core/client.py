"""TCP Client for X-Poker Club System."""

import socket
import time
import threading
import logging
import struct
import os
from typing import Optional, Callable, Any
from urllib.parse import urlparse, unquote
import base64

try:
    import socks  # PySocks
except Exception:  # pragma: no cover
    socks = None

from .protocol import (
    varint_encode, frame_send, frame_recv,
    patch_varint, patch_string
)
from .constants import (
    CLUB_SERVER_HOST, CLUB_SERVER_PORT, DEFAULT_TIMEOUT,
    TEMPLATES, TEMPLATE_VALUES, MSG_HEADERS,
    MSG_USER_LOGIN_RSP, MSG_APPLY_CLUB_RSP, MSG_GET_CLUB_DESC_RSP,
    DEFAULT_HEARTBEAT_INTERVAL, XPOKER_CLIENT_VERSION
)

log = logging.getLogger(__name__)


class DisconnectedError(Exception):
    """Raised when an operation requires an active TCP connection but none is available."""
    pass


class XClubTCPClient:
    """TCP client for X-Poker club operations.
    
    This client handles the low-level TCP protocol for communicating
    with the X-Poker club server, including login, club operations,
    and heartbeat management.
    """
    
    def __init__(
        self,
        host: str = CLUB_SERVER_HOST,
        port: int = CLUB_SERVER_PORT,
        timeout: float = DEFAULT_TIMEOUT,
        on_message: Optional[Callable[[bytes], None]] = None,
        heartbeat_type: str = "GetMoneyREQ",  # или "HBREQ"
        proxy: Optional[str] = None,
        fallback_endpoints: Optional[list[tuple[str, int]]] = None,
        disable_bootstrap: bool = False,
        frida_strict: bool = False,
        log_tx_hex: bool = False,
        log_rx_hex: bool = False,
        force_seq_one: Optional[bool] = None,
        strict_pause_ms: int = 50,
    ):
        """Initialize TCP client.
        
        Args:
            host: Server hostname or IP
            port: Server port
            timeout: Socket timeout in seconds
            on_message: Optional callback for received messages
            heartbeat_type: Type of heartbeat to use ("GetMoneyREQ" or "HBREQ")
            proxy: Proxy URL (http/https/socks5/socks5h), e.g. "http://user:pass@host:port"
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()
        self.on_message = on_message
        self._connected = False
        self.heartbeat_type = heartbeat_type
        self.heartbeat_failures = 0  # Счетчик пропущенных heartbeat'ов
        self.proxy_url = proxy
        self.sequence_counter = 1  # Счетчик последовательности пакетов (начинаем с 1)
        # Message pump state
        self._pump_thread: Optional[threading.Thread] = None
        self._pump_stop = threading.Event()
        self._pump_lock = threading.Lock()
        self._pump_ready = threading.Event()
        self._cv = threading.Condition()
        self._inbox_by_cmd: dict[str, list[bytes]] = {}
        self._auto_hb_enabled = True
        # Heartbeat pause control
        self._heartbeat_paused = threading.Event()
        # Lobby poller state
        self._lobby_poller_thread: Optional[threading.Thread] = None
        self._stop_lobby_poller = threading.Event()
        # Session state
        self._logged_in: bool = False
        # Flags for wire logging and strict mode (Frida)
        self._frida_strict: bool = bool(frida_strict)
        self.log_tx_hex: bool = bool(log_tx_hex)
        self.log_rx_hex: bool = bool(log_rx_hex)
        # Wire debug logging flag (enable via env XP_DEBUG_WIRE=1)
        _wire_env = os.getenv("XP_DEBUG_WIRE", "").strip().lower() in ("1", "true", "yes", "y")
        # Enable debug wire logging only if explicitly requested (env or flags)
        self.debug_wire: bool = _wire_env or self.log_tx_hex or self.log_rx_hex
        # Reconnect/fallback endpoints and state
        self._fallback_endpoints: list[tuple[str, int]] = list(fallback_endpoints or [])
        self._reconnect_lock = threading.RLock()
        # round-robin index for endpoint rotation across reconnects
        self._rr_index: int = 0
        # Stored auth context for autoreconnect
        self._uid: Optional[int] = None
        self._token: Optional[str] = None
        self._version: str = XPOKER_CLIENT_VERSION
        # Post-login bootstrap state
        self._bootstrap_done = threading.Event()
        self._disable_bootstrap = bool(disable_bootstrap)
        # Strict bootstrap pacing (40–60ms by default)
        self._strict_pause_ms = max(1, int(strict_pause_ms))
        # Force seq=1 on all outgoing frames (default True in frida_strict mode)
        self.force_seq_one: bool = (True if (force_seq_one is None and self._frida_strict) else bool(force_seq_one))
        # External cancellation support
        self._external_cancel: Optional[threading.Event] = None
        
    def _next_sequence(self) -> int:
        """Получить следующий номер последовательности."""
        if self.force_seq_one:
            return 1
        current = self.sequence_counter
        self.sequence_counter += 1
        # Обернуть при превышении 16-битного значения
        if self.sequence_counter > 0xFFFF:
            self.sequence_counter = 1
        return current
        
    def _normalize_proxy_url(self, proxy: str) -> str:
        if not proxy:
            return ""
        p = proxy.strip()
        if '://' not in p:
            try:
                from .proxy_utils import normalize_proxy_input as _norm
                autod = _norm(p)  # auto-detect http vs socks5h
                if autod:
                    log.info(f"Auto-detected proxy scheme: {autod.split('://',1)[0]}")
                    return autod
            except Exception as e:
                log.debug(f"Proxy autodetect failed, falling back to http://: {e}")
            # fallback: treat as http
            p = 'http://' + p
        return p

    def _parse_proxy(self, proxy: Optional[str]):
        if not proxy:
            return None
        norm = self._normalize_proxy_url(proxy)
        u = urlparse(norm)
        if not u.hostname or not u.port:
            raise OSError(f"Некорректный прокси URL: {proxy}")
        username = unquote(u.username) if u.username else None
        password = unquote(u.password) if u.password else None
        scheme = (u.scheme or 'http').lower()
        rdns = (scheme == 'socks5h')
        return {
            'scheme': scheme,
            'host': u.hostname,
            'port': u.port,
            'username': username,
            'password': password,
            'rdns': rdns,
        }

    def _connect_via_http_proxy(self, proxy_info) -> socket.socket:
        # Поддержка HTTP CONNECT. "https" будет трактован как обычный HTTP CONNECT (без TLS к прокси)
        phost = proxy_info['host']
        pport = proxy_info['port']
        log.info(f"Connecting via HTTP proxy {phost}:{pport} -> {self.host}:{self.port}")
        s = socket.create_connection((phost, pport), timeout=self.timeout)
        s.settimeout(self.timeout)
        # Формируем CONNECT
        connect_lines = [
            f"CONNECT {self.host}:{self.port} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Proxy-Connection: Keep-Alive",
        ]
        if proxy_info['username'] is not None:
            userpass = f"{proxy_info['username']}:{proxy_info['password'] or ''}".encode('utf-8')
            auth = base64.b64encode(userpass).decode('ascii')
            connect_lines.append(f"Proxy-Authorization: Basic {auth}")
        req = ("\r\n".join(connect_lines) + "\r\n\r\n").encode('ascii')
        s.sendall(req)
        # Читаем ответ до конца заголовков
        buff = b""
        while b"\r\n\r\n" not in buff and len(buff) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buff += chunk
        # Простейшая проверка статуса
        first_line = buff.split(b"\r\n", 1)[0] if buff else b""
        ok = first_line.startswith(b"HTTP/1.1 200") or first_line.startswith(b"HTTP/1.0 200")
        if not ok:
            try:
                msg = first_line.decode('latin1', errors='ignore')
            except Exception:
                msg = str(first_line)
            s.close()
            raise OSError(f"HTTP proxy CONNECT failed: {msg}")
        log.info("HTTP proxy CONNECT established")
        return s

    def _connect_via_socks(self, proxy_info) -> socket.socket:
        if socks is None:
            raise OSError("Для схем socks5/socks5h требуется пакет PySocks. Установите: pip install pysocks")
        log.info(f"Connecting via SOCKS proxy {proxy_info['host']}:{proxy_info['port']} (rdns={proxy_info['rdns']}) -> {self.host}:{self.port}")
        s = socks.socksocket()
        s.set_proxy(
            socks.SOCKS5,
            proxy_info['host'],
            proxy_info['port'],
            username=proxy_info['username'],
            password=proxy_info['password'],
            rdns=proxy_info['rdns'],
        )
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def connect(self) -> None:
        """Connect to the club server.
        
        Raises:
            socket.error: If connection fails
        """
        if self.proxy_url:
            pinfo = self._parse_proxy(self.proxy_url)
            scheme = pinfo['scheme']
            if scheme in ("socks5", "socks5h"):
                s = self._connect_via_socks(pinfo)
            elif scheme in ("http", "https"):
                if scheme == 'https':
                    log.warning("Схема https для прокси трактуется как HTTP CONNECT без TLS к прокси")
                s = self._connect_via_http_proxy(pinfo)
            else:
                raise OSError(f"Неподдерживаемая схема прокси для TCP: {scheme}")
        else:
            log.info(f"Connecting to {self.host}:{self.port}...")
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            s.settimeout(self.timeout)
        
        self.sock = s
        self._connected = True
        if self.proxy_url:
            log.info(f"Connected to {self.host}:{self.port} via proxy")
        else:
            log.info(f"Connected to {self.host}:{self.port}")
        
    def close(self) -> None:
        """Close connection and stop heartbeat."""
        # stop pump first
        try:
            self.stop_pump()
        except Exception:
            pass
        self._stop_heartbeat.set()
        self._connected = False
        
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
            self.heartbeat_thread = None
        # reset login flag
        self._logged_in = False
        # stop lobby poller
        try:
            self.stop_lobby_poller()
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
            log.info("Socket closed")
            
    @property
    def connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self.sock is not None
        
    def ensure_connected(self, *, allow_reconnect: bool = True, max_attempts: int = 3) -> bool:
        """Ensure there is an active TCP connection and a logged-in session.
        If disconnected and allow_reconnect is True, attempts to reconnect and re-login,
        rotating through fallback endpoints from HTTP login.
        Returns True if a usable connection is available, False otherwise.
        """
        if self.connected:
            return True
        if not allow_reconnect:
            return False
        # Try to recover connection
        with self._reconnect_lock:
            if self.connected:
                return True
            # Build endpoint list: current then fallbacks (deduped)
            endpoints: list[tuple[str, int]] = []
            try:
                if self.host and self.port:
                    endpoints.append((self.host, self.port))
            except Exception:
                pass
            for ep in self._fallback_endpoints:
                if ep not in endpoints:
                    endpoints.append(ep)
            if not endpoints:
                return False
            # Round-robin rotation start index
            n = len(endpoints)
            start = self._rr_index % n
            ordered: list[tuple[str, int]] = [endpoints[(start + i) % n] for i in range(n)]
            max_tries = min(max_attempts, n)
            for i in range(max_tries):
                h, p = ordered[i]
                try:
                    # switch target and connect
                    self.host, self.port = h, p
                    self.connect()
                    # must have credentials to complete session
                    if self._uid is None or not self._token:
                        log.debug("Reconnected socket, but no stored credentials for TCP login; leaving as-is")
                        self._rr_index = endpoints.index((h, p))
                        return self.connected
                    # perform TCP login (this will also start pump and handshake)
                    rsp = self.tcp_login(self._uid, self._token, version=self._version)
                    if MSG_USER_LOGIN_RSP.encode() in rsp:
                        # lock to this endpoint for now
                        self._rr_index = endpoints.index((h, p))
                        return True
                    else:
                        # advance rr index on failure
                        self._rr_index = (endpoints.index((h, p)) + 1) % n
                except Exception as e:
                    log.debug(f"Reconnection attempt to {h}:{p} failed: {e}")
                    try:
                        self.close()
                    except Exception:
                        pass
                    # advance rr index and try next
                    self._rr_index = (endpoints.index((h, p)) + 1) % n
                    continue
            return False
        
    def send_payload(self, payload: bytes) -> None:
        """Send raw payload.
        
        Args:
            payload: Data to send
            
        Raises:
            RuntimeError: If not connected
        """
        if not self.ensure_connected():
            raise RuntimeError("Not connected")
        self._safe_send_frame(payload)
        
    def _safe_send_frame(self, payload: bytes) -> None:
        """Safely send a framed payload (adds 4-byte length) over the socket, with reconnect if needed."""
        if not self.connected:
            if not self.ensure_connected():
                raise DisconnectedError("No TCP connection established")
        try:
            frame_send(self.sock, payload)  # type: ignore[arg-type]
        except Exception as e:
            log.debug(f"Frame send failed: {e}")
            # mark disconnected
            try:
                self._connected = False
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
            except Exception:
                pass
            raise
        
    def _safe_sendall(self, packet: bytes) -> None:
        """Safely send a complete packet (already framed) over the socket, with reconnect if needed."""
        if not self.connected:
            if not self.ensure_connected():
                raise DisconnectedError("No TCP connection established")
        try:
            self.sock.sendall(packet)  # type: ignore[union-attr]
        except Exception as e:
            log.debug(f"Send failed: {e}")
            try:
                self._connected = False
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
            except Exception:
                pass
            raise
        
    def recv_payload(self) -> bytes:
        """Receive response payload.
        
        Returns:
            Received payload
            
        Raises:
            RuntimeError: If not connected
        """
        if not self.sock:
            raise RuntimeError("Not connected")
        payload = frame_recv(self.sock)
        
        # Invoke callback if provided
        if self.on_message:
            try:
                self.on_message(payload)
            except Exception as e:
                log.error(f"Message callback error: {e}")
                
        return payload

    # --------------- Message pump ---------------
    def start_pump(self) -> None:
        with self._pump_lock:
            if self._pump_thread and self._pump_thread.is_alive():
                log.debug("Message pump already running; skip start")
                return
            self._pump_stop.clear()
            self._pump_ready.clear()
            t = threading.Thread(target=self._pump_loop, name="xclub-pump", daemon=True)
            self._pump_thread = t
            t.start()
        # wait until pump loop signals readiness (up to 0.5s)
        self._pump_ready.wait(timeout=0.5)
        log.info("Message pump started")

    def stop_pump(self) -> None:
        self._pump_stop.set()
        if self._pump_thread and self._pump_thread.is_alive():
            self._pump_thread.join(timeout=2)
        self._pump_thread = None
        log.info("Message pump stopped")

    def _store_cmd(self, cmd: str, payload: bytes) -> None:
        with self._cv:
            self._inbox_by_cmd.setdefault(cmd, []).append(payload)
            self._cv.notify_all()

    def _parse_cmd_from_payload(self, payload: bytes) -> Optional[str]:
        try:
            s = payload.decode('utf-8', errors='ignore')
            i = s.find('pk.')
            if i == -1:
                return None
            j = i
            # read until NUL or non-printable
            out = []
            while j < len(s):
                ch = s[j]
                if ch == '\x00':
                    break
                if ord(ch) < 0x20 or ord(ch) > 0x7e:
                    break
                out.append(ch)
                j += 1
            cmd = ''.join(out)
            if cmd.endswith('$'):
                cmd = cmd[:-1]
            return cmd if cmd else None
        except Exception:
            return None

    def _pump_loop(self) -> None:
        # signal that pump is ready to receive frames
        try:
            self._pump_ready.set()
        except Exception:
            pass
        while not self._pump_stop.is_set() and self.connected:
            try:
                payload = frame_recv(self.sock)
                if not payload:
                    continue
                cmd = self._parse_cmd_from_payload(payload)
                if self.debug_wire or self.log_rx_hex:
                    try:
                        log.info(f"RX: {cmd or '(unknown)'} len={len(payload)} hex={payload.hex()}")
                    except Exception:
                        pass
                if cmd:
                    self._store_cmd(cmd, payload)
                    # Раньше здесь автоматически отправляли HBREQ при получении HBRSP.
                    # По реальным логам HBREQ инициирует клиент с периодом ~3с, а сервер отвечает HBRSP.
                    # Автоответ HBREQ на HBRSP может вносить шум и сбивать ритм, отключаем.
            except socket.timeout:
                continue
            except Exception as e:
                if not self._pump_stop.is_set():
                    log.exception(f"Pump read error: {e}")
                    # Помечаем соединение как разорванное и закрываем сокет, не пытаясь останавливать помпу изнутри
                    try:
                        self._connected = False
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
                            log.info("Pump: socket set to None and client marked disconnected")
                    except Exception:
                        pass
                break

    def set_cancel_event(self, ev: Optional[threading.Event]) -> None:
        """Assign an external cancellation event used to abort waits early."""
        self._external_cancel = ev

    def wait_for_cmd(self, cmd: str, timeout: float) -> Optional[bytes]:
        end = time.time() + timeout
        with self._cv:
            while time.time() < end:
                # Early exit on external cancellation
                try:
                    if self._external_cancel is not None and self._external_cancel.is_set():
                        return None
                except Exception:
                    pass
                lst = self._inbox_by_cmd.get(cmd)
                if lst:
                    return lst.pop(0)
                remaining = end - time.time()
                if remaining <= 0:
                    break
                self._cv.wait(timeout=min(0.2, remaining))
        return None

    # --------------- Post-login bootstrap ---------------
    def _start_post_login_bootstrap(self) -> None:
        """Запустить фоновый bootstrap-поток после успешного TCP-логина.
        Выполняет безопасный набор служебных запросов, чтобы синхронизировать состояние,
        не блокируя основной поток выполнения.
        """
        # Сбросить флаг завершения перед стартом
        try:
            self._bootstrap_done.clear()
        except Exception:
            pass
        t = threading.Thread(target=self._post_login_bootstrap_worker, name="xclub-bootstrap", daemon=True)
        t.start()

    def _post_login_bootstrap_worker(self) -> None:
        # Небольшая пауза чтобы избежать "наваливания" сразу после HBREQ
        time.sleep(0.05)
        try:
            # Последовательно выполнить набор безопасных запросов
            self._prewarm_like_real()
        except Exception as e:
            log.debug(f"Bootstrap worker error: {e}")
        finally:
            try:
                self._bootstrap_done.set()
            except Exception:
                pass
            log.info("Post-login bootstrap completed")

    # Strict FRIDA bootstrap: reproduce official client post-login sequence
    def _start_frida_strict_bootstrap(self) -> None:
        try:
            self._bootstrap_done.clear()
        except Exception:
            pass
        t = threading.Thread(target=self._frida_strict_bootstrap_worker, name="xclub-frida-bootstrap", daemon=True)
        t.start()

    def _strict_pause(self) -> None:
        """Pause between strict steps (40–60 ms with small jitter)."""
        try:
            import random
            base = max(1, int(self._strict_pause_ms)) / 1000.0
            jitter = random.uniform(-0.01, 0.01)  # ±10ms jitter around the base
            time.sleep(max(0.04, min(0.06, base + jitter)))
        except Exception:
            time.sleep(0.05)

    def run_frida_strict_bootstrap(self) -> None:
        """Run the strict bootstrap synchronously in the current thread.
        Sends exactly one HBREQ, then the ordered sequence with 40–60 ms gaps.
        Sets _bootstrap_done when finished.
        """
        try:
            self._bootstrap_done.clear()
        except Exception:
            pass
        try:
            # Step 1: Single HBREQ (as in Frida)
            try:
                _ = self._send_heartbeat()
            except Exception:
                pass
            self._strict_pause()
            # Step 2: GetSelfDataREQ
            try:
                from .constants import MSG_TYPE_IDS as _IDS
                _ = self.send_cmd_and_wait("pk.GetSelfDataREQ", _IDS["GetSelfDataREQ"], b"", "pk.GetSelfDataRSP", timeout=2.0)
            except Exception as e:
                log.debug(f"FRIDA strict: GetSelfDataREQ failed: {e}")
            self._strict_pause()
            # Step 3: GetMoneyREQ variants (field 0x18 = 1,2,9,0x0a)
            try:
                self._send_get_money_variant(0x01)
                self._strict_pause()
                self._send_get_money_variant(0x02)
                self._strict_pause()
                self._send_get_money_variant(0x09)
                self._strict_pause()
                self._send_get_money_variant(0x0a)
            except Exception as e:
                log.debug(f"FRIDA strict: GetMoney variants failed: {e}")
            self._strict_pause()
            # Step 4: GetRiskManageDetailREQ
            try:
                from .constants import MSG_TYPE_IDS as _IDS
                _ = self.send_cmd_and_wait("pk.GetRiskManageDetailREQ", _IDS["GetRiskManageDetailREQ"], b"", "pk.GetRiskManageDetailRSP", timeout=2.0)
            except Exception as e:
                log.debug(f"FRIDA strict: GetRiskManageDetailREQ failed: {e}")
            self._strict_pause()
            # Step 5: GetUserCustomizeREQ
            try:
                from .constants import MSG_TYPE_IDS as _IDS
                _ = self.send_cmd_and_wait("pk.GetUserCustomizeREQ", _IDS["GetUserCustomizeREQ"], b"", "pk.GetUserCustomizeRSP", timeout=2.0)
            except Exception as e:
                log.debug(f"FRIDA strict: GetUserCustomizeREQ failed: {e}")
            self._strict_pause()
            # Step 6: GetSelfGamesInfoREQ
            try:
                from .constants import MSG_TYPE_IDS as _IDS
                _ = self.send_cmd_and_wait("pk.GetSelfGamesInfoREQ", _IDS["GetSelfGamesInfoREQ"], b"", "pk.GetSelfGamesInfoRSP", timeout=2.0)
            except Exception as e:
                log.debug(f"FRIDA strict: GetSelfGamesInfoREQ failed: {e}")
            self._strict_pause()
            # Step 7: GetAppearanceSystemDataREQ (param 08 03)
            try:
                from .constants import MSG_TYPE_IDS as _IDS
                _ = self.send_cmd_and_wait("pk.GetAppearanceSystemDataREQ", _IDS["GetAppearanceSystemDataREQ"], bytes([0x08, 0x03]), "pk.GetAppearanceSystemDataRSP", timeout=2.0)
            except Exception as e:
                log.debug(f"FRIDA strict: GetAppearanceSystemDataREQ failed: {e}")
        except Exception as e:
            log.debug(f"FRIDA strict bootstrap error: {e}")
        finally:
            try:
                self._bootstrap_done.set()
            except Exception:
                pass
            log.info("FRIDA strict bootstrap completed")

    def _frida_strict_bootstrap_worker(self) -> None:
        # Kept for compatibility if background mode is used elsewhere
        self.run_frida_strict_bootstrap()

    def _send_get_money_variant(self, value: int) -> None:
        from .constants import MSG_TYPE_IDS as _IDS
        from .protocol import build_packet_correct as _build
        seq = self._next_sequence()
        payload = bytes([0x18, value & 0xff])
        packet = _build("pk.GetMoneyREQ", _IDS["GetMoneyREQ"], payload, seq)
        if self.debug_wire or self.log_tx_hex:
            try:
                content_len = len(packet) - 4 if len(packet) >= 4 else len(packet)
                log.info(f"TX: pk.GetMoneyREQ type=0x{_IDS['GetMoneyREQ']:04x} seq={seq} len={content_len} hex={packet.hex()}")
            except Exception:
                pass
        self._safe_sendall(packet)

    def send_cmd_and_wait(self, msg_type: str, msg_type_id: int, protobuf_payload: bytes, expected_cmd: str, timeout: float) -> Optional[bytes]:
        from .protocol import build_packet_correct
        seq = self._next_sequence()
        packet = build_packet_correct(msg_type, msg_type_id, protobuf_payload, seq)
        # Ensure pump is running before waiting for a response
        if not (self._pump_thread and self._pump_thread.is_alive()):
            self.start_pump()
        # Log full TX packet if debug enabled (includes 4-byte length)
        if self.debug_wire or self.log_tx_hex:
            try:
                content_len = len(packet) - 4 if len(packet) >= 4 else len(packet)
                log.info(f"TX: {msg_type} type=0x{msg_type_id:04x} seq={seq} len={content_len} hex={packet.hex()}")
            except Exception:
                pass
        # send full packet atomically
        self._safe_sendall(packet)
        log.debug(f"Send+Wait: {msg_type} (type_id=0x{msg_type_id:04x}, seq={seq}) -> expect {expected_cmd} within {timeout}s")
        return self.wait_for_cmd(expected_cmd, timeout)
        
    def tcp_login(self, uid: int, token: str, version: str = XPOKER_CLIENT_VERSION) -> bytes:
        """Send TCP login request using the correct builder framing.
        
        Args:
            uid: User ID (integer)
            token: Access token from HTTP login (string)
            version: Client version string
            
        Returns:
            Response payload
        """
        log.info(f"TCP login for uid={uid}")
        # store auth context for autoreconnect
        try:
            self._uid = int(uid)
        except Exception:
            self._uid = None
        self._token = token
        self._version = version
        
        # Build protobuf payload: field3=token (string), field2=uid (varint), field1=version (string)
        from .protocol import varint_encode as _venc
        token_bytes = token.encode('utf-8') if isinstance(token, str) else token
        version_bytes = version.encode('utf-8') if isinstance(version, str) else version
        pb = bytearray()
        # field 3: token (tag=0x1a)
        pb += bytes([0x1a]) + _venc(len(token_bytes)) + token_bytes
        # field 2: uid (tag=0x10)
        pb += bytes([0x10]) + _venc(uid)
        # field 1: version (tag=0x0a)
        pb += bytes([0x0a]) + _venc(len(version_bytes)) + version_bytes
        
        # Build full packet with correct 2-byte msg_type and trailing sequence
        from .constants import MSG_TYPE_IDS as _IDS
        from .protocol import build_packet_correct as _build
        seq = self._next_sequence()
        packet = _build("pk.UserLoginREQ", _IDS["UserLoginREQ"], bytes(pb), seq)
        
        # Log full TX
        if self.debug_wire or self.log_tx_hex:
            try:
                content_len = len(packet) - 4 if len(packet) >= 4 else len(packet)
                log.info(f"TX: pk.UserLoginREQ type=0x{_IDS['UserLoginREQ']:04x} seq={seq} len={content_len} hex={packet.hex()}")
            except Exception:
                pass
        
        # Send and receive synchronously (do not start pump yet)
        self._safe_sendall(packet)
        response = self.recv_payload()
        
        # Check if login successful
        if MSG_USER_LOGIN_RSP.encode() in response:
            log.info("TCP login successful")
            # Инициализируем счётчик после успешного логина
            self.sequence_counter = 1
            self._logged_in = True
            log.debug("💫 Счетчик последовательности сброшен до 1 после логина")
            # Поднимаем помпу до любых запросов
            try:
                self.start_pump()
            except Exception as e:
                log.debug(f"Failed to start message pump after login: {e}")
            
            # В строгом режиме: выполняем bootstrap СИНХРОННО и не запускаем фоновый heartbeat до его завершения
            try:
                if getattr(self, "_frida_strict", False):
                    log.info("🔒 Running strict FRIDA bootstrap synchronously (no heartbeat thread during bootstrap)")
                    self.run_frida_strict_bootstrap()
                elif not getattr(self, "_disable_bootstrap", False):
                    # Нестрогий режим: прежний фоновый bootstrap
                    self._start_post_login_bootstrap()
            except Exception as e:
                log.debug(f"Post-login bootstrap error: {e}")
            
            # После bootstrap запускаем фоновый heartbeat-поток
            try:
                self.start_heartbeat(DEFAULT_HEARTBEAT_INTERVAL)
            except Exception as e:
                log.debug(f"Failed to start heartbeat after bootstrap: {e}")
        else:
            log.warning("TCP login response doesn't contain UserLoginRSP")
            
        return response
        
    def get_club_desc(self, club_id: int) -> bytes:
        """Запрос описания клуба через pump (без прямых recv()).
        По умолчанию сначала отправляет пакет через корректный builder.
        При отсутствии ответа — пробует строгий шаблон (как в Frida) и, в крайнем случае, override msg_type_id=0x000f.
        """
        from .constants import MSG_TYPE_IDS
        from .protocol import varint_encode
        log.info(f"Getting club description for club_id={club_id}")
        # Жёстко ждём завершения bootstrap перед клубными операциями (до 2с)
        try:
            if getattr(self, "_frida_strict", False):
                self._bootstrap_done.wait(timeout=2.0)
        except Exception:
            pass
        # 1) Нормальный builder (msg_type_id=0x0011)
        payload = bytes([0x08]) + varint_encode(club_id) + bytes([0x10, 0x00])
        
        # Проверка 1-в-1 пакета для club_id=123456 по логам (строка 77 в 'логи из скрипта.txt')
        try:
            if int(club_id) == 123456:
                # Ожидаемый пакет (из логов), но с патчем последовательности на наш текущий seq
                expected_hex = (
                    "00000021"  # length (33)
                    "0011"      # msg_type_id
                    "00000000"  # padding
                    "706b2e476574436c756244657363524551"  # "pk.GetClubDescREQ"
                    "0001"      # separator
                    "08c0c407"  # field1=club_id=123456 (varint c0 c4 07)
                    "10"        # field2 tag
                    "00"        # value 0
                )
                # Строка для журнала, откуда взят пакет
                log_line = 77
                # Сформируем наш пакет с тем seq, который будет использован send_cmd_and_wait
                seq_expected = self.sequence_counter
                from .protocol import build_packet_correct as _build
                our_packet = _build("pk.GetClubDescREQ", MSG_TYPE_IDS["GetClubDescREQ"], payload, seq_expected)
                expected_bytes = bytes.fromhex(expected_hex) + seq_expected.to_bytes(2, 'big')
                if our_packet != expected_bytes:
                    # Найти первую позицию несовпадения
                    idx = next((i for i, (a,b) in enumerate(zip(our_packet, expected_bytes)) if a != b), -1)
                    log.warning(
                        "[VERIFY 123456] Наш пакет не совпал с логом (строка %s). first_diff=%s our=%s expected=%s",
                        log_line, idx, our_packet.hex(), expected_bytes.hex()
                    )
                else:
                    log.info("[VERIFY 123456] Пакет совпал с логом (строка %s)", log_line)
        except Exception as ve:
            log.debug(f"Packet verify skipped/failed: {ve}")
        
        rsp = self.send_cmd_and_wait("pk.GetClubDescREQ", MSG_TYPE_IDS["GetClubDescREQ"], payload, "pk.GetClubDescRSP", timeout=6.0)
        if rsp:
            return rsp
        # 2) Шаблон из дампов (тот же тип сообщения)
        try:
            tpl_rsp = self.get_club_desc_via_template(club_id)
            if tpl_rsp:
                return tpl_rsp
        except Exception as e:
            log.debug(f"Template-based GetClubDesc failed: {e}")
        # 3) Редкий случай: сервер принимает 0x000f для GetClubDesc — пробуем override
        try:
            tpl_rsp2 = self.get_club_desc_via_template(club_id, msg_type_id_override=0x000f)
            if tpl_rsp2:
                return tpl_rsp2
        except Exception as e:
            log.debug(f"Override(0x000f) GetClubDesc failed: {e}")
        return b""

    def get_club_desc_via_template(self, club_id: int, msg_type_id_override: Optional[int] = None) -> bytes:
        """Отправить GetClubDescREQ строго по шаблонному payload из дампов, с патчем club_id и корректным seq.
        Можно принудительно переопределить первые 2 байта (msg_type_id), чтобы проверить 0x0011 vs 0x000f.
        """
        from .constants import TEMPLATES, TEMPLATE_VALUES
        from .protocol import varint_encode
        # Жёстко ждём завершения bootstrap перед клубными операциями (до 2с)
        try:
            if getattr(self, "_frida_strict", False):
                self._bootstrap_done.wait(timeout=2.0)
        except Exception:
            pass
        tpl = TEMPLATES["GetClubDescREQ"]
        # Патчим club_id «в связке» с тэгом поля 0x08 (field 1 varint), чтобы не задеть случайные 0x7b
        old_v = varint_encode(TEMPLATE_VALUES["club_id"])  # varint(123)
        new_v = varint_encode(club_id)
        pattern = bytes([0x08]) + old_v
        repl = bytes([0x08]) + new_v
        if pattern not in tpl:
            raise ValueError("GetClubDescREQ template does not contain expected field1=club_id pattern")
        patched = tpl.replace(pattern, repl, 1)
        # Переопределяем msg_type_id при необходимости (первые 2 байта)
        if msg_type_id_override is not None:
            if not (0 <= msg_type_id_override <= 0xFFFF):
                raise ValueError("msg_type_id_override must be 0..65535")
            patched = msg_type_id_override.to_bytes(2, 'big') + patched[2:]
        # Проставляем актуальный sequence (2 байта BE в самом конце)
        seq = self._next_sequence()
        if len(patched) < 2:
            raise ValueError("Template payload too short to contain sequence")
        patched = patched[:-2] + seq.to_bytes(2, 'big')
        # Логи (INFO) для сравнения с эталоном
        try:
            head_hex = patched[:48].hex()
            tail_hex = patched[-8:].hex()
            used_mtype = int.from_bytes(patched[:2], 'big')
            log.info(f"GetClubDescREQ(template): len={len(patched)} mtype=0x{used_mtype:04x} seq={seq} head={head_hex} tail={tail_hex}")
        except Exception:
            pass
        # Не ставим паузу heartbeat, чтобы соединение не рвалось при длительном ожидании
        try:
            # Log full framed TX if debug enabled
            if self.debug_wire:
                try:
                    from .protocol import frame_pack as _frame_pack
                    framed = _frame_pack(patched)
                    content_len = len(framed) - 4
                    cmd_name = self._parse_cmd_from_payload(patched) or "(unknown)"
                    log.info(f"TX: {cmd_name} (template) seq={seq} len={content_len} hex={framed.hex()}")
                except Exception:
                    pass
            self.send_payload(patched)
            # Ждём ответ через pump (увеличенный таймаут для надёжности)
            rsp = self.wait_for_cmd("pk.GetClubDescRSP", timeout=6.0)
            return rsp or b""
        except Exception:
            return b""

    def apply_club_via_template(self, club_id: int, uid: int) -> bytes:
        """Отправить ApplyClubREQ строго по шаблонному payload из дампов, с патчем club_id, username и корректным seq.
        Использует тот же формат, что и реальный клиент (по Frida).
        """
        from .constants import TEMPLATES, TEMPLATE_VALUES
        from .protocol import varint_encode
        # Жёстко ждём завершения bootstrap перед клубными операциями (до 2с)
        try:
            if getattr(self, "_frida_strict", False):
                self._bootstrap_done.wait(timeout=2.0)
        except Exception:
            pass
        tpl = TEMPLATES["ApplyClubREQ"]
        # 1) Патч club_id: поле 2 (tag=0x10, wire=varint)
        old_club_v = varint_encode(TEMPLATE_VALUES["club_id"])  # varint(123)
        new_club_v = varint_encode(club_id)
        pattern2 = bytes([0x10]) + old_club_v
        repl2 = bytes([0x10]) + new_club_v
        if pattern2 not in tpl:
            raise ValueError("ApplyClubREQ template does not contain expected field2=club_id pattern")
        patched = tpl.replace(pattern2, repl2, 1)
        # 2) Патч username (field 1 length-delimited). Заменяем строку с автоматической корректировкой длины
        new_uname = f"Я XP{uid}".encode('utf-8')
        from .protocol import patch_string
        patched2 = patch_string(patched, TEMPLATE_VALUES["username"], new_uname)
        if patched2 == patched:
            # Если не нашли длину+строку, пробуем тупую замену при равной длине (маловероятно)
            if len(TEMPLATE_VALUES["username"]) == len(new_uname):
                patched2 = patched.replace(TEMPLATE_VALUES["username"], new_uname, 1)
        patched = patched2
        # 3) Проставляем актуальный sequence (2 байта BE в самом конце)
        seq = self._next_sequence()
        if len(patched) < 2:
            raise ValueError("ApplyClubREQ template too short to contain sequence")
        patched = patched[:-2] + seq.to_bytes(2, 'big')
        # Логи (INFO) для сравнения с эталоном
        try:
            head_hex = patched[:48].hex()
            tail_hex = patched[-8:].hex()
            used_mtype = int.from_bytes(patched[:2], 'big')
            log.info(f"ApplyClubREQ(template): len={len(patched)} mtype=0x{used_mtype:04x} seq={seq} head={head_hex} tail={tail_hex}")
        except Exception:
            pass
        # Не ставим паузу heartbeat; ждём ответ с меньшим таймаутом
        try:
            # Log full framed TX if debug enabled
            if self.debug_wire:
                try:
                    from .protocol import frame_pack as _frame_pack
                    framed = _frame_pack(patched)
                    content_len = len(framed) - 4
                    cmd_name = self._parse_cmd_from_payload(patched) or "(unknown)"
                    log.info(f"TX: {cmd_name} (template) seq={seq} len={content_len} hex={framed.hex()}")
                except Exception:
                    pass
            self.send_payload(patched)
            rsp = self.wait_for_cmd("pk.ApplyClubRSP", timeout=6.0)
            return rsp or b""
        except Exception:
            return b""
    
    def debug_club_join_sequence(self, uid: int, token: str, club_id: int, version: str = XPOKER_CLIENT_VERSION) -> dict:
        """Debug method to follow the exact TCP sequence from Frida logs.
        
        Based on the captured sequence:
        1. UserLoginREQ -> UserLoginRSP
        2. HBREQ -> HBRSP (heartbeat)
        3. Multiple GetSelfData/GetMoney requests (simulating full client)
        4. GetClubDescListREQ -> GetClubDescListRSP (get club list)
        5. GetWaitingListDetailREQ (optional)
        6. HBREQ -> HBRSP (heartbeat before club operation)
        7. GetClubDescREQ -> GetClubDescRSP (specific club info)
        8. HBREQ -> HBRSP (heartbeat after club desc)
        9. ApplyClubREQ -> ApplyClubRSP (actual join request)
        10. HBREQ -> HBRSP (final heartbeat)
        
        Args:
            uid: User ID
            token: Access token
            club_id: Club ID to join
            version: Client version
            
        Returns:
            Dict with step results and final status
        """
        log.info(f"🚀 DEBUG: Starting full club join sequence for club_id={club_id}")
        results = {
            "steps": [],
            "success": False,
            "final_message": "",
            "club_info": {},
            "apply_status": None
        }
        
        def add_step(name, success, message="", data=None):
            results["steps"].append({
                "name": name,
                "success": success,
                "message": message,
                "data": data or {}
            })
            log.info(f"Step: {name} - {'✅' if success else '❌'} {message}")
        
        try:
            # Step 1: TCP Login (skip if already logged in)
            if not self._logged_in:
                add_step("TCP Login", True, "Attempting login...")
                login_response = self.tcp_login(uid, token, version)
                login_success = MSG_USER_LOGIN_RSP.encode() in login_response
                add_step("TCP Login", login_success, f"Login {'successful' if login_success else 'failed'}")
                if not login_success:
                    results["final_message"] = "TCP login failed"
                    return results
            else:
                add_step("TCP Login", True, "Already logged in; skipping")
            
            # Step 2: Initial heartbeat (optional pacing)
            time.sleep(0.05)
            add_step("Initial Heartbeat", True, "Sending HBREQ...")
            try:
                _ = self._send_heartbeat()
            except Exception:
                pass
            hb_success = True
            add_step("Initial Heartbeat", hb_success, f"Heartbeat {'successful' if hb_success else 'failed'}")
            
            # Step 3: GetSelfDataREQ — SKIPPED to avoid server disconnects on empty payloads
            add_step("Get Self Data", True, "skipped")
            
            # Step 4: GetClubDescListREQ — SKIPPED (we go directly to club flow)
            add_step("Get Club List", True, "skipped")
            
            # Step 5: Heartbeat before club operations
            time.sleep(0.3)
            add_step("Pre-Club Heartbeat", True, "Sending HBREQ...")
            hb2_response = self._send_heartbeat()
            hb2_success = bool(hb2_response)
            add_step("Pre-Club Heartbeat", hb2_success, f"Heartbeat {'successful' if hb2_success else 'failed'}")
            
            # Step 6: GetClubDescREQ (specific club info)
            time.sleep(0.1)
            add_step("Get Club Info", True, f"Sending GetClubDescREQ for club_id={club_id}...")
            club_desc_response = self.get_club_desc(club_id)
            club_desc_success = MSG_GET_CLUB_DESC_RSP.encode() in club_desc_response
            add_step("Get Club Info", club_desc_success, f"Club info {'received' if club_desc_success else 'failed'}")
            
            if club_desc_success:
                # Try to parse club name
                try:
                    from core.protobuf_decoder import ProtobufDecoder
                    decoded_club = ProtobufDecoder.decode_club_desc_response(club_desc_response)
                    if decoded_club and 'club_info' in decoded_club:
                        club_name = decoded_club['club_info'].get('club_name', 'Unknown')
                        results["club_info"] = {
                            "name": club_name,
                            "exists": decoded_club['club_info'].get('exists', False)
                        }
                        add_step("Parse Club Info", True, f"Club name: {club_name}")
                except Exception as e:
                    add_step("Parse Club Info", False, f"Failed to parse: {e}")
            
            # Step 7: Post-club-desc heartbeat (like in real logs)
            time.sleep(0.2)
            add_step("Post-Desc Heartbeat", True, "Sending HBREQ...")
            hb3_response = self._send_heartbeat()
            hb3_success = bool(hb3_response)
            add_step("Post-Desc Heartbeat", hb3_success, f"Heartbeat {'successful' if hb3_success else 'failed'}")
            
            # Step 8: ApplyClubREQ (actual join request)
            time.sleep(0.3)  # Delay before applying (like in real logs)
            add_step("Apply to Club", True, f"Sending ApplyClubREQ for club_id={club_id}...")
            apply_response = self.apply_club(club_id, uid)
            apply_success = MSG_APPLY_CLUB_RSP.encode() in apply_response
            add_step("Apply to Club", apply_success, f"Apply response {'received' if apply_success else 'failed'}")
            
            if apply_success:
                # Try to parse apply response
                try:
                    from core.protobuf_decoder import ProtobufDecoder
                    decoded_apply = ProtobufDecoder.decode_apply_club_response(apply_response)
                    if decoded_apply:
                        status = decoded_apply.get('status', -1)
                        results["apply_status"] = status
                        reason_text = (decoded_apply.get('reason_text') or '').strip()
                        
                        from core.messages import decode_club_apply_status
                        status_info = decode_club_apply_status(status)
                        add_step("Parse Apply Result", True, f"Status: {status} - {status_info['message']}")
                        
                        if status == 0:
                            results["success"] = True
                            results["final_message"] = "Successfully joined club!"
                        elif status == 2:
                            results["success"] = True
                            results["final_message"] = "Already member of club"
                        else:
                            # В приоритете текстовая причина из ответа, если есть
                            fail_reason = reason_text or status_info['message']
                            results["final_message"] = f"Join failed: {fail_reason}"
                    else:
                        add_step("Parse Apply Result", False, "Failed to decode response")
                        results["final_message"] = "Failed to parse apply response"
                except Exception as e:
                    add_step("Parse Apply Result", False, f"Parse error: {e}")
                    results["final_message"] = f"Parse error: {e}"
            
            # Step 9: Final heartbeat
            time.sleep(0.2)
            add_step("Final Heartbeat", True, "Sending HBREQ...")
            hb4_response = self._send_heartbeat()
            hb4_success = bool(hb4_response)
            add_step("Final Heartbeat", hb4_success, f"Heartbeat {'successful' if hb4_success else 'failed'}")
            
            if not results["final_message"]:
                results["final_message"] = "Sequence completed but status unclear"
                
        except Exception as e:
            add_step("ERROR", False, f"Sequence failed: {e}")
            results["final_message"] = f"Error: {e}"
            
        log.info(f"🏁 DEBUG: Sequence completed. Success: {results['success']}. Message: {results['final_message']}")
        return results
    
    def _send_heartbeat(self) -> bytes:
        """Отправить правильный heartbeat (pk.HBREQ) и вернуть один ответ (если есть)."""
        try:
            from .protocol import build_packet_correct
            from .constants import MSG_TYPE_IDS
            seq = self._next_sequence()
            hb_packet = build_packet_correct("pk.HBREQ", MSG_TYPE_IDS["HBREQ"], b"", seq)
            if self.debug_wire or self.log_tx_hex:
                try:
                    content_len = len(hb_packet) - 4 if len(hb_packet) >= 4 else len(hb_packet)
                    log.info(f"TX: pk.HBREQ type=0x{MSG_TYPE_IDS['HBREQ']:04x} seq={seq} len={content_len} hex={hb_packet.hex()}")
                except Exception:
                    pass
            # ensure full packet is sent
            self._safe_sendall(hb_packet)
            log.debug(f"Sent HBREQ (seq={seq})")
            # Ответ прочитает pump; здесь попробуем один кадр, но это опционально
            return b""
        except Exception as e:
            log.debug(f"Heartbeat error: {e}")
            return b""

    def _send_heartbeat_send_only(self) -> None:
        """Отправить только HBREQ без чтения ответа (для фонового heartbeat)."""
        try:
            from .protocol import build_packet_correct
            from .constants import MSG_TYPE_IDS
            seq = self._next_sequence()
            hb_packet = build_packet_correct("pk.HBREQ", MSG_TYPE_IDS["HBREQ"], b"", seq)
            if self.debug_wire or self.log_tx_hex:
                try:
                    content_len = len(hb_packet) - 4 if len(hb_packet) >= 4 else len(hb_packet)
                    log.info(f"TX: pk.HBREQ type=0x{MSG_TYPE_IDS['HBREQ']:04x} seq={seq} len={content_len} hex={hb_packet.hex()}")
                except Exception:
                    pass
            # ensure full packet is sent
            self._safe_sendall(hb_packet)
            log.debug(f"HB thread: HBREQ sent (seq={seq})")
        except Exception as e:
            log.debug(f"HB thread: send failed: {e}")
    
    def pause_heartbeat(self, pause: bool) -> None:
        """Поставить/снять паузу отправки HBREQ в heartbeat-потоке."""
        if pause:
            self._heartbeat_paused.set()
            log.debug("Heartbeat paused")
        else:
            self._heartbeat_paused.clear()
            log.debug("Heartbeat resumed")
    
    def _send_get_self_data(self) -> bytes:
        """Отправить GetSelfDataREQ и дождаться RSP через pump."""
        from .constants import MSG_TYPE_IDS
        return self.send_cmd_and_wait("pk.GetSelfDataREQ", MSG_TYPE_IDS["GetSelfDataREQ"], b"", "pk.GetSelfDataRSP", timeout=2.0) or b""
    
    def _send_get_club_list(self) -> bytes:
        """Отправить GetClubDescListREQ и дождаться RSP через pump."""
        from .constants import MSG_TYPE_IDS
        return self.send_cmd_and_wait("pk.GetClubDescListREQ", MSG_TYPE_IDS["GetClubDescListREQ"], b"", "pk.GetClubDescListRSP", timeout=3.0) or b""
        
    def search_club(self, search_id: int) -> bytes:
        """Search for a club by ID.
        
        Args:
            search_id: User-visible club ID to search for
            
        Returns:
            Response payload with search results
        """
        log.info(f"Searching for club with ID={search_id}")
        
        
        # Build packet with application header
        app_header = MSG_HEADERS.get("SearchClubREQ", bytes.fromhex("00 12 00 00 00 00"))
        msg_type = "pk.SearchClubREQ"
        separator = bytes([0x00, 0x01])
        
        # Protobuf payload: field 1 (search_id)
        search_id_bytes = varint_encode(search_id)
        payload = bytes([0x08]) + search_id_bytes  # Field 1
        payload += bytes([0x00, 0x01])  # Terminator
        
        # Complete message with app header
        full_msg = app_header + msg_type.encode() + separator + payload
        
        log.debug(f"Sending SearchClub: {full_msg.hex()}")
        self.send_payload(full_msg)
        
        try:
            response = self.recv_payload()
            if b"SearchClubRSP" in response or b"ClubInfo" in response:
                log.info("Got search response")
            return response
        except Exception as e:
            log.error(f"Search failed: {e}")
            return b""
            
    def _prepare_apply_message(self, uid: int, message_text: Optional[str]) -> bytes:
        """Подготовить текст сообщения для заявки.
        Ограничение: максимум 40 символов (Unicode); кодировка UTF‑8.
        """
        text = (message_text if (message_text is not None and message_text.strip() != "") else f"Я XP{uid}")
        # Ограничим по символам (code points)
        if len(text) > 40:
            text = text[:40]
        return text.encode('utf-8')

    def apply_club(self, club_id: int, uid: int, message_text: Optional[str] = None) -> bytes:
        """Отправить ApplyClubREQ и дождаться ApplyClubRSP через pump.
        По умолчанию используется строгий шаблон (как в нативном клиенте). Если не удалось — fallback на builder.
        На время отправки ставим паузу heartbeat (тишина вокруг критического запроса).
        """
        from .constants import MSG_TYPE_IDS
        from .protocol import varint_encode
        log.info(f"Applying to club_id={club_id} for uid={uid}")
        # Жёстко ждём завершения bootstrap перед клубными операциями (до 2с)
        try:
            if getattr(self, "_frida_strict", False):
                self._bootstrap_done.wait(timeout=2.0)
        except Exception:
            pass
        # 1) Попытка по шаблону
        try:
            rsp = self.apply_club_via_template(club_id, uid)
            if rsp:
                return rsp
        except Exception as e:
            log.debug(f"Apply via template failed, will try builder: {e}")
        # 2) Fallback builder: field2: club_id (varint), field1: message (len-delimited), field3: 0
        uname = self._prepare_apply_message(uid, message_text)
        payload = bytes([0x10]) + varint_encode(club_id) + bytes([0x0a]) + varint_encode(len(uname)) + uname + bytes([0x18, 0x00])
        try:
            rsp2 = self.send_cmd_and_wait("pk.ApplyClubREQ", MSG_TYPE_IDS["ApplyClubREQ"], payload, "pk.ApplyClubRSP", timeout=6.0)
            return rsp2 or b""
        except Exception:
            return b""
        
    def send_heartbeat(self) -> None:
        """Send a heartbeat packet to keep connection alive."""
        try:
            hb_payload = TEMPLATES["HeartbeatREQ"]
            self.send_payload(hb_payload)
            log.debug("Heartbeat sent")
        except Exception as e:
            log.error(f"Heartbeat failed: {e}")
            raise
            
    def start_heartbeat(self, interval: float = DEFAULT_HEARTBEAT_INTERVAL) -> None:
        """Start heartbeat thread to keep connection alive.
        
        Args:
            interval: Heartbeat interval in seconds
        """
        # avoid spawning duplicate heartbeat threads
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            log.info("Heartbeat already running; skipping")
            return
        def heartbeat_worker():
            import random
            log.info(f"Starting heartbeat (HBREQ) with interval={interval}s ± 50ms jitter")
            while not self._stop_heartbeat.is_set():
                # Добавляем джиттер ± 50ms согласно инструкции
                jitter = random.uniform(-0.05, 0.05)  # ± 50ms
                actual_interval = max(0.2, interval + jitter)
                
                if self._stop_heartbeat.wait(actual_interval):
                    break  # Остановились
                try:
                    if self.sock and not self._heartbeat_paused.is_set():
                        self._send_heartbeat_send_only()
                    else:
                        log.debug("HB thread: paused, skip send")
                except Exception as e:
                    log.debug(f"Heartbeat thread error: {e}")
                    # не выходим, продолжаем попытки
                    continue
            log.info("Heartbeat stopped")
            
        self._stop_heartbeat.clear()
        self.heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
        self.heartbeat_thread.start()
        
    def stop_heartbeat(self) -> None:
        """Stop the heartbeat thread."""
        self._stop_heartbeat.set()
        
    def start_lobby_poller(self, interval: float = 5.0) -> None:
        """Запустить фоновый опрос списка клубов, как делает реальный клиент.
        Шлёт pk.GetClubDescListREQ каждые ~4–6с с джиттером и ждёт RSP через pump.
        """
        if self._lobby_poller_thread and self._lobby_poller_thread.is_alive():
            return
        self._stop_lobby_poller.clear()
        
        def poller():
            import random
            from .constants import MSG_TYPE_IDS as _IDS
            while not self._stop_lobby_poller.is_set() and self.connected:
                try:
                    # джиттер ±0.2с вокруг заданного интервала
                    jitter = random.uniform(-0.2, 0.2)
                    next_wait = max(1.0, interval + jitter)
                    # запрос списка клубов
                    try:
                        _ = self.send_cmd_and_wait("pk.GetClubDescListREQ", _IDS["GetClubDescListREQ"], b"", "pk.GetClubDescListRSP", timeout=4.0)
                    except Exception as e:
                        log.debug(f"Lobby poller: GetClubDescList failed: {e}")
                    # ждать до следующего круга или выхода
                    if self._stop_lobby_poller.wait(next_wait):
                        break
                except Exception as e:
                    log.debug(f"Lobby poller error: {e}")
                    if self._stop_lobby_poller.wait(2.0):
                        break
            log.info("Lobby poller stopped")
        
        t = threading.Thread(target=poller, name="xclub-lobby-poller", daemon=True)
        self._lobby_poller_thread = t
        t.start()
        log.info("Lobby poller started")
    
    def stop_lobby_poller(self) -> None:
        """Остановить фоновый опрос списка клубов."""
        self._stop_lobby_poller.set()
        if self._lobby_poller_thread and self._lobby_poller_thread.is_alive():
            self._lobby_poller_thread.join(timeout=2)
        self._lobby_poller_thread = None
        
    def _prewarm_like_real(self) -> None:
        """Отправляет набор служебных запросов как в логах Frida перед операциями клуба.
        Игнорирует ошибки/таймауты; цель — синхронизация состояния на сервере.
        """
        try:
            from .constants import MSG_TYPE_IDS
            steps = [
                ("GetSelfDataREQ", b"", 1.5),
                ("GetUserCustomizeREQ", b"", 1.5),
                ("GetSelfGamesInfoREQ", b"", 1.5),
                # AppearanceSystemData требует параметр (в логах встречалось значение 3)
                ("GetAppearanceSystemDataREQ", bytes([0x08, 0x03]), 2.0),
                ("GetClubDescListREQ", b"", 2.5),
            ]
            for key, payload, tout in steps:
                try:
                    mid = MSG_TYPE_IDS[key]
                    cmd = f"pk.{key}"
                    expect = cmd.replace("REQ", "RSP")
                    _ = self.send_cmd_and_wait(cmd, mid, payload, expect, tout)
                except Exception as e:
                    log.debug(f"Prewarm step {key} failed: {e}")
                time.sleep(0.05)
        except Exception as e:
            log.debug(f"Prewarm sequence error: {e}")

    def simple_club_join(self, uid: int, token: str, club_id: int, message_text: Optional[str] = None) -> tuple[bool, str]:
        """Простой метод вступления в клуб с минимальным корректным прологом.
        
        Выполняет мини-последовательность, наблюдаемую в реальном клиенте:
        - короткая пауза
        - GetClubDescREQ (для целевого клуба)
        - Heartbeat (HBREQ)
        - ApplyClubREQ
        
        ВНИМАНИЕ: Предполагает, что TCP соединение уже установлено и логин выполнен!
        
        Args:
            uid: User ID
            token: Access token (не используется, т.к. логин уже выполнен)
            club_id: Club ID to join
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not self.ensure_connected():
                return False, "No TCP connection established"
            
            # Даем небольшой люфт на фоновый bootstrap после логина
            try:
                self._bootstrap_done.wait(timeout=2.0)
            except Exception:
                pass
            # Небольшая задержка перед действиями
            time.sleep(0.05)
            # Предполагаем, что pump/heartbeat/пуллер запускаются снаружи (main-скриптом) при необходимости.
            # 1) Прогреваем сессию набором служебных запросов (как в логах)
            try:
                # Прогрев можно отключить через внешний флаг
                if not getattr(self, "_no_prewarm", False):
                    self._prewarm_like_real()
            except Exception:
                pass

            # 2) Получаем описание клуба (как в актуальных логах) и проверяем, что клуб существует
            log.info(f"🏛️ Пролог: GetClubDescREQ для клуба {club_id} перед ApplyClubREQ")
            # Сначала пробуем корректный builder+pump; при отсутствии ответа далее сработают fallback-и внутри get_club_desc
            desc_response = self.get_club_desc(club_id)
            # Отмена сразу после получения ответа
            try:
                if self._external_cancel is not None and self._external_cancel.is_set():
                    return False, "Cancelled"
            except Exception:
                pass
            
            def _desc_indicates_existence(resp: bytes) -> bool:
                """Строгая проверка существования клуба по описанию.
                Считаем, что клуб существует, только если декодировано имя клуба (club_name)
                или явный флаг exists=True. Наличие RSP само по себе недостаточно.
                """
                has_rsp = bool(resp) and (MSG_GET_CLUB_DESC_RSP.encode() in resp)
                if not has_rsp:
                    return False
                try:
                    from core.protobuf_decoder import ProtobufDecoder
                    decoded = ProtobufDecoder.decode_club_desc_response(resp)
                    if not decoded or not isinstance(decoded, dict):
                        return False
                    club_info = decoded.get("club_info", {}) or {}
                    if club_info.get("club_name") or club_info.get("exists"):
                        return True
                    return False
                except Exception:
                    # Консервативно: при ошибке парсинга считаем клуб несуществующим
                    return False
            
            club_exists = _desc_indicates_existence(desc_response)
            if not club_exists:
                log.info(f"ℹ️ Первый ответ по клубу {club_id} неоднозначен/отсутствует — повторим попытку после HBREQ и шаблонный повтор")
                try:
                    _ = self._send_heartbeat()
                except Exception:
                    pass
                time.sleep(0.2)
                try:
                    desc_response = self.get_club_desc(club_id)
                except Exception as e:
                    log.info(f"Повторный GetClubDescREQ исключение: {e}")
                    desc_response = b""
                club_exists = _desc_indicates_existence(desc_response)
            
            if not club_exists:
                # Дополнительный fallback: попробуем msg_type_id=0x000f для GetClubDescREQ
                try:
                    desc_response = self.get_club_desc_via_template(club_id, msg_type_id_override=0x000f)
                    club_exists = _desc_indicates_existence(desc_response)
                except Exception:
                    pass
            if not club_exists:
                log.info(f"⛔ Клуб {club_id} не существует или недоступен — не отправляем ApplyClubREQ")
                return False, f"Клуб {club_id} не существует или недоступен"
            
            # 3) Как в логах: перед Apply клиент повторно запрашивает список клубов
            try:
                from .constants import MSG_TYPE_IDS as _MSGIDS
                _ = self.send_cmd_and_wait("pk.GetClubDescListREQ", _MSGIDS["GetClubDescListREQ"], b"", "pk.GetClubDescListRSP", timeout=2.0)
                log.debug("Повторный GetClubDescListRSP получен перед Apply")
            except Exception as e:
                log.debug(f"Повторный GetClubDescListREQ не удался (игнор): {e}")
            time.sleep(0.05)
            
            # 4) Отправляем заявку на вступление в клуб (через pump), без немедленного heartbeat — как в логах
            log.info(f"🎯 Отправляем заявку на вступление в клуб {club_id}...")
            from .protocol import varint_encode as _venc
            from .constants import MSG_TYPE_IDS as _MSGIDS
            # payload: field2 club_id, field1 message, field3=0
            uname = self._prepare_apply_message(uid, message_text)
            app_payload = bytes([0x10]) + _venc(club_id) + bytes([0x0a]) + _venc(len(uname)) + uname + bytes([0x18, 0x00])
            try:
                # отправляем пакет (ожидать прямо здесь не будем)
                _ = self.send_cmd_and_wait("pk.ApplyClubREQ", _MSGIDS["ApplyClubREQ"], app_payload, "pk.ApplyClubRSP", timeout=0.01)
            except Exception:
                pass
            # ждём реальный ответ до 15с
            apply_response = self.wait_for_cmd("pk.ApplyClubRSP", timeout=15.0) or b""
            # Если отмена — выходим аккуратно
            try:
                if self._external_cancel is not None and self._external_cancel.is_set():
                    return False, "Cancelled"
            except Exception:
                pass
            
            if MSG_APPLY_CLUB_RSP.encode() in apply_response:
                # Try to parse status from response
                try:
                    from core.protobuf_decoder import ProtobufDecoder
                    decoded = ProtobufDecoder.decode_apply_club_response(apply_response)
                    if decoded:
                        status = decoded.get('status', -1)
                        reason_text = (decoded.get('reason_text') or '').strip()
                        from core.messages import decode_club_apply_status
                        status_info = decode_club_apply_status(status)
                        
                        if status == 0:
                            return True, "Successfully joined club!"
                        elif status == 2:
                            return True, "Already member of club"
                        else:
                            fail_reason = reason_text or status_info['message']
                            return False, f"Join failed: {fail_reason}"
                    else:
                        return True, "Got ApplyClubRSP but couldn't parse status"
                except Exception as e:
                    log.debug(f"Failed to parse apply response: {e}")
                    return True, "Got ApplyClubRSP response"
            else:
                return False, "No ApplyClubRSP received"
                
        except Exception as e:
            log.error(f"Error in simple join: {e}")
            return False, f"Error: {e}"
        finally:
            # Не останавливаем heartbeat/pump здесь, чтобы fallback debug имел живое соединение
            pass
    
    def full_join_flow(self, uid: int, token: str, club_id: int) -> bool:
        """Complete flow to join a club.
        
        Args:
            uid: User ID from HTTP login
            token: Access token from HTTP login
            club_id: Target club ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # 1. Connect
            self.connect()
            
            # 2. TCP Login
            login_resp = self.tcp_login(uid, token)
            if MSG_USER_LOGIN_RSP.encode() not in login_resp:
                log.error("TCP login failed")
                return False
                
            # 3. Start heartbeat
            self.start_heartbeat()
            
            # 4. Get club description (optional but recommended)
            time.sleep(0.5)
            club_resp = self.get_club_desc(club_id)
            
            # 5. Apply to club
            time.sleep(0.5)
            apply_resp = self.apply_club(club_id, uid)
            
            # Check if successful
            if MSG_APPLY_CLUB_RSP.encode() in apply_resp:
                log.info(f"Successfully applied to club {club_id}")
                return True
            else:
                log.error(f"Failed to apply to club {club_id}")
                return False
                
        except Exception as e:
            log.error(f"Error in join flow: {e}")
            return False
        finally:
            # Keep connection for a bit before closing
            time.sleep(2)
            self.close()
