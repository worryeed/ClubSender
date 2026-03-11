
from __future__ import annotations
import sys, os, time, traceback, socket
import logging
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Dict, Set
from dataclasses import dataclass
from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QSpinBox, QCheckBox, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QComboBox, QGroupBox, QGridLayout, QProgressBar, QStyleFactory
)
import pandas as pd
import json
import requests
from pathlib import Path
import platform
try:
    import winreg  # for Windows theme detection
except Exception:
    winreg = None
# Optional: qdarktheme/pyqtdarktheme for consistent light/dark themes
_qdt_mod = None
_qdt_api = None  # 'setup_theme' | 'load_stylesheet' | None
try:
    import qdarktheme as _qdt_mod  # type: ignore
    _qdt_api = 'setup_theme' if hasattr(_qdt_mod, 'setup_theme') else ('load_stylesheet' if hasattr(_qdt_mod, 'load_stylesheet') else None)
except Exception:
    try:
        import pyqtdarktheme as _qdt_mod  # type: ignore
        _qdt_api = 'setup_theme' if hasattr(_qdt_mod, 'setup_theme') else ('load_stylesheet' if hasattr(_qdt_mod, 'load_stylesheet') else None)
    except Exception:
        _qdt_mod = None
        _qdt_api = None

from core import Account, JoinResult, XPokerAPI, ApiError, XClubTCPClient
from core.messages import Icons, format_login_step, format_join_result, MESSAGES
from core.version import __version__
from update.manager import UpdateManager

# Версия приложения для релизов/GUI
APP_VERSION = __version__

APP_TITLE = "ClubSender"
ACCOUNTS_COLUMNS = ["Имя пользователя", "Пароль", "Прокси", "ID устройства", "Токен (кратко)", "Последний вход"]
EXTRA_COLUMNS = ["Прогресс", "Статус", "Текущий клуб"]
REPORT_COLUMNS = ["Время", "Имя пользователя", "ID клуба", "Успешно", "Сообщение"]

class Worker(QThread):
    def __init__(self, accounts: List[Account], parent=None, *, api_class=XPokerAPI, api_error_class=ApiError):
        super().__init__(parent)
        self.accounts = accounts
        self._task = None
        self._args = ()
        self._stop = False
        self._pause = False
        self._stopped_accounts: Set[str] = set()  # Остановленные индивидуально аккаунты
        self.jitter_ms = (400, 900)
        # Для отслеживания последнего клуба при остановке
        self._last_club_info = {
            'club_id': None,
            'username': None,
            'success': None,
            'message': None
        }
        # Для хранения индивидуального распределения клубов
        self.account_club_limits: Dict[str, int] = {}
        # Событие отмены для быстрого прерывания сетевых ожиданий
        import threading as _th
        self._cancel_event = _th.Event()
        # Инъекция провайдера API
        self.api_class = api_class
        self.api_error_class = api_error_class
        # Отслеживание активных HTTP/TCP клиентов для жёсткой остановки
        self._live_apis: Set[object] = set()
        self._live_tcps: Set[object] = set()

    log = pyqtSignal(str)
    account_updated = pyqtSignal(int, list)
    join_result = pyqtSignal(object)
    task_finished = pyqtSignal()  # Сигнал о завершении задачи
    pause_changed = pyqtSignal(bool)  # Сигнал об изменении состояния паузы
    # username, done, total, status_text, current_club
    account_progress = pyqtSignal(str, int, int, str, str)
    # Новый аккаунт (после регистрации)
    new_account = pyqtSignal(object)


    def stop(self):
        self._stop = True
        try:
            # Сигнализируем всем долгим операциям о необходимости завершения
            self._cancel_event.set()
        except Exception:
            pass
        # Мгновенно обрубаем активные соединения
        try:
            self.log.emit(f"{Icons.WARNING} Остановка: прерываем текущие операции немедленно")
        except Exception:
            pass
        # TCP: закрыть сокеты
        try:
            for tcp in list(self._live_tcps):
                try:
                    if hasattr(tcp, 'set_cancel_event'):
                        try:
                            tcp.set_cancel_event(self._cancel_event)
                        except Exception:
                            pass
                    tcp.close()
                except Exception:
                    pass
                finally:
                    try:
                        self._live_tcps.discard(tcp)
                    except Exception:
                        pass
        except Exception:
            pass
        # HTTP: закрыть сессии
        try:
            for api in list(self._live_apis):
                try:
                    sess = getattr(api, 'session', None)
                    if sess is not None:
                        try:
                            sess.close()
                        except Exception:
                            pass
                except Exception:
                    pass
                finally:
                    try:
                        self._live_apis.discard(api)
                    except Exception:
                        pass
        except Exception:
            pass

    def set_pause(self, value: bool):
        """Установить состояние паузы и оповестить UI."""
        prev = self._pause
        self._pause = bool(value)
        if prev != self._pause:
            self.pause_changed.emit(self._pause)
            if self._pause:
                self.log.emit(f"{Icons.INFO} ⏸ Пауза: процесс приостановлен")
            else:
                self.log.emit(f"{Icons.INFO} ▶️ Продолжение: процесс возобновлён")

    def pause_toggle(self):
        """Переключить паузу."""
        self.set_pause(not self._pause)

    def _wait_if_paused(self):
        """Задержка выполнения, пока установлена пауза (или до остановки)."""
        while self._pause and not self._stop:
            try:
                # ждём небольшими шагами, чтобы stop() срабатывал мгновенно
                if hasattr(self, "_cancel_event") and self._cancel_event is not None:
                    self._cancel_event.wait(timeout=0.2)
                else:
                    time.sleep(0.2)
            except Exception:
                time.sleep(0.2)

    def _sleep(self, seconds: float, *, granularity: float = 0.1) -> None:
        """Ожидание с быстрым выходом при stop()/cancel_event и с уважением к паузе."""
        try:
            seconds_f = float(seconds)
        except Exception:
            return
        if seconds_f <= 0:
            return
        end = time.time() + seconds_f
        while (not self._stop) and time.time() < end:
            # если поставили паузу — ждём снятия
            self._wait_if_paused()
            if self._stop:
                break
            remain = end - time.time()
            if remain <= 0:
                break
            chunk = min(float(granularity), remain)
            try:
                if hasattr(self, "_cancel_event") and self._cancel_event is not None:
                    if self._cancel_event.wait(timeout=chunk):
                        break
                else:
                    time.sleep(chunk)
            except Exception:
                try:
                    time.sleep(chunk)
                except Exception:
                    break

    def run(self):
        if not self._task:
            return
        try:
            self._task(*self._args)
        except Exception as e:
            self.log.emit(f"[FATAL] {e}\n{traceback.format_exc()}")

    def set_task(self, fn, *args):
        self._task = fn
        self._args = args

    def task_login_all(self):
        # Сброс стопа/паузы/отмены
        try:
            self._stop = False
            # новая задача не должна стартовать в состоянии паузы
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        # Группируем аккаунты по прокси (ключ = строка прокси или None)
        from collections import defaultdict
        groups: Dict[Optional[str], list[int]] = defaultdict(list)
        for idx, acc in enumerate(self.accounts):
            groups[acc.proxy].append(idx)
        # Запускаем по одному потоку на каждую группу
        import threading
        threads: list[threading.Thread] = []
        counts_lock = threading.Lock()
        processed = 0
        ok_cnt = 0
        fail_cnt = 0

        def _is_transient_login_error(err: Exception) -> bool:
            s = str(err).lower()
            return (
                ("remotedisconnected" in s)
                or ("remote end closed connection without response" in s)
                or ("connection aborted" in s)
                or ("connection reset" in s)
                or ("connection refused" in s)
                or ("read timed out" in s)
                or ("connect timeout" in s)
                or ("timed out" in s)
                or ("proxyerror" in s)
                or ("max retries exceeded" in s)
                or ("service unavailable" in s)
                or ("bad gateway" in s)
                or ("gateway timeout" in s)
            )

        def group_worker(proxy_key: Optional[str], indices: list[int]):
            nonlocal processed, ok_cnt, fail_cnt
            for idx in indices:
                if self._stop:
                    break
                acc = self.accounts[idx]
                local_success = False
                api = None
                data = None
                try:
                    proxy_info = acc.proxy or 'без прокси'
                    self.log.emit(f"{Icons.AUTH} [{acc.username}] Авторизация через {proxy_info}")
                    # Генерируем device_id если отсутствует (один раз на аккаунт)
                    if not acc.device_id:
                        import uuid
                        acc.device_id = str(uuid.uuid4())
                        self.log.emit(f"{Icons.INFO} [{acc.username}] Сгенерирован device_id: {acc.device_id[:8]}...")

                    max_attempts = 3
                    for attempt_n in range(1, max_attempts + 1):
                        if self._stop:
                            break
                        self._wait_if_paused()
                        api = self.api_class(proxy=acc.proxy)
                        try:
                            self._live_apis.add(api)
                        except Exception:
                            pass
                        try:
                            data = api.login(
                                username=acc.username,
                                password=acc.password,
                                device_id=acc.device_id
                            )
                            token = api.token
                            acc.token = token
                            local_success = bool(token)
                            # Сохраняем refresh token если есть
                            acc.refresh_token = api.refresh_token
                            acc.access_token_expire = api.access_token_expire
                            acc.refresh_token_expire = api.refresh_token_expire
                            # Сохраняем служебные данные (TCP endpoints / version / client_ip) в extra
                            try:
                                eps = getattr(api, 'tcp_entries', None) or getattr(api, 'tcp_endpoints', None)
                                if eps:
                                    acc.extra['tcp_entries'] = list(eps)
                                cv = getattr(api, 'client_version', None)
                                if cv:
                                    acc.extra['client_version'] = str(cv)
                                cip = getattr(api, 'client_ip', None) or getattr(api, 'clientip', None)
                                if cip:
                                    acc.extra['client_ip'] = str(cip)
                            except Exception:
                                pass
                            # Try to extract UID from login response
                            uid = api.get_uid_from_login_response(data)
                            if uid:
                                acc.uid = uid
                                self.log.emit(format_login_step(acc.username, "UID получен", True, f"uid={uid}"))
                            else:
                                if acc.username.startswith("XP"):
                                    try:
                                        acc.uid = int(acc.username[2:])
                                        self.log.emit(format_login_step(acc.username, "UID получен из имени", True, f"uid={acc.uid}"))
                                    except Exception:
                                        self.log.emit(format_login_step(acc.username, "UID не найден", False, "не удалось извлечь из имени пользователя"))
                            acc.last_login_at = time.time()
                            try:
                                acc.headers = api.session.headers.copy()
                            except Exception:
                                acc.headers = {}
                            self.account_updated.emit(idx, acc.as_row())
                            # Понятный вывод причины, если токен не получен
                            human = None
                            try:
                                if isinstance(data, dict):
                                    dcode = int(data.get('code', -1))
                                    dmsg = str(data.get('msg', '') or '').lower()
                                    if not token:
                                        if dcode == 10010042 or 'user ban' in dmsg:
                                            human = 'аккаунт забанен (10010042)'
                                        elif dcode == 10000044 or 'accessdenied' in dmsg or 'access denied' in dmsg:
                                            human = 'IP под угрозой — использование запрещено (10000044)'
                            except Exception:
                                pass
                            if token:
                                self.log.emit(format_login_step(acc.username, "Авторизация завершена", True, "токен получен"))
                            else:
                                self.log.emit(format_login_step(acc.username, "Авторизация завершена", False, human or "токен отсутствует"))
                            break
                        except Exception as e:
                            # stop requested — прекращаем без лишних логов/ретраев
                            if self._stop:
                                break
                            if attempt_n < max_attempts and _is_transient_login_error(e):
                                wait_s = 2.0 * attempt_n
                                try:
                                    self.log.emit(f"{Icons.WARNING} [{acc.username}] HTTP login: {e}. Повтор {attempt_n+1}/{max_attempts} через {int(wait_s)}с…")
                                except Exception:
                                    pass
                                self._sleep(wait_s)
                                continue
                            raise
                        finally:
                            # Закрываем HTTP-сессию, чтобы не держать лишние дескрипторы/сокеты
                            try:
                                sess = getattr(api, 'session', None)
                                if sess is not None:
                                    sess.close()
                            except Exception:
                                pass
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                except self.api_error_class as e:
                    self.log.emit(format_login_step(acc.username, "Ошибка API", False, str(e)))
                except Exception as e:
                    self.log.emit(format_login_step(acc.username, "Ошибка авторизации", False, str(e)))
                finally:
                    # Закрываем HTTP-сессию, чтобы не держать лишние дескрипторы/сокеты
                    try:
                        sess = getattr(api, 'session', None)
                        if sess is not None:
                            sess.close()
                    except Exception:
                        pass
                    # Счётчики
                    try:
                        with counts_lock:
                            processed += 1
                            if local_success:
                                ok_cnt += 1
                            else:
                                fail_cnt += 1
                    except Exception:
                        pass
                if not self._stop:
                    self._sleep(self._rand_delay())
        for proxy_key, idxs in groups.items():
            t = threading.Thread(target=group_worker, args=(proxy_key, idxs), daemon=True)
            threads.append(t)
            t.start()
        # Ожидаем завершение всех групп или стоп
        stop_deadline = 0.0
        announced_wait = False
        while any(t.is_alive() for t in threads):
            if self._stop:
                if not announced_wait:
                    try:
                        self.log.emit(f"{Icons.INFO} Ожидаем остановки рабочих потоков...")
                    except Exception:
                        pass
                    announced_wait = True
                    stop_deadline = time.time() + 6.0  # максимум 6с на корректное завершение
                if time.time() > stop_deadline:
                    break
            self._wait_if_paused()
            time.sleep(0.1)
        # Точечно подождём каждый поток до 300мс, чтобы убрать хвосты логов
        for t in threads:
            try:
                t.join(timeout=0.3)
            except Exception:
                pass
        # Итоговая строка: сколько вошло и сколько ошибок
        try:
            icon = Icons.SUCCESS if fail_cnt == 0 else Icons.INFO
            self.log.emit(f"{icon} 🏁 Вход завершён: успешно {ok_cnt}, ошибки {fail_cnt}, всего {processed}")
        except Exception:
            pass
        self.task_finished.emit()

    def task_logout_selected(self, rows: List[int]):
        for r in rows:
            if self._stop: break
            acc = self.accounts[r]
            if not acc.token:
                self.log.emit(f"{Icons.WARNING} [{acc.username}] Выход: нет токена")
                continue
            api = None
            try:
                api = self.api_class(proxy=acc.proxy)
                try:
                    self._live_apis.add(api)
                except Exception:
                    pass
                api.logout(acc.token)
                acc.token = None
                self.account_updated.emit(r, acc.as_row())
                self.log.emit(f"{Icons.SUCCESS} [{acc.username}] Выход выполнен успешно")
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [{acc.username}] Ошибка выхода: {e}")
            finally:
                try:
                    if api is not None:
                        sess = getattr(api, 'session', None)
                        if sess is not None:
                            sess.close()
                        try:
                            self._live_apis.discard(api)
                        except Exception:
                            pass
                except Exception:
                    pass
            self._sleep(self._rand_delay())

    def task_join_round(self, club_ids: List[str], clubs_per_account: int, delay_min_ms: int, delay_max_ms: int, message_text: Optional[str] = None, join_threads: int = 32):
        # Сброс сигнала остановки/паузы и очистка события отмены перед стартом задачи
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        self.jitter_ms = (delay_min_ms, delay_max_ms)
        processed_clubs = 0
        
        # Получаем только авторизованные аккаунты
        authorized_accounts = [acc for acc in self.accounts if acc.token]
        
        if not authorized_accounts:
            self.log.emit(f"{Icons.ERROR} Нет авторизованных аккаунтов для выполнения операции")
            self.task_finished.emit()
            return
            
        # Проверяем, есть ли индивидуальное распределение
        using_individual_limits = len(self.account_club_limits) > 0
        
        if using_individual_limits:
            # Логируем индивидуальное распределение
            total_clubs_needed = sum(
                self.account_club_limits.get(acc.username.lower(), 0) 
                for acc in authorized_accounts
            )
            self.log.emit(f"{Icons.INFO} 📊 Используется индивидуальное распределение клубов")
        else:
            # Стандартное распределение
            if clubs_per_account == 0:
                clubs_per_account = len(club_ids)
                self.log.emit(f"{Icons.INFO} Режим 'все клубы': будет использовано {clubs_per_account} клубов на аккаунт")
            
            total_clubs_needed = len(authorized_accounts) * clubs_per_account
        
        # Валидация: достаточно ли клубов для всех аккаунтов
        if len(club_ids) < total_clubs_needed:
            self.log.emit(f"{Icons.WARNING} ⚠️ Недостаточно клубов! Требуется {total_clubs_needed}, доступно {len(club_ids)}")
            self.log.emit(f"{Icons.INFO} Будут использованы все доступные клубы")
        
        # Логируем распределение клубов по аккаунтам
        self.log.emit(f"{Icons.INFO} 📋 Распределение клубов:")
        self.log.emit(f"{Icons.INFO} • Авторизованных аккаунтов: {len(authorized_accounts)}")
        if using_individual_limits:
            self.log.emit(f"{Icons.INFO} • Используется индивидуальное распределение клубов")
        else:
            self.log.emit(f"{Icons.INFO} • Клубов на аккаунт: {clubs_per_account}")
        self.log.emit(f"{Icons.INFO} • Общее количество клубов требуется: {total_clubs_needed}")
        self.log.emit(f"{Icons.INFO} • Всего клубов для обработки: {len(club_ids)}")
        
        # Распределяем клубы по аккаунтам порционно
        club_index = 0
        account_jobs = []  # [(acc, [club_ids])]
        assigned_accounts = 0
        for acc_idx, acc in enumerate(authorized_accounts):
            # Определяем количество клубов для текущего аккаунта
            if using_individual_limits:
                account_clubs_count = self.account_club_limits.get(acc.username.lower(), 0)
                if account_clubs_count == 0:
                    self.log.emit(f"{Icons.INFO} [{acc.username}] Лимит клубов = 0, аккаунт пропускается")
                    continue
            else:
                account_clubs_count = clubs_per_account
            # Определяем диапазон клубов для текущего аккаунта
            start_idx = club_index
            end_idx = min(club_index + account_clubs_count, len(club_ids))
            if start_idx >= len(club_ids):
                remaining = len(authorized_accounts) - acc_idx
                if remaining > 0:
                    self.log.emit(f"{Icons.INFO} Осталось аккаунтов без клубов: {remaining} — будут пропущены")
                break
            account_clubs = club_ids[start_idx:end_idx]
            club_index = end_idx
            # Логируем диапазон клубов для аккаунта
            if len(account_clubs) > 0:
                clubs_range = f"{account_clubs[0]}-{account_clubs[-1]}" if len(account_clubs) > 1 else account_clubs[0]
                self.log.emit(f"{Icons.INFO} 👤 [{acc.username}] назначено {len(account_clubs)} клубов: {clubs_range}")
                assigned_accounts += 1
            account_jobs.append((acc, account_clubs))
        
        # Параллельная обработка по аккаунтам: одно TCP-соединение на аккаунт
        import threading, queue
        processed_clubs_lock = threading.Lock()
        processed_clubs_total = 0
        # Агрегатор результатов по аккаунтам + сводные счётчики
        agg_lock = threading.Lock()
        agg_results: Dict[str, Dict[str, object]] = {}
        summary_lock = threading.Lock()
        ok_total = 0
        not_found_total = 0
        send_fail_total = 0

        def _is_not_found_msg(m: str) -> bool:
            s = (m or "").lower()
            return (
                ("клуба нет" in s)
                or ("клуб не найден" in s)
                or ("не существует" in s)
                or ("club not found" in s)
            )

        def _bump_summary(ok: bool, msg: str) -> None:
            nonlocal ok_total, not_found_total, send_fail_total
            try:
                with summary_lock:
                    if ok:
                        ok_total += 1
                    else:
                        if _is_not_found_msg(msg):
                            not_found_total += 1
                        else:
                            send_fail_total += 1
            except Exception:
                pass

        def account_worker(acc: Account, account_clubs: list[str]):
            nonlocal processed_clubs_total
            try:
                # Проверка обязательных полей
                if not acc.uid:
                    self.log.emit(f"{Icons.ERROR} [{acc.username}] UID отсутствует — пропуск аккаунта")
                    return
                api = self.api_class(proxy=acc.proxy)
                try:
                    self._live_apis.add(api)
                except Exception:
                    pass
                api.token = acc.token
                api.refresh_token = acc.refresh_token
                # Пробросим сохранённые служебные данные (если есть)
                try:
                    if getattr(acc, 'device_id', None) is not None and hasattr(api, 'device_id'):
                        api.device_id = acc.device_id
                    eps = None
                    try:
                        eps = (acc.extra or {}).get('tcp_entries')
                    except Exception:
                        eps = None
                    if eps:
                        if hasattr(api, 'tcp_entries'):
                            api.tcp_entries = list(eps)
                        if hasattr(api, 'tcp_endpoints'):
                            api.tcp_endpoints = list(eps)
                        if hasattr(api, 'tcp_host') and hasattr(api, 'tcp_port'):
                            try:
                                api.tcp_host, api.tcp_port = list(eps)[0]
                            except Exception:
                                pass
                    try:
                        cv = (acc.extra or {}).get('client_version')
                        if cv and hasattr(api, 'client_version'):
                            api.client_version = str(cv)
                    except Exception:
                        pass
                    try:
                        cip = (acc.extra or {}).get('client_ip')
                        if cip and hasattr(api, 'client_ip'):
                            api.client_ip = str(cip)
                    except Exception:
                        pass
                except Exception:
                    pass
                # Колбэк прогресса для остановки/паузы
                def progress_cb(cid: int, idx: int, total: int) -> bool:
                    # Ожидание паузы
                    self._wait_if_paused()
                    # Проверка остановки
                    if self._stop:
                        return False
                    # Отобразить статус начала обработки клуба
                    self.account_progress.emit(acc.username, idx, total, "🔄 Обработка", str(cid))
                    if idx == 0:
                        self.log.emit(f"{Icons.TARGET} [{acc.username}] ▶️ Старт обработки {total} клубов на одном TCP-соединении")
                    return True
                # Колбэк результатов по мере выполнения
                def result_cb(cid: int, ok: bool, msg: str, idx: int, total: int):
                    nonlocal processed_clubs_total
                    # Если запрошена остановка — не спамим логами и выходим как можно раньше
                    if self._stop:
                        return
                    done = idx + 1
                    low = (msg or "").lower()
                    def _is_transient_tcp(m: str) -> bool:
                        s = m.lower()
                        return (
                            ("no tcp connection" in s)
                            or ("socket error" in s)
                            or ("timed out" in s)
                            or ("tcp_connect" in s)
                            or ("tcp_login" in s)
                            or ("tcp login" in s)
                            or ("userloginrsp" in s)
                            or ("connect timeout" in s)
                            or ("read timed out" in s)
                        )
                    # Если временная сетевая ошибка — сделаем 1 повтор через 10с для этого клуба
                    if not ok and _is_transient_tcp(low):
                        try:
                            self.log.emit(f"{Icons.WARNING} [{acc.username}] → Клуб {cid}: временная ошибка сети ({msg}). Повтор через 10с…")
                        except Exception:
                            pass
                        # Пауза с уважением к паузе/стопу
                        for _ in range(10):
                            if self._stop:
                                return
                            self._sleep(1.0)
                        # Повтор одной попыткой на отдельном TCP
                        ok2 = False; msg2 = msg
                        try:
                            _any2, _res2 = api.join_clubs_tcp([int(cid)], uid=acc.uid, auth_token=acc.token, keepalive=False, progress_cb=None, result_cb=None, cancel_event=self._cancel_event, message_text=message_text)
                            if _res2:
                                _, ok2, msg2 = _res2[0]
                            else:
                                ok2 = _any2; msg2 = msg2 or ""
                        except Exception as e:
                            ok2 = False; msg2 = str(e)
                        # Финальная фиксация результата после повтора
                        try:
                            self.join_result.emit(JoinResult(ts=time.time(), username=acc.username, club_id=str(cid), ok=ok2, message=msg2))
                            result_msg = format_join_result(acc.username, str(cid), ok2, msg2)
                            self.log.emit(result_msg)
                            status_text = "✅ Клуб есть" if ok2 else ("❌ Клуба нет" if _is_not_found_msg(msg2) else "❌ Ошибка")
                            self.account_progress.emit(acc.username, done, total, status_text, str(cid))
                        except Exception:
                            pass
                        with processed_clubs_lock:
                            processed_clubs_total += 1
                        _bump_summary(bool(ok2), str(msg2 or ""))
                        # Агрегатор
                        try:
                            with agg_lock:
                                r = agg_results.setdefault(acc.username, {"ok": 0, "fail": 0, "ok_ids": []})
                                if ok2:
                                    r["ok"] = int(r.get("ok", 0)) + 1
                                    try:
                                        r["ok_ids"].append(str(cid))  # type: ignore
                                    except Exception:
                                        pass
                                else:
                                    r["fail"] = int(r.get("fail", 0)) + 1
                        except Exception:
                            pass
                        if not self._stop:
                            self._sleep(self._rand_delay())
                        return
                    # Обычная обработка (без повтора)
                    self.join_result.emit(JoinResult(ts=time.time(), username=acc.username, club_id=str(cid), ok=ok, message=msg))
                    result_msg = format_join_result(acc.username, str(cid), ok, msg)
                    self.log.emit(result_msg)
                    status_text = "✅ Клуб есть" if ok else ("❌ Клуба нет" if _is_not_found_msg(msg) else "❌ Ошибка")
                    self.account_progress.emit(acc.username, done, total, status_text, str(cid))
                    with processed_clubs_lock:
                        processed_clubs_total += 1
                    _bump_summary(bool(ok), str(msg or ""))
                    # Сохраним для мини-отчёта
                    try:
                        with agg_lock:
                            r = agg_results.setdefault(acc.username, {"ok": 0, "fail": 0, "ok_ids": []})
                            if ok:
                                r["ok"] = int(r.get("ok", 0)) + 1
                                try:
                                    r["ok_ids"].append(str(cid))  # type: ignore
                                except Exception:
                                    pass
                            else:
                                r["fail"] = int(r.get("fail", 0)) + 1
                    except Exception:
                        pass
                    if not self._stop:
                        self._sleep(self._rand_delay())
                # Преобразуем ID клубов в int
                club_ids_int: list[int] = []
                for cid in account_clubs:
                    try:
                        club_ids_int.append(int(cid))
                    except Exception:
                        self.log.emit(f"{Icons.ERROR} [{acc.username}] Неверный формат ID клуба: {cid}")
                if not club_ids_int:
                    return
                # Одна попытка + 1 повтор при сетевых таймаутах подключения/логина
                try:
                    attempt = 0
                    while attempt < 2:
                        try:
                            any_success, results = api.join_clubs_tcp(
                                club_ids_int,
                                uid=acc.uid,
                                auth_token=acc.token,
                                keepalive=False,
                                progress_cb=progress_cb,
                                result_cb=result_cb,
                                cancel_event=self._cancel_event,
                                message_text=message_text,
                            )
                            break
                        except self.api_error_class as e:
                            em = str(e).lower()
                            transient = ("tcp_connect" in em) or ("tcp_login" in em) or ("timed out" in em) or ("connect timeout" in em)
                            if transient and attempt == 0 and not self._stop:
                                try:
                                    self.log.emit(f"{Icons.WARNING} [{acc.username}] TCP подключение/логин: {e}. Повтор через 10с…")
                                except Exception:
                                    pass
                                for _ in range(10):
                                    if self._stop:
                                        break
                                    self._sleep(1.0)
                                attempt += 1
                                continue
                            # Нетребуемая или повторная ошибка — пробрасываем
                            raise
                finally:
                    # Закрываем HTTP-сессию — TCP не зависит от неё
                    try:
                        sess = getattr(api, 'session', None)
                        if sess is not None:
                            sess.close()
                        try:
                            self._live_apis.discard(api)
                        except Exception:
                            pass
                    except Exception:
                        pass
                # Если остановка запрошена — не эмитим финальный статус для аккуратного молчаливого завершения
                if self._stop:
                    return
                # Если result_cb уже отдал все, можно дополнительно финализировать статус
                self.account_progress.emit(acc.username, len(results), len(club_ids_int), "🏁 Завершено", "-")
            except Exception as e:
                if not self._stop:
                    self.log.emit(f"{Icons.ERROR} [{acc.username}] Ошибка обработки аккаунта: {e}")
        
        # Пул потоков по заданиям (аккаунт + его клубы)
        job_q: "queue.Queue[tuple[Account, list[str]]]" = queue.Queue()
        for acc, acc_clubs in account_jobs:
            job_q.put((acc, acc_clubs))
        pool_size = max(1, int(join_threads))
        pool_size = min(pool_size, len(account_jobs) if account_jobs else 1)
        threads: list[threading.Thread] = []
        def pool_worker():
            while not self._stop:
                try:
                    acc, acc_clubs = job_q.get_nowait()
                except queue.Empty:
                    break
                try:
                    account_worker(acc, acc_clubs)
                except Exception as e:
                    if not self._stop:
                        try:
                            self.log.emit(f"{Icons.ERROR} [{acc.username}] Ошибка рабочего пула: {e}")
                        except Exception:
                            pass
                finally:
                    try:
                        job_q.task_done()
                    except Exception:
                        pass
                    # Избегаем лишнего спина
                    self._wait_if_paused()
        for _ in range(pool_size):
            t = threading.Thread(target=pool_worker, daemon=True)
            threads.append(t)
            t.start()
        # Ждём завершения пула (или остановки)
        stop_deadline = 0.0
        announced_wait = False
        while any(t.is_alive() for t in threads):
            if self._stop:
                if not announced_wait:
                    try:
                        self.log.emit(f"{Icons.INFO} Ожидаем остановки рабочих потоков...")
                    except Exception:
                        pass
                    announced_wait = True
                    stop_deadline = time.time() + 6.0  # максимум 6с на корректное завершение
                if time.time() > stop_deadline:
                    break
            self._wait_if_paused()
            self._sleep(0.1)
        # Точечно подождём каждый поток до 300мс, чтобы убрать хвосты логов
        for t in threads:
            try:
                t.join(timeout=0.3)
            except Exception:
                pass
        if not self._stop:
            try:
                job_q.join()
            except Exception:
                pass
        
        # Итоговый отчёт по вступлению
        planned_clubs = min(total_clubs_needed, len(club_ids))
        if self._stop:
            finish_reason = "Остановлено пользователем"
            icon = Icons.WARNING
        elif planned_clubs <= 0:
            finish_reason = "Нет клубов для обработки"
            icon = Icons.INFO
        else:
            finish_reason = "Все задачи выполнены"
            icon = Icons.SUCCESS
        # Если клубов не хватило на всех аккаунтов — добавим пояснение
        try:
            if assigned_accounts < len(authorized_accounts):
                skipped = len(authorized_accounts) - assigned_accounts
                finish_reason += f"; аккаунтов без клубов: {skipped}"
        except Exception:
            pass
        self.log.emit(
            f"{icon} 🏁 Конец вступления: {finish_reason}. "
            f"Прогресс: {processed_clubs_total}/{planned_clubs} "
            f"(успешно: {ok_total}, клуба нет: {not_found_total}, ошибки: {send_fail_total}). "
            f"Аккаунтов использовано: {assigned_accounts}/{len(authorized_accounts)}"
        )
        self.task_finished.emit()

    def _rand_delay(self):
        import random
        a,b = self.jitter_ms
        return random.randint(a,b)/1000.0

    # -------- helper: upload avatar to tmpfiles and return direct dl URL --------
    def _upload_avatar_tmpfiles(self, file_path: str) -> Optional[str]:
        try:
            fn = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                files = {'file': (fn, f, 'application/octet-stream')}
                r = requests.post('https://tmpfiles.org/api/v1/upload', files=files, timeout=25)
            r.raise_for_status()
            try:
                j = r.json()
            except Exception:
                j = None
            url = None
            if isinstance(j, dict):
                url = (j.get('data', {}) or {}).get('url') or j.get('url')
            if not url:
                txt = (r.text or '')
                import re
                m = re.search(r'https?://tmpfiles\.org/[^\s"]+', txt)
                if m:
                    url = m.group(0)
            if not url:
                return None
            # Build direct dl URL
            # Expected share url like https://tmpfiles.org/1234567/filename or /f/1234567/filename
            import re
            m = re.search(r'tmpfiles\.org/(?:f/)?(\d+)/(.*)$', url)
            if m:
                file_id, fname = m.group(1), m.group(2)
                dl = f'https://tmpfiles.org/dl/{file_id}/{fname}'
                return dl
            # If already a direct link or unknown pattern
            if '/dl/' in url:
                return url
            return url
        except Exception:
            return None

    # ===== PPPoker helpers =====
    def _ppp_imei40(self, seed: str) -> str:
        try:
            import hashlib
            s = (seed or '').replace('-', '').strip() or 'pppoker'
            return hashlib.sha1(s.encode('utf-8')).hexdigest()
        except Exception:
            return 'd98cc29319f8ff44f171963a3f959a0c07803c4a'

    def _ppp_upload_avatar(self, api, uid: int, image_path: str) -> Optional[str]:
        try:
            import mimetypes
            url = 'https://www.pppoker.club/poker/api/icon_up.php'
            params = {
                'rdkey': getattr(api, 'token', '') or '',
                'uid': str(int(uid)),
                'type': 'user',
                'clubid': '0',
            }
            mt, _ = mimetypes.guess_type(image_path)
            if not mt:
                mt = 'image/jpeg'
            fn = os.path.basename(image_path) or 'icon.jpg'
            with open(image_path, 'rb') as f:
                files = {'icon': (fn, f, mt)}
                data = {'act': 'upload', 'submit': 'upload'}
                r = requests.post(url, params=params, data=data, files=files, timeout=30, proxies=getattr(api, 'proxies', None), verify=False)
            r.raise_for_status()
            try:
                j = r.json()
            except Exception:
                j = None
            if isinstance(j, dict) and int(j.get('code', -1)) == 0:
                return str(j.get('icon') or '')
            return None
        except Exception:
            return None

    # ===== FishPoker helpers =====
    def _fp_gen_device_id(self, seed: Optional[str] = None) -> str:
        """Generate a MAC-like device id (XX-XX-XX-XX-XX-XX)."""
        try:
            import hashlib
            import secrets

            if seed:
                h = hashlib.md5(str(seed).encode('utf-8')).digest()
                b = bytearray(h[:6])
            else:
                b = bytearray(secrets.token_bytes(6))
            # locally administered, unicast
            b[0] = (b[0] & 0xFE) | 0x02
            return '-'.join(f"{x:02X}" for x in b)
        except Exception:
            return '02-00-00-00-00-01'

    def _fp_upload_avatar(self, api, uid: int, image_path: str) -> Optional[str]:
        try:
            rdkey = getattr(api, 'token', '') or ''
            if not rdkey:
                return None
            fn = getattr(api, 'upload_avatar', None)
            if callable(fn):
                return fn(uid=int(uid), rdkey=str(rdkey), image_path=str(image_path))
            return None
        except Exception:
            return None

    def task_register_fishpoker(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, avatar_path: Optional[str] = None):
        """Регистрация FishPoker: HTTP register -> HTTP login -> (опц.) upload avatar -> (опц.) TCP change nick."""
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        # jitter
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a: a, b = b, a
            self.jitter_ms = (max(0, a), max(0, b))
        except Exception:
            self.jitter_ms = (400, 900)
        # generator
        try:
            from core.credgen import CredGenerator
        except Exception as e:
            self.log.emit(f"{Icons.ERROR} Не удалось импортировать генератор: {e}")
            return
        gen = CredGenerator(words_file=words_file)
        proxies = [p.strip() for p in (proxies or []) if p and p.strip()]
        proxy_count = len(proxies)
        proxy_idx = 0
        used_usernames: Set[str] = set()
        # CSV
        regs_file = None
        regs_writer = None
        try:
            from pathlib import Path
            import csv
            regs_path = Path('logs')/"registrations.csv"
            regs_path.parent.mkdir(parents=True, exist_ok=True)
            is_new = not regs_path.exists() or regs_path.stat().st_size == 0
            regs_file = regs_path.open('a', encoding='utf-8', newline='')
            regs_writer = csv.writer(regs_file)
            if is_new:
                regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        except Exception:
            regs_file = None
            regs_writer = None

        def current_proxy() -> Optional[str]:
            nonlocal proxy_idx
            if proxy_count == 0:
                return reg_proxy
            p = proxies[proxy_idx % proxy_count]
            proxy_idx += 1
            return p

        processed_total = 0
        success_total = 0
        fail_total = 0

        try:
            from fishpoker.api import FishPokerAPI
        except Exception as e:
            self.log.emit(f"{Icons.ERROR} FishPoker API недоступен: {e}")
            return

        for i in range(int(count)):
            if self._stop:
                break
            self._wait_if_paused()
            # creds
            def _mk_nick(u: str) -> str:
                n = gen.derive_nick(u, min_len=6, max_len=20)
                # FishPoker: если ник совпал с логином — добавим цифры, чтобы он реально изменился
                try:
                    if (n or '').lower() == (u or '').lower():
                        import random
                        suf = str(random.randint(100, 9999))
                        base = n
                        if len(base) + len(suf) > 20:
                            base = base[: max(1, 20 - len(suf))]
                        n = (base + suf)[:20]
                except Exception:
                    pass
                return n

            username = gen.generate_login(min_len=6, max_len=16)
            while username in used_usernames:
                username = gen.generate_login(min_len=6, max_len=16)
            used_usernames.add(username)
            nick = _mk_nick(username)
            password = gen.generate_password(min_len=6, max_len=16)
            device_id = self._fp_gen_device_id(username)

            self.log.emit(f"{Icons.PROCESS} [FP] Регистрация [{i+1}/{count}] {username}")

            api = None
            curp = current_proxy()
            api = FishPokerAPI(proxy=curp)
            try:
                self._live_apis.add(api)
            except Exception:
                pass

            max_username_retries = 6
            max_net_retries = 6
            uname_retry = 0
            net_retry = 0
            reg_ok = False
            reg_code = -999
            reg_msg = ''

            while not self._stop:
                self._wait_if_paused()
                try:
                    rsp = api.register(username=username, password=password, device_id=device_id, country='CN')
                    reg_code = int(rsp.get('code', -1)) if isinstance(rsp, dict) else -1
                    reg_msg = str(rsp.get('msg', '') or '') if isinstance(rsp, dict) else ''
                except Exception as e:
                    reg_code = -999
                    reg_msg = str(e)

                if reg_code == 0:
                    reg_ok = True
                    break

                busy = (reg_code == -1) or (reg_code == 10010008) or (
                    'username' in (reg_msg or '').lower() and (
                        'unavailable' in (reg_msg or '').lower() or 'exists' in (reg_msg or '').lower() or 'exist' in (reg_msg or '').lower()
                    )
                )
                if busy and uname_retry < max_username_retries:
                    old = username
                    username = gen.generate_login(min_len=6, max_len=16)
                    while username in used_usernames:
                        username = gen.generate_login(min_len=6, max_len=16)
                    used_usernames.add(username)
                    nick = _mk_nick(username)
                    uname_retry += 1
                    self.log.emit(f"{Icons.WARNING} [FP] Имя занято (code={reg_code}). Новая попытка: {old} → {username} ({uname_retry}/{max_username_retries})")
                    self._sleep(self._rand_delay())
                    continue

                hard = (reg_code in (-999, -2, 10000044, 20010029)) or ('access' in (reg_msg or '').lower() and 'denied' in (reg_msg or '').lower())
                if hard and proxy_count > 0 and net_retry < max_net_retries:
                    try:
                        self.log.emit(f"{Icons.WARNING} [FP] Ошибка регистрации (code={reg_code} msg={reg_msg}). Смена прокси...")
                    except Exception:
                        pass
                    # close previous session
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    curp = current_proxy()
                    api = FishPokerAPI(proxy=curp)
                    try:
                        self._live_apis.add(api)
                    except Exception:
                        pass
                    net_retry += 1
                    self._sleep(self._rand_delay())
                    continue

                break

            if not reg_ok:
                self.log.emit(f"{Icons.ERROR} [FP] Регистрация отклонена: code={reg_code} msg={reg_msg}")
                try:
                    if regs_writer is not None:
                        import datetime
                        regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, reg_code, reg_msg, ''])
                        regs_file.flush()  # type: ignore[attr-defined]
                except Exception:
                    pass
                fail_total += 1
                processed_total += 1
                self._sleep(self._rand_delay())
                continue

            # login (до 3 попыток на сетевых обрывах)
            data = None
            last_login_err = None
            for att in range(1, 3 + 1):
                if self._stop:
                    break
                self._wait_if_paused()
                try:
                    data = api.login(username=username, password=password, device_id=device_id, country='CN')
                    last_login_err = None
                    break
                except Exception as e:
                    last_login_err = e
                    if self._stop:
                        break
                    s = str(e).lower()
                    transient = (
                        ("remotedisconnected" in s)
                        or ("remote end closed connection without response" in s)
                        or ("connection aborted" in s)
                        or ("connection reset" in s)
                        or ("proxyerror" in s)
                        or ("max retries exceeded" in s)
                        or ("read timed out" in s)
                        or ("connect timeout" in s)
                        or ("timed out" in s)
                        or ("bad gateway" in s)
                        or ("service unavailable" in s)
                        or ("gateway timeout" in s)
                    )
                    if transient and att < 3:
                        wait_s = 2.0 * att
                        try:
                            self.log.emit(f"{Icons.WARNING} [FP] Login: {e}. Повтор {att+1}/3 через {int(wait_s)}с…")
                        except Exception:
                            pass
                        self._sleep(wait_s)
                        continue
                    break
            if data is None:
                if self._stop:
                    break
                e = last_login_err
                self.log.emit(f"{Icons.ERROR} [FP] Ошибка login после регистрации: {e}")
                try:
                    if regs_writer is not None:
                        import datetime
                        regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, -999, f"login:{e}", ''])
                        regs_file.flush()  # type: ignore[attr-defined]
                except Exception:
                    pass
                fail_total += 1
                processed_total += 1
                self._sleep(self._rand_delay())
                continue

            code = int(data.get('code', -1)) if isinstance(data, dict) else -1
            if code != 0 or not getattr(api, 'token', None):
                self.log.emit(f"{Icons.ERROR} [FP] Login отклонён: code={code}")
                try:
                    if regs_writer is not None:
                        import datetime
                        regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, code, 'login_failed', ''])
                        regs_file.flush()  # type: ignore[attr-defined]
                except Exception:
                    pass
                fail_total += 1
                processed_total += 1
                self._sleep(self._rand_delay())
                continue

            uid = api.get_uid_from_login_response(data)

            # Перед сменой профиля (аватар/ник) дадим аккаунту "созреть"
            # Это уменьшает случаи, когда сервер отвечает OK, но изменения не применяются сразу.
            if (uid and api.token) and ((change_avatar and avatar_path) or change_nick):
                self._sleep(4.0)

            # Avatar (per-account), 2 retries, 7s interval
            if change_avatar and avatar_path and uid and api.token:
                max_avatar_attempts = 3
                last_err = None
                url = None
                for att in range(1, max_avatar_attempts + 1):
                    if self._stop:
                        break
                    self._wait_if_paused()
                    try:
                        url = self._fp_upload_avatar(api, int(uid), avatar_path)
                        if url:
                            self.log.emit(f"{Icons.INFO} [FP] Аватар загружен: {url}")
                            break
                    except Exception as e:
                        last_err = e
                    if att < max_avatar_attempts:
                        try:
                            self.log.emit(f"{Icons.WARNING} [FP] Аватар: повторная попытка {att+1}/{max_avatar_attempts} через 7с")
                        except Exception:
                            pass
                        for _ in range(7):
                            if self._stop:
                                break
                            self._sleep(1.0)
                if not url:
                    if last_err:
                        self.log.emit(f"{Icons.WARNING} [FP] Аватар не загружен после {max_avatar_attempts} попыток: {last_err}")
                    else:
                        self.log.emit(f"{Icons.WARNING} [FP] Аватар не загружен после {max_avatar_attempts} попыток")

            # TCP change nick (2 retries, 7s interval)
            if change_nick and uid and api.token:
                # дополнительная пауза перед сменой ника (часто помогает)
                self._sleep(4.0)
                max_nick_attempts = 3
                okn = False
                last_msg = ''
                endpoints = list(getattr(api, 'tcp_entries', []) or [])
                for att in range(1, max_nick_attempts + 1):
                    if self._stop:
                        break
                    self._wait_if_paused()
                    try:
                        okn, rsp = api.change_username_tcp(uid=int(uid), token=str(api.token), nickname=nick, endpoints=endpoints, cancel_event=self._cancel_event)
                        if okn:
                            self.log.emit(f"{Icons.INFO} [FP] Смена ника [{username}] → '{nick}': успех")
                            break
                        last_msg = str(rsp)
                    except Exception as e:
                        last_msg = str(e)
                    if not okn and att < max_nick_attempts:
                        try:
                            self.log.emit(f"{Icons.WARNING} [FP] Смена ника: повторная попытка {att+1}/{max_nick_attempts} через 7с ({last_msg})")
                        except Exception:
                            pass
                        for _ in range(7):
                            if self._stop:
                                break
                            self._sleep(1.0)
                if not okn:
                    self.log.emit(f"{Icons.WARNING} [FP] Смена ника не удалась после {max_nick_attempts} попыток: {last_msg}")

            # Emit account
            acc = Account(username=username, password=password, device_id=device_id)
            acc.proxy = api.proxy_url
            acc.token = api.token
            acc.uid = int(uid) if uid else None
            acc.last_login_at = time.time()
            try:
                acc.headers = api.session.headers.copy() if hasattr(api, 'session') else {}
            except Exception:
                acc.headers = {}
            # Store TCP+version hints into extra
            try:
                eps = getattr(api, 'tcp_entries', None)
                if eps:
                    acc.extra['tcp_entries'] = list(eps)
                cv = getattr(api, 'client_version', None)
                if cv:
                    acc.extra['client_version'] = str(cv)
                cip = getattr(api, 'client_ip', None)
                if cip:
                    acc.extra['client_ip'] = str(cip)
            except Exception:
                pass
            self.new_account.emit(acc)
            self.log.emit(f"{Icons.SUCCESS} [FP] Зарегистрирован аккаунт: {username} (uid={acc.uid})")

            try:
                if regs_writer is not None:
                    import datetime
                    regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, 0, 'FishPoker', acc.uid or ''])
                    regs_file.flush()  # type: ignore[attr-defined]
            except Exception:
                pass

            success_total += 1
            processed_total += 1

            # close session
            try:
                if api is not None:
                    sess = getattr(api, 'session', None)
                    if sess is not None:
                        sess.close()
                    try:
                        self._live_apis.discard(api)
                    except Exception:
                        pass
            except Exception:
                pass

            self._sleep(self._rand_delay())

        try:
            if regs_file:
                regs_file.close()
        except Exception:
            pass
        self.log.emit(f"{Icons.SUCCESS if fail_total==0 else Icons.INFO} 🏁 Конец FishPoker: {processed_total}/{count} (успешно: {success_total}, ошибки: {fail_total})")

    def task_register_fishpoker_parallel(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, threads: int = 1, proxies_per_thread: int = 0, avatar_path: Optional[str] = None):
        """Параллельная регистрация FishPoker по общей очереди задач."""
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        try:
            threads = max(1, int(threads))
        except Exception:
            threads = 1
        if threads <= 1:
            return self.task_register_fishpoker(count, change_nick, change_avatar, words_file, reg_proxy, delay_min_ms, delay_max_ms, proxies, avatar_path)
        # jitter
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a: a, b = b, a
            self.jitter_ms = (max(0, a), max(0, b))
        except Exception:
            self.jitter_ms = (400, 900)
        import threading, queue
        import random
        # split proxies into per-thread groups
        proxies_all = [p.strip() for p in (proxies or []) if p and p.strip()]
        random.shuffle(proxies_all)
        ppt = max(0, int(proxies_per_thread))
        proxy_groups: list[list[str]] = []
        if ppt > 0 and proxies_all:
            it = iter(proxies_all)
            for _ in range(threads):
                grp = []
                for _k in range(ppt):
                    try:
                        grp.append(next(it))
                    except StopIteration:
                        break
                proxy_groups.append(grp)
        else:
            if proxies_all:
                chunk = (len(proxies_all) + threads - 1)//threads
                for i in range(threads):
                    s = i*chunk; e = min(len(proxies_all), (i+1)*chunk)
                    proxy_groups.append(proxies_all[s:e])
            else:
                proxy_groups = [[] for _ in range(threads)]

        # CSV log
        from pathlib import Path
        import csv
        regs_path = Path('logs')/"registrations.csv"
        regs_path.parent.mkdir(parents=True, exist_ok=True)
        regs_file = regs_path.open('a', encoding='utf-8', newline='')
        regs_writer = csv.writer(regs_file)
        try:
            if regs_path.stat().st_size == 0:
                regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        except Exception:
            pass
        csv_lock = threading.Lock()

        q: "queue.Queue[int]" = queue.Queue()
        for j in range(int(count)):
            q.put(j+1)

        counts_lock = threading.Lock()
        processed_total = 0
        success_total = 0
        fail_total = 0

        usernames_global: Set[str] = set()
        usernames_lock = threading.Lock()

        def worker_fn(wi: int, pgroup: list[str]):
            nonlocal processed_total, success_total, fail_total
            try:
                from core.credgen import CredGenerator
                from fishpoker.api import FishPokerAPI
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [T{wi}] Импорты недоступны: {e}")
                return
            gen = CredGenerator(words_file=words_file)
            proxy_idx = 0

            def _mk_nick(u: str) -> str:
                n = gen.derive_nick(u, min_len=6, max_len=20)
                try:
                    if (n or '').lower() == (u or '').lower():
                        import random
                        suf = str(random.randint(100, 9999))
                        base = n
                        if len(base) + len(suf) > 20:
                            base = base[: max(1, 20 - len(suf))]
                        n = (base + suf)[:20]
                except Exception:
                    pass
                return n

            def current_proxy() -> Optional[str]:
                nonlocal proxy_idx
                if not pgroup:
                    return reg_proxy
                p = pgroup[proxy_idx % len(pgroup)]
                proxy_idx += 1
                return p

            while not self._stop:
                try:
                    token = q.get_nowait()
                except queue.Empty:
                    break
                api = None
                try:
                    self._wait_if_paused()
                    # reserve unique username
                    while True:
                        cand = gen.generate_login(min_len=6, max_len=16)
                        with usernames_lock:
                            if cand not in usernames_global:
                                usernames_global.add(cand)
                                break
                    username = cand
                    nick = _mk_nick(username)
                    password = gen.generate_password(min_len=6, max_len=16)
                    device_id = self._fp_gen_device_id(username)

                    curp = current_proxy()
                    api = FishPokerAPI(proxy=curp)
                    try:
                        self._live_apis.add(api)
                    except Exception:
                        pass

                    # register (busy username retries)
                    reg_ok = False
                    reg_code = -999
                    reg_msg = ''
                    max_username_retries = 4
                    attempt = 0
                    while attempt <= max_username_retries and not reg_ok and not self._stop:
                        try:
                            rsp = api.register(username=username, password=password, device_id=device_id, country='CN')
                            reg_code = int(rsp.get('code', -1)) if isinstance(rsp, dict) else -1
                            reg_msg = str(rsp.get('msg', '') or '') if isinstance(rsp, dict) else ''
                        except Exception as e:
                            reg_code = -999
                            reg_msg = str(e)

                        if reg_code == 0:
                            reg_ok = True
                            break

                        busy = (reg_code == -1) or (reg_code == 10010008) or (
                            'username' in (reg_msg or '').lower() and (
                                'unavailable' in (reg_msg or '').lower() or 'exists' in (reg_msg or '').lower() or 'exist' in (reg_msg or '').lower()
                            )
                        )
                        if busy and attempt < max_username_retries:
                            old = username
                            # reserve new username
                            while True:
                                cand2 = gen.generate_login(min_len=6, max_len=16)
                                with usernames_lock:
                                    if cand2 not in usernames_global:
                                        usernames_global.add(cand2)
                                        break
                            username = cand2
                            nick = _mk_nick(username)
                            attempt += 1
                            self.log.emit(f"{Icons.WARNING} [T{wi}] [FP] Имя занято (code={reg_code}), новая попытка: {old} → {username} ({attempt}/{max_username_retries})")
                            self._sleep(self._rand_delay())
                            continue
                        break

                    if not reg_ok:
                        self.log.emit(f"{Icons.ERROR} [T{wi}] [FP] Регистрация отклонена: code={reg_code} msg={reg_msg}")
                        with counts_lock:
                            fail_total += 1
                            processed_total += 1
                        q.task_done()
                        self._sleep(self._rand_delay())
                        continue

                    # login (до 3 попыток на сетевых обрывах)
                    data = None
                    last_login_err = None
                    for att in range(1, 3 + 1):
                        if self._stop:
                            break
                        self._wait_if_paused()
                        try:
                            data = api.login(username=username, password=password, device_id=device_id, country='CN')
                            last_login_err = None
                            break
                        except Exception as e:
                            last_login_err = e
                            if self._stop:
                                break
                            s = str(e).lower()
                            transient = (
                                ("remotedisconnected" in s)
                                or ("remote end closed connection without response" in s)
                                or ("connection aborted" in s)
                                or ("connection reset" in s)
                                or ("proxyerror" in s)
                                or ("max retries exceeded" in s)
                                or ("read timed out" in s)
                                or ("connect timeout" in s)
                                or ("timed out" in s)
                                or ("bad gateway" in s)
                                or ("service unavailable" in s)
                                or ("gateway timeout" in s)
                            )
                            if transient and att < 3:
                                wait_s = 2.0 * att
                                try:
                                    self.log.emit(f"{Icons.WARNING} [T{wi}] [FP] Login: {e}. Повтор {att+1}/3 через {int(wait_s)}с…")
                                except Exception:
                                    pass
                                self._sleep(wait_s)
                                continue
                            break
                    if data is None:
                        if self._stop:
                            try:
                                q.task_done()
                            except Exception:
                                pass
                            break
                        self.log.emit(f"{Icons.ERROR} [T{wi}] [FP] Ошибка login: {last_login_err}")
                        with counts_lock:
                            fail_total += 1
                            processed_total += 1
                        q.task_done()
                        self._sleep(self._rand_delay())
                        continue

                    code = int(data.get('code', -1)) if isinstance(data, dict) else -1
                    if code != 0 or not getattr(api, 'token', None):
                        self.log.emit(f"{Icons.ERROR} [T{wi}] [FP] Login отклонён: code={code}")
                        with counts_lock:
                            fail_total += 1
                            processed_total += 1
                        q.task_done()
                        self._sleep(self._rand_delay())
                        continue


                    uid = api.get_uid_from_login_response(data)

                    # Перед сменой профиля (аватар/ник) дадим аккаунту "созреть"
                    if (uid and api.token) and ((change_avatar and avatar_path) or change_nick):
                        self._sleep(4.0)

                    # avatar (2 retries, 7s interval)
                    if change_avatar and avatar_path and uid and api.token:
                        max_avatar_attempts = 3
                        last_err = None
                        url = None
                        for att in range(1, max_avatar_attempts + 1):
                            if self._stop:
                                break
                            self._wait_if_paused()
                            try:
                                url = self._fp_upload_avatar(api, int(uid), avatar_path)
                                if url:
                                    self.log.emit(f"{Icons.INFO} [T{wi}] [FP] Аватар загружен: {url}")
                                    break
                            except Exception as e:
                                last_err = e
                            if att < max_avatar_attempts:
                                self._sleep(7.0)
                        if not url and last_err:
                            self.log.emit(f"{Icons.WARNING} [T{wi}] [FP] Аватар не загружен после {max_avatar_attempts} попыток: {last_err}")

                    # nick via TCP (2 retries, 7s interval)
                    if change_nick and uid and api.token:
                        # дополнительная пауза перед сменой ника
                        self._sleep(4.0)
                        max_nick_attempts = 3
                        okn = False
                        last_msg = ''
                        endpoints = list(getattr(api, 'tcp_entries', []) or [])
                        for att in range(1, max_nick_attempts + 1):
                            if self._stop:
                                break
                            self._wait_if_paused()
                            try:
                                okn, rsp = api.change_username_tcp(uid=int(uid), token=str(api.token), nickname=nick, endpoints=endpoints, cancel_event=self._cancel_event)
                                if okn:
                                    self.log.emit(f"{Icons.INFO} [T{wi}] [FP] Смена ника [{username}] → '{nick}': успех")
                                    break
                                last_msg = str(rsp)
                            except Exception as e:
                                last_msg = str(e)
                            if not okn and att < max_nick_attempts:
                                self._sleep(7.0)
                        if not okn:
                            self.log.emit(f"{Icons.WARNING} [T{wi}] [FP] Смена ника не удалась после {max_nick_attempts} попыток: {last_msg}")

                    acc = Account(username=username, password=password, device_id=device_id)
                    acc.proxy = api.proxy_url
                    acc.token = api.token
                    acc.uid = int(uid) if uid else None
                    acc.last_login_at = time.time()
                    try:
                        acc.headers = api.session.headers.copy() if hasattr(api, 'session') else {}
                    except Exception:
                        acc.headers = {}
                    try:
                        eps = getattr(api, 'tcp_entries', None)
                        if eps:
                            acc.extra['tcp_entries'] = list(eps)
                        cv = getattr(api, 'client_version', None)
                        if cv:
                            acc.extra['client_version'] = str(cv)
                        cip = getattr(api, 'client_ip', None)
                        if cip:
                            acc.extra['client_ip'] = str(cip)
                    except Exception:
                        pass

                    self.new_account.emit(acc)
                    self.log.emit(f"{Icons.SUCCESS} [T{wi}] [FP] Зарегистрирован аккаунт: {username} (uid={acc.uid})")

                    try:
                        with csv_lock:
                            import datetime
                            regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, 0, 'FishPoker', acc.uid or ''])
                            regs_file.flush()
                    except Exception:
                        pass

                    with counts_lock:
                        success_total += 1
                        processed_total += 1

                    q.task_done()
                except Exception as e:
                    try:
                        self.log.emit(f"{Icons.ERROR} [T{wi}] [FP] Ошибка регистрации: {e}")
                    except Exception:
                        pass
                    try:
                        with counts_lock:
                            fail_total += 1
                            processed_total += 1
                    except Exception:
                        pass
                    try:
                        q.task_done()
                    except Exception:
                        pass
                finally:
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                self._sleep(self._rand_delay())

        ths: list[threading.Thread] = []
        for i in range(int(threads)):
            pg = proxy_groups[i] if i < len(proxy_groups) else []
            t = threading.Thread(target=worker_fn, args=(i+1, pg), daemon=True)
            ths.append(t)
            t.start()
        for t in ths:
            t.join()
        try:
            regs_file.close()
        except Exception:
            pass
        icon = Icons.SUCCESS if fail_total == 0 else Icons.INFO
        self.log.emit(f"{icon} 🏁 Конец FishPoker: {processed_total}/{count} (успешно: {success_total}, ошибки: {fail_total})")

    def task_register_pppoker(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, avatar_path: Optional[str] = None):
        """Регистрация для PPPoker: по факту login создаёт нового пользователя.
        Для каждого аккаунта: HTTP login -> (опц.) HTTP upload avatar -> (опц.) TCP change nick -> emit new_account.
        """
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        # Настроим джиттер
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a: a,b = b,a
            self.jitter_ms = (max(0,a), max(0,b))
        except Exception:
            self.jitter_ms = (400,900)
        # Подготовим генератор
        try:
            from core.credgen import CredGenerator
        except Exception as e:
            self.log.emit(f"{Icons.ERROR} Не удалось импортировать генератор: {e}")
            return
        gen = CredGenerator(words_file=words_file)
        proxies = [p.strip() for p in (proxies or []) if p and p.strip()]
        proxy_count = len(proxies)
        proxy_idx = 0 if proxy_count>0 else -1
        used_usernames: Set[str] = set()
        # PPPoker: mark IP-limit proxies + remember recent -2 to treat fast -1 as ip-limit (desync)
        ip_limit_marked: Set[str] = set()
        recent_ip_until: Dict[str, float] = {}
        # Подготовим CSV лог так же, как для XPoker
        regs_file = None
        regs_writer = None
        try:
            from pathlib import Path
            import csv
            regs_path = Path('logs')/"registrations.csv"
            regs_path.parent.mkdir(parents=True, exist_ok=True)
            is_new = not regs_path.exists() or regs_path.stat().st_size == 0
            regs_file = regs_path.open('a', encoding='utf-8', newline='')
            regs_writer = csv.writer(regs_file)
            if is_new:
                regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        except Exception:
            regs_file = None
            regs_writer = None
        def current_proxy() -> Optional[str]:
            nonlocal proxy_idx
            if proxy_count == 0:
                return reg_proxy
            if proxy_count <= 0:
                return None
            # find next proxy not marked with IP limit
            for _ in range(proxy_count):
                p = proxies[proxy_idx]
                proxy_idx = (proxy_idx + 1) % proxy_count
                if p not in ip_limit_marked:
                    return p
            return None
        processed_total = 0
        success_total = 0
        fail_total = 0
        for i in range(int(count)):
            if self._stop:
                break
            # creds
            username = gen.generate_login(min_len=6, max_len=16)
            while username in used_usernames:
                username = gen.generate_login(min_len=6, max_len=16)
            used_usernames.add(username)
            nick = gen.derive_nick(username, min_len=6, max_len=20)
            password = gen.generate_password(min_len=6, max_len=16)
            # device id seed -> imei40
            import uuid
            seed = str(uuid.uuid4())
            imei = self._ppp_imei40(seed)
            self.log.emit(f"{Icons.PROCESS} [PP] Регистрация [{i+1}/{count}] {username}")
            # API register, then login (mirrors official client flow)
            try:
                from pppoker.api import PPPokerAPI, ApiError as PPPApiError
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} PPPoker API недоступен: {e}")
                break
            api = None
            curp = current_proxy()
            api = PPPokerAPI(proxy=curp)
            # preflight cookie (aliyungf_tc) как в клиенте
            try:
                api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
            except Exception:
                pass
            try:
                self._live_apis.add(api)
            except Exception:
                pass
            # username ретраи только при явной занятости имени; сетевые/лимит-IP → ротация прокси
            max_username_retries = 6
            max_net_retries = 6
            attempt = 0
            net_retry = 0
            reg_ok = False
            while attempt <= max_username_retries and not reg_ok:
                reg_code = -999
                reg_msg = ''
                try:
                    reg_rsp = api.register(username=username, password=password, device_id=imei)
                    reg_code = int(reg_rsp.get('code', -1)) if isinstance(reg_rsp, dict) else -1
                    reg_msg = str(reg_rsp.get('msg','')) if isinstance(reg_rsp, dict) else ''
                except Exception as e:
                    reg_code = -999
                    reg_msg = str(e)
                if reg_code == 0:
                    reg_ok = True
                    break
# Классификация PPPoker: -2 = IP limit; -1 = имя занято, но при быстром повторе после -2 может отражать IP limit (десинхрон)
                now_ts = time.time()
                is_ip_limit = (reg_code == -2) or (reg_code == -1 and curp and recent_ip_until.get(curp, 0) > now_ts)
                busy = (reg_code == -1) or (reg_code == 10010008) or ('username' in reg_msg.lower() and ('unavailable' in reg_msg.lower() or 'exists' in reg_msg.lower() or 'exist' in reg_msg.lower()))
                if is_ip_limit:
                    # помечаем прокси и ротируем, имя не меняем
                    if curp:
                        ip_limit_marked.add(curp)
                        recent_ip_until[curp] = now_ts + 15.0
                    try:
                        self.log.emit(f"{Icons.WARNING} [PP] Пометка прокси как 'Register IP Limit' (code={reg_code}). Смена прокси...")
                    except Exception:
                        pass
                    # Закрываем предыдущую HTTP-сессию перед ротацией
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    curp = current_proxy()
                    if not curp:
                        break
                    api = PPPokerAPI(proxy=curp)
                    try:
                        api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
                    except Exception:
                        pass
                    time.sleep(self._rand_delay())
                    continue
                hard = (reg_code in (10000044, 20010029, -999))
                if busy and attempt < max_username_retries:
                    old = username
                    username = gen.generate_login(min_len=6, max_len=16)
                    attempt += 1
                    self.log.emit(f"{Icons.WARNING} [PP] Имя занято (code={reg_code}). Новая попытка: {old} → {username} ({attempt}/{max_username_retries})")
                    time.sleep(self._rand_delay())
                    continue
                # сетевые/жёсткие ошибки → ротация прокси, username не меняем
                if hard and net_retry < max_net_retries:
                    try:
                        from core.api import mask_proxy_for_log as _mask
                        self.log.emit(f"{Icons.WARNING} [PP] Сетевая/лимит-IP ошибка (code={reg_code} msg={reg_msg}). Смена прокси...")
                    except Exception:
                        pass
                    # Закрываем предыдущую HTTP-сессию перед ротацией
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    curp = current_proxy()
                    api = PPPokerAPI(proxy=curp)
                    try:
                        api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
                    except Exception:
                        pass
                    net_retry += 1
                    time.sleep(self._rand_delay())
                    continue
                # иначе — окончательный отказ
                break
            if not reg_ok:
                self.log.emit(f"{Icons.ERROR} [PP] Регистрация отклонена окончательно")
                fail_total += 1; processed_total += 1
                time.sleep(self._rand_delay())
                continue
            # immediate login
            try:
                data = api.login(username=username, password=password, device_id=imei)
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [PP] Ошибка login после регистрации: {e}")
                fail_total += 1; processed_total += 1
                time.sleep(self._rand_delay())
                continue
            code = int(data.get('code', -1)) if isinstance(data, dict) else -1
            if code != 0 or not api.token:
                self.log.emit(f"{Icons.ERROR} [PP] Login отклонён: code={code}")
                fail_total += 1; processed_total += 1
                time.sleep(self._rand_delay())
                continue
            uid = api.get_uid_from_login_response(data)
            # Avatar via HTTP per-account (2 retries, 7s interval)
            if change_avatar and avatar_path and uid:
                max_avatar_attempts = 3  # 1 try + 2 retries
                last_err = None
                url = None
                for att in range(1, max_avatar_attempts + 1):
                    try:
                        url = self._ppp_upload_avatar(api, int(uid), avatar_path)
                        if url:
                            self.log.emit(f"{Icons.INFO} [PP] Аватар загружен: {url}")
                            break
                    except Exception as e:
                        last_err = e
                    if att < max_avatar_attempts:
                        try:
                            self.log.emit(f"{Icons.WARNING} [PP] Аватар: повторная попытка {att+1}/{max_avatar_attempts} через 7с")
                        except Exception:
                            pass
                        time.sleep(7)
                if not url:
                    if last_err:
                        self.log.emit(f"{Icons.WARNING} [PP] Аватар не загружен после {max_avatar_attempts} попыток: {last_err}")
                    else:
                        self.log.emit(f"{Icons.WARNING} [PP] Аватар не загружен после {max_avatar_attempts} попыток")
            # TCP change name (2 retries, 7s interval)
            if change_nick and uid and api.token:
                max_nick_attempts = 3
                okn = False
                last_msg = ''
                for att in range(1, max_nick_attempts + 1):
                    try:
                        from pppoker.client import PPPokerTCPClient
                        host = getattr(api, 'tcp_host', None) or 'ali-entry.pppoker.club'
                        port = int(getattr(api, 'tcp_port', None) or 4000)
                        tcp = PPPokerTCPClient(host=host, port=port, timeout=5.0, proxy=api.proxy_url)
                        try:
                            tcp.clientver = getattr(api, 'client_version', '4.2.41')
                        except Exception:
                            pass
                        try:
                            tcp.connect()
                            ok_login, msg = tcp.tcp_login(uid=int(uid), token=api.token, clientip='', entry_host=host, entry_port=port)
                            if not ok_login:
                                last_msg = f"tcp_login: {msg}"
                            else:
                                okn, rsp = tcp.change_username(nickname=nick)
                                if okn:
                                    self.log.emit(f"{Icons.INFO} [PP] Смена ника [{username}] → '{nick}': успех")
                                    break
                                else:
                                    last_msg = str(rsp)
                        except Exception as e:
                            last_msg = str(e)
                        finally:
                            try:
                                tcp.close()
                            except Exception:
                                pass
                    except Exception as e:
                        last_msg = str(e)
                    if not okn and att < max_nick_attempts:
                        try:
                            self.log.emit(f"{Icons.WARNING} [PP] Смена ника: повторная попытка {att+1}/{max_nick_attempts} через 7с ({last_msg})")
                        except Exception:
                            pass
                        time.sleep(7)
                if not okn:
                    self.log.emit(f"{Icons.WARNING} [PP] Смена ника не удалась после {max_nick_attempts} попыток: {last_msg}")
            # Emit account
            acc = Account(username=username, password=password, device_id=imei)
            acc.proxy = api.proxy_url
            acc.token = api.token
            acc.uid = int(uid) if uid else None
            acc.last_login_at = time.time()
            try:
                acc.headers = api.session.headers.copy() if hasattr(api, 'session') else {}
            except Exception:
                acc.headers = {}
            self.new_account.emit(acc)
            self.log.emit(f"{Icons.SUCCESS} [PP] Зарегистрирован аккаунт: {username} (uid={acc.uid})")
            # Запишем в общий CSV (как у XPoker) с пометкой PPPoker
            try:
                if regs_writer is not None:
                    import datetime
                    regs_writer.writerow([
                        datetime.datetime.utcnow().isoformat(),
                        username,
                        password,
                        nick,
                        imei,
                        0,
                        'PPPoker',
                        acc.uid or ''
                    ])
                    regs_file.flush()  # type: ignore[attr-defined]
            except Exception:
                pass
            success_total += 1
            processed_total += 1
            # Закрываем HTTP-сессию по окончании итерации
            try:
                if api is not None:
                    sess = getattr(api, 'session', None)
                    if sess is not None:
                        sess.close()
                    try:
                        self._live_apis.discard(api)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(self._rand_delay())
        # Закроем CSV
        try:
            if regs_file:
                regs_file.close()
        except Exception:
            pass
        self.log.emit(f"{Icons.SUCCESS if fail_total==0 else Icons.INFO} 🏁 Конец PPPoker: {processed_total}/{count} (успешно: {success_total}, ошибки: {fail_total})")

    def task_register_pppoker_parallel(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, threads: int = 1, proxies_per_thread: int = 0, avatar_path: Optional[str] = None):
        """Параллельная регистрация PPPoker по общей очереди задач (как XPoker)."""
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        try:
            threads = max(1, int(threads))
        except Exception:
            threads = 1
        if threads <= 1:
            return self.task_register_pppoker(count, change_nick, change_avatar, words_file, reg_proxy, delay_min_ms, delay_max_ms, proxies, avatar_path)
        # jitter
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a: a,b = b,a
            self.jitter_ms = (max(0,a), max(0,b))
        except Exception:
            self.jitter_ms = (400,900)
        import threading, queue, uuid
        # split proxies into per-thread groups
        proxies_all = [p.strip() for p in (proxies or []) if p and p.strip()]
        import random
        random.shuffle(proxies_all)
        ppt = max(0, int(proxies_per_thread))
        proxy_groups: list[list[str]] = []
        if ppt > 0 and proxies_all:
            it = iter(proxies_all)
            for _ in range(threads):
                grp = []
                for _k in range(ppt):
                    try:
                        grp.append(next(it))
                    except StopIteration:
                        break
                proxy_groups.append(grp)
        else:
            if proxies_all:
                chunk = (len(proxies_all) + threads - 1)//threads
                for i in range(threads):
                    s=i*chunk; e=min(len(proxies_all),(i+1)*chunk)
                    proxy_groups.append(proxies_all[s:e])
            else:
                proxy_groups = [[] for _ in range(threads)]
        # Подготовим CSV лог и общий лок, как в XPoker parallel
        from pathlib import Path
        import csv
        regs_path = Path('logs')/"registrations.csv"
        regs_path.parent.mkdir(parents=True, exist_ok=True)
        regs_file = regs_path.open('a', encoding='utf-8', newline='')
        regs_writer = csv.writer(regs_file)
        try:
            if regs_path.stat().st_size == 0:
                regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        except Exception:
            pass
        csv_lock = threading.Lock()
        # queue of jobs
        q: "queue.Queue[int]" = queue.Queue()
        for j in range(int(count)):
            q.put(j+1)
        counts_lock = threading.Lock()
        processed_total = 0
        success_total = 0
        fail_total = 0
        usernames_global: Set[str] = set()
        usernames_lock = threading.Lock()
        def worker_fn(wi: int, pgroup: list[str]):
            nonlocal processed_total, success_total, fail_total
            try:
                from core.credgen import CredGenerator
                from pppoker.api import PPPokerAPI
                from pppoker.client import PPPokerTCPClient
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [T{wi}] Импорты недоступны: {e}")
                return
            gen = CredGenerator(words_file=words_file)
            proxy_idx = 0
            ip_limit_local: Set[str] = set()
            def current_proxy() -> Optional[str]:
                nonlocal proxy_idx
                if not pgroup:
                    return reg_proxy
                # find next proxy in pgroup not marked IP-limit
                for _ in range(max(1, len(pgroup))):
                    p = pgroup[proxy_idx % len(pgroup)]; proxy_idx += 1
                    if p not in ip_limit_local:
                        return p
                return None
            while not self._stop:
                try:
                    token = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    # reserve unique username
                    while True:
                        cand = gen.generate_login(min_len=6, max_len=16)
                        with usernames_lock:
                            if cand not in usernames_global:
                                usernames_global.add(cand)
                                break
                    username = cand
                    nick = gen.derive_nick(username, min_len=6, max_len=20)
                    password = gen.generate_password(min_len=6, max_len=16)
                    imei = self._ppp_imei40(str(uuid.uuid4()))
                    api = None
                    curp = current_proxy()
                    api = PPPokerAPI(proxy=curp)
                    # preflight cookie (aliyungf_tc)
                    try:
                        api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
                    except Exception:
                        pass
                    # explicit register + login
                    reg_ok = False
                    max_username_retries = 4
                    max_net_retries = 6
                    attempt = 0
                    net_retry = 0
                    while attempt <= max_username_retries and not reg_ok:
                        reg_code = -999
                        reg_msg = ''
                        try:
                            reg_rsp = api.register(username=username, password=password, device_id=imei)
                            reg_code = int(reg_rsp.get('code', -1)) if isinstance(reg_rsp, dict) else -1
                            reg_msg = str(reg_rsp.get('msg','')) if isinstance(reg_rsp, dict) else ''
                        except Exception as e:
                            reg_code = -999
                            reg_msg = str(e)
                        if reg_code == 0:
                            reg_ok = True
                            break
                        now_ts = time.time()
                        is_ip_limit = (reg_code == -2) or (reg_code == -1 and curp and False)  # recent window handled via local mark
                        # treat -1 as username busy by default
                        busy = (reg_code == -1) or (reg_code == 10010008) or ('username' in reg_msg.lower() and ('unavailable' in reg_msg.lower() or 'exists' in reg_msg.lower() or 'exist' in reg_msg.lower()))
                        if is_ip_limit:
                            if curp:
                                ip_limit_local.add(curp)
                            try:
                                self.log.emit(f"{Icons.WARNING} [T{wi}] Пометка прокси как 'Register IP Limit' (code={reg_code}). Смена прокси...")
                            except Exception:
                                pass
                            # rotate proxy
                            curp = current_proxy()
                            # recreate API on new proxy
                            api = PPPokerAPI(proxy=curp)
                            try:
                                api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
                            except Exception:
                                pass
                            net_retry += 1
                            time.sleep(self._rand_delay())
                            continue
                        hard = (reg_code in (10000044, 20010029, -999))
                        if busy and attempt < max_username_retries:
                            old = username
                            # reserve new username
                            while True:
                                cand = gen.generate_login(min_len=6, max_len=16)
                                with usernames_lock:
                                    if cand not in usernames_global:
                                        usernames_global.add(cand)
                                        break
                            username = cand
                            attempt += 1
                            self.log.emit(f"{Icons.WARNING} [T{wi}] Имя занято (code={reg_code}), новая попытка: {old} → {username} ({attempt}/{max_username_retries})")
                            time.sleep(self._rand_delay())
                            continue
                        if hard and net_retry < max_net_retries:
                            try:
                                self.log.emit(f"{Icons.WARNING} [T{wi}] Сетевая/лимит-IP ошибка (code={reg_code} msg={reg_msg}). Смена прокси...")
                            except Exception:
                                pass
                            # Закрываем предыдущую HTTP-сессию перед ротацией
                            try:
                                if api is not None:
                                    sess = getattr(api, 'session', None)
                                    if sess is not None:
                                        sess.close()
                                    try:
                                        self._live_apis.discard(api)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            curp = current_proxy()
                            api = PPPokerAPI(proxy=curp)
                            try:
                                api.session.get('https://www.pppoker.club/', proxies=api.proxies, timeout=10)
                            except Exception:
                                pass
                            net_retry += 1
                            time.sleep(self._rand_delay())
                            continue
                        break
                    if not reg_ok:
                        self.log.emit(f"{Icons.ERROR} [T{wi}] Регистрация отклонена окончательно")
                        with counts_lock:
                            fail_total += 1; processed_total += 1
                        time.sleep(self._rand_delay())
                        q.task_done();
                        continue
                    data = api.login(username=username, password=password, device_id=imei)
                    code = int(data.get('code', -1)) if isinstance(data, dict) else -1
                    if code != 0 or not api.token:
                        self.log.emit(f"{Icons.ERROR} [T{wi}] Login отклонён: code={code}")
                        with counts_lock:
                            fail_total += 1; processed_total += 1
                        time.sleep(self._rand_delay())
                        q.task_done();
                        continue
                    uid = self.api_class().get_uid_from_login_response(data)
                    # avatar (2 retries, 7s interval)
                    if change_avatar and avatar_path and uid:
                        max_avatar_attempts = 3
                        last_err = None
                        url = None
                        for att in range(1, max_avatar_attempts + 1):
                            try:
                                url = self._ppp_upload_avatar(api, int(uid), avatar_path)
                                if url:
                                    self.log.emit(f"{Icons.INFO} [T{wi}] Аватар загружен: {url}")
                                    break
                            except Exception as e:
                                last_err = e
                            if att < max_avatar_attempts:
                                try:
                                    self.log.emit(f"{Icons.WARNING} [T{wi}] Аватар: повторная попытка {att+1}/{max_avatar_attempts} через 7с")
                                except Exception:
                                    pass
                                time.sleep(7)
                        if not url and last_err:
                            self.log.emit(f"{Icons.WARNING} [T{wi}] Аватар не загружен после {max_avatar_attempts} попыток: {last_err}")
                    # nick via TCP (2 retries, 7s interval)
                    if change_nick and uid and api.token:
                        max_nick_attempts = 3
                        okn = False
                        last_msg = ''
                        for att in range(1, max_nick_attempts + 1):
                            try:
                                host = getattr(api, 'tcp_host', None) or 'ali-entry.pppoker.club'
                                port = int(getattr(api, 'tcp_port', None) or 4000)
                                tcp = PPPokerTCPClient(host=host, port=port, timeout=5.0, proxy=api.proxy_url)
                                try:
                                    tcp.clientver = getattr(api, 'client_version', '4.2.41')
                                except Exception:
                                    pass
                                tcp.connect(); ok_login, msg = tcp.tcp_login(uid=int(uid), token=api.token, clientip='', entry_host=host, entry_port=port)
                                if ok_login:
                                    okn, rsp = tcp.change_username(nickname=nick)
                                    if okn:
                                        self.log.emit(f"{Icons.INFO} [T{wi}] Смена ника [{username}] → '{nick}': успех")
                                        tcp.close()
                                        break
                                    else:
                                        last_msg = str(rsp)
                                else:
                                    last_msg = f"tcp_login: {msg}"
                                tcp.close()
                            except Exception as e:
                                last_msg = str(e)
                            if not okn and att < max_nick_attempts:
                                try:
                                    self.log.emit(f"{Icons.WARNING} [T{wi}] Смена ника: повторная попытка {att+1}/{max_nick_attempts} через 7с ({last_msg})")
                                except Exception:
                                    pass
                                time.sleep(7)
                        if not okn:
                            self.log.emit(f"{Icons.WARNING} [T{wi}] Смена ника не удалась после {max_nick_attempts} попыток: {last_msg}")
                    acc = Account(username=username, password=password, device_id=imei)
                    acc.proxy = api.proxy_url; acc.token = api.token; acc.uid = int(uid) if uid else None; acc.last_login_at = time.time()
                    try:
                        acc.headers = api.session.headers.copy() if hasattr(api, 'session') else {}
                    except Exception:
                        acc.headers = {}
                    self.new_account.emit(acc)
                    self.log.emit(f"{Icons.SUCCESS} [T{wi}] Зарегистрирован аккаунт: {username} (uid={acc.uid})")
                    # CSV запись (PPPoker)
                    try:
                        with csv_lock:
                            import datetime
                            regs_writer.writerow([
                                datetime.datetime.utcnow().isoformat(),
                                username,
                                password,
                                nick,
                                imei,
                                0,
                                'PPPoker',
                                acc.uid or ''
                            ])
                            regs_file.flush()
                    except Exception:
                        pass
                    with counts_lock:
                        success_total += 1; processed_total += 1
                    time.sleep(self._rand_delay())
                except Exception as e:
                    self.log.emit(f"{Icons.ERROR} [T{wi}] Ошибка регистрации: {e}")
                finally:
                    # Закрываем HTTP-сессию по окончании обработки задачи
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        q.task_done()
                    except Exception:
                        pass
        ths = []
        for i in range(int(threads)):
            pg = proxy_groups[i] if i < len(proxy_groups) else []
            import threading
            t = threading.Thread(target=worker_fn, args=(i+1, pg), daemon=True)
            ths.append(t); t.start()
        for t in ths:
            t.join()
        try:
            regs_file.close()
        except Exception:
            pass
        icon = Icons.SUCCESS if fail_total==0 else Icons.INFO
        self.log.emit(f"{icon} 🏁 Конец PPPoker: {processed_total}/{count} (успешно: {success_total}, ошибки: {fail_total})")

    def task_register_accounts(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, avatar_path: Optional[str] = None):
        """Сгенерировать+зарегистрировать N аккаунтов, опционально сменить ник по TCP, добавить в таблицу.
        Работает последовательно. Задержка между шагами — случайная в заданном диапазоне.
        Поддержка списка прокси с ротацией при "жёстких" ошибках регистрации.
        """
        # Сброс сигнала остановки/паузы и очистка события отмены перед стартом задачи
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        # Настроим джиттер согласно параметрам
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a:
                a, b = b, a
            self.jitter_ms = (max(0, a), max(0, b))
        except Exception:
            self.jitter_ms = (400, 900)
        # Подготовим генератор кредов
        try:
            from core.credgen import CredGenerator
        except Exception as e:
            self.log.emit(f"{Icons.ERROR} Не удалось импортировать генератор: {e}")
            return
        gen = CredGenerator(words_file=words_file)
        import csv, datetime
        # Набор уже пробованных имён (локально за сессию)
        used_usernames: Set[str] = set()
        # Нормализуем список прокси
        proxies = [p.strip() for p in (proxies or []) if p and p.strip()]
        proxy_count = len(proxies)
        proxy_idx = 0 if proxy_count > 0 else -1
        # Прокси, выбывшие по лимиту IP (20010029) в рамках этой сессии (локально)
        ip_limit_marked: Set[str] = set()
        def _is_ip_limit(code: int, msg: str) -> bool:
            m = (msg or "").lower()
            return (code == 20010029) or ("register ip limit" in m)
        def current_proxy() -> Optional[str]:
            nonlocal proxy_idx
            # Если прокси выделены — выбираем ближайший не помеченный лимитом; иначе — используем общий reg_proxy
            if proxy_count > 0:
                if len(ip_limit_marked) >= proxy_count:
                    return None
                # Найти первый доступный, начиная с текущего индекса
                for _ in range(proxy_count):
                    p = proxies[proxy_idx]
                    if p not in ip_limit_marked:
                        return p
                    # иначе — шаг вперёд и продолжим поиск
                    proxy_idx = (proxy_idx + 1) % proxy_count
                return None
            return reg_proxy
        def _classify_reason(reason: str) -> str:
            r = (reason or "").lower()
            # Known server/business codes
            if "code=20010029" in reason or "register ip limit" in r:
                return "лимит регистраций по IP (20010029)"
            if "code=10000044" in reason or "accessdenied" in r or "access denied" in r:
                # Сообщение, аналогичное всплывашке клиента
                return "IP под угрозой — использование запрещено (10000044)"
            if "10010008" in reason or "username unavailable" in r:
                return "имя занято (10010008)"
            # HTTP/transport patterns
            if "too many 500" in r or "max retries exceeded" in r or "retry error" in r:
                return "серверные ошибки 5xx (нестабильность)"
            if "proxy error" in r or "proxy connect error" in r:
                return "ошибка прокси/соединения с прокси"
            if "connect timeout" in r or "read timed out" in r or "timed out" in r:
                return "таймаут соединения"
            if "connection error" in r:
                return "ошибка соединения"
            return reason
        def _shorten(s: str, lim: int = 160) -> str:
            try:
                s = str(s)
                return s if len(s) <= lim else (s[:lim-3] + "...")
            except Exception:
                return s
        def rotate_proxy(reason: str = "") -> None:
            nonlocal proxy_idx
            if proxy_count <= 1:
                return
            # сдвигаем указатель на следующий доступный не помеченный прокси
            for _ in range(proxy_count):
                proxy_idx = (proxy_idx + 1) % proxy_count
                cand = proxies[proxy_idx]
                if cand not in ip_limit_marked:
                    break
            try:
                from core.api import mask_proxy_for_log as _mask
                newp = current_proxy()
                masked = _mask(newp) if newp else "(нет)"
                friendly = _classify_reason(reason)
                if friendly and friendly != reason:
                    self.log.emit(f"{Icons.WARNING} Смена прокси [{proxy_idx+1}/{proxy_count}] — {friendly}. Новый: {masked}")
                else:
                    self.log.emit(f"{Icons.WARNING} Смена прокси [{proxy_idx+1}/{proxy_count}] из-за ошибки: {_shorten(reason)}. Новый: {masked}")
            except Exception:
                pass
        def is_username_busy(code: int, msg: str) -> bool:
            msg = (msg or "").lower()
            return code == 10010008 or "username unavailable" in msg
        def should_rotate_on(code: int, msg: str) -> bool:
            # Жёсткие отказы на уровне сервера / лимиты по IP
            m = (msg or "").lower()
            return (code in (10000044, 20010029)) or ("accessdenied" in m) or ("register ip limit" in m) or ("ip" in m and "limit" in m)
        # Подготовим файл логирования регистраций
        try:
            from pathlib import Path
            regs_path = Path('logs')/"registrations.csv"
            regs_path.parent.mkdir(parents=True, exist_ok=True)
            regs_file = regs_path.open('a', encoding='utf-8', newline='')
            regs_writer = csv.writer(regs_file)
            if regs_path.stat().st_size == 0:
                regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        except Exception:
            regs_file = None
            regs_writer = None
        # Подготовим общий URL аватара (однократная загрузка)
        avatar_url_common: Optional[str] = None
        if change_avatar and avatar_path:
            try:
                avatar_url_common = self._upload_avatar_tmpfiles(avatar_path)
                if avatar_url_common:
                    self.log.emit(f"{Icons.SUCCESS} Загружен аватар (tmpfiles): {avatar_url_common}")
                else:
                    self.log.emit(f"{Icons.WARNING} Не удалось загрузить аватар на tmpfiles — будет использован URL по умолчанию")
            except Exception as e:
                self.log.emit(f"{Icons.WARNING} Загрузка аватара не удалась: {e}")
                avatar_url_common = None
        # Счётчики прогресса
        processed_total = 0
        success_total = 0
        fail_total = 0
        finished_cause = ""
        for i in range(int(count)):
            if self._stop:
                finished_cause = "Остановлено пользователем"
                break
            api = None
            try:
                # Генерируем логин/ник/пароль (логин можно ретраить при 10010008)
                username = gen.generate_login(min_len=8, max_len=16)
                while username in used_usernames:
                    username = gen.generate_login(min_len=8, max_len=16)
                used_usernames.add(username)
                nick = gen.derive_nick(username, min_len=6, max_len=20)
                password = gen.generate_password(min_len=6, max_len=16)
                # device_id для X-Poker — UUID4
                import uuid
                device_id = str(uuid.uuid4())
                self.log.emit(f"{Icons.PROCESS} Регистрация [{i+1}/{count}] {username}")
                # Параметры ретраев
                max_username_retries = 10
                username_attempt = 0
                uid = None
                code = -1
                msg = ''
                data = {}
                # Выбор текущего прокси (учитывая пометки IP Limit)
                curp = current_proxy()
                if proxy_count > 0 and curp is None:
                    # Все прокси в списке помечены лимитом ip — прекращаем дальнейшие попытки
                    self.log.emit(f"{Icons.WARNING} Все прокси помечены как 'Register IP Limit' — пропускаем оставшиеся регистрации")
                    # прерываем внешний цикл по аккаунтам
                    break
                api = self.api_class(proxy=curp)
                try:
                    self._live_apis.add(api)
                except Exception:
                    pass
                # UI: покажем, через какой прокси идёт HTTP (маскируем пароль)
                try:
                    from core.api import mask_proxy_for_log as _mask
                    if curp:
                        self.log.emit(f"{Icons.INFO} HTTP через прокси: {_mask(curp)}")
                    else:
                        self.log.emit(f"{Icons.INFO} HTTP без прокси")
                except Exception:
                    pass
                # Внутренний цикл: пытаемся регистрировать, при нужных ошибках — ротация прокси (не меняя username)
                rotated = 0
                while True:
                    # Ограничение на полные круги по прокси, чтобы не зациклиться
                    if rotated > proxy_count and proxy_count > 0:
                        break
                    try:
                        data = api.register(username=username, password=password, device_id=device_id)
                        code = int(data.get('code', -1)) if isinstance(data, dict) else -1
                        msg = str(data.get('msg', '')) if isinstance(data, dict) else ''
                    except self.api_error_class as e:
                        # Ошибка уровня сети/прокси — пробуем ротацию
                        code = -1
                        msg = str(e)
                        # Если это серия серверных 5xx (исчерпаны ретраи) — делаем паузу 60с перед повторами
                        try:
                            mlow = (msg or "").lower()
                            if ("too many 500" in mlow) or ("max retries exceeded" in mlow) or ("retry error" in mlow):
                                self.log.emit(f"{Icons.WARNING} Серверные 5xx — исчерпаны повторы (2 шт, задержка ≈3с). Пауза 20с перед следующей попыткой")
                                for _ in range(20):
                                    if self._stop:
                                        break
                                    time.sleep(1.0)
                        except Exception:
                            pass
                        if proxy_count > 0:
                            rotate_proxy(msg)
                            # Закрываем предыдущую HTTP-сессию перед ротацией
                            try:
                                if api is not None:
                                    sess = getattr(api, 'session', None)
                                    if sess is not None:
                                        sess.close()
                                    try:
                                        self._live_apis.discard(api)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            api = self.api_class(proxy=current_proxy())
                            try:
                                self._live_apis.add(api)
                            except Exception:
                                pass
                            rotated += 1
                            time.sleep(self._rand_delay())
                            continue
                        else:
                            # Без прокси — считаем фатально для этой попытки
                            break
                    except Exception as e:
                        code = -1
                        msg = str(e)
                        # Если получили исчерпание ретраев (частые 500/429) — пауза 60с и, при наличии, смена прокси
                        mlow = (msg or "").lower()
                        if ("max retries exceeded" in mlow or "too many 500" in mlow or "retry error" in mlow):
                            try:
                                self.log.emit(f"{Icons.WARNING} Серверные 5xx — исчерпаны повторы (2 шт, задержка ≈3с). Пауза 20с перед следующей попыткой")
                                for _ in range(20):
                                    if self._stop:
                                        break
                                    time.sleep(1.0)
                            except Exception:
                                pass
                            if proxy_count > 0:
                                rotate_proxy(f"{msg}")
                                # Закрываем предыдущую HTTP-сессию перед ротацией
                                try:
                                    if api is not None:
                                        sess = getattr(api, 'session', None)
                                        if sess is not None:
                                            sess.close()
                                        try:
                                            self._live_apis.discard(api)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                                api = self.api_class(proxy=current_proxy())
                                try:
                                    self._live_apis.add(api)
                                except Exception:
                                    pass
                                rotated += 1
                                time.sleep(self._rand_delay())
                                continue
                        break
                    # Успех
                    if code == 0:
                        break
                    # Имя занято — меняем имя, НЕ меняем прокси
                    if is_username_busy(code, msg):
                        if username_attempt + 1 >= max_username_retries:
                            self.log.emit(f"{Icons.ERROR} Слишком много коллизий имени для {username} — пропускаем")
                            break
                        old_username = username
                        try:
                            used_usernames.add(old_username)
                        except Exception:
                            pass
                        # Увеличиваем длину/уникальность с каждой попыткой
                        username = gen.generate_login(min_len=min(16, 8 + username_attempt), max_len=16)
                        while username in used_usernames:
                            username = gen.generate_login(min_len=min(16, 8 + username_attempt), max_len=16)
                        used_usernames.add(username)
                        nick = gen.derive_nick(username, min_len=6, max_len=20)
                        username_attempt += 1
                        self.log.emit(f"{Icons.WARNING} Имя занято: {old_username} → новая попытка: {username} ({username_attempt}/{max_username_retries})")
                        # остаёмся на том же прокси, пауза
                        time.sleep(self._rand_delay())
                        continue
                    # Жёсткая ошибка — пробуем сменить прокси (если есть)
                    if proxy_count > 0 and should_rotate_on(code, msg):
                        # Помечаем прокси, если это именно лимит IP
                        if _is_ip_limit(code, msg) and curp:
                            try:
                                ip_limit_marked.add(curp)
                                from core.api import mask_proxy_for_log as _mask
                                self.log.emit(f"{Icons.INFO} Пометка прокси как 'Register IP Limit': {_mask(curp)} — будет пропускаться")
                            except Exception:
                                pass
                        rotate_proxy(f"code={code} msg={msg}")
                        curp = current_proxy()
                        if curp is None:
                            self.log.emit(f"{Icons.WARNING} Все прокси помечены как 'Register IP Limit' — прекращаем попытку")
                            break
                        # Закрываем предыдущую HTTP-сессию перед ротацией
                        try:
                            if api is not None:
                                sess = getattr(api, 'session', None)
                                if sess is not None:
                                    sess.close()
                                try:
                                    self._live_apis.discard(api)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        api = self.api_class(proxy=curp)
                        rotated += 1
                        time.sleep(self._rand_delay())
                        continue
                    # Прочая ошибка — выходим
                    break
                # Лог в CSV (итог)
                try:
                    if regs_writer:
                        regs_writer.writerow([
                            datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, code, msg, ''
                        ])
                        regs_file.flush()
                except Exception:
                    pass
                if code != 0:
                    fail_total += 1
                    processed_total += 1
                    # Более понятная причина вместо raw code/msg
                    reason_h = _classify_reason(f"code={code} {msg}")
                    self.log.emit(f"{Icons.ERROR} Регистрация {username} отклонена: {reason_h}")
                    time.sleep(self._rand_delay())
                    continue
                # Пытаемся извлечь uid и токен
                uid = api.get_uid_from_login_response(data)
                if not api.token:
                    try:
                        data_login = api.login(username=username, password=password, device_id=device_id)
                        uid = uid or api.get_uid_from_login_response(data_login)
                    except Exception as e:
                        self.log.emit(f"{Icons.ERROR} Повторный login после регистрации не удался: {e}")
                # Смена ника и/или аватара по TCP (в зависимости от настроек) с ретраями и ротацией endpoint'ов
                if (change_nick or change_avatar) and api.token and uid:
                    from core.constants import CLUB_SERVER_HOST, CLUB_SERVER_PORT, DEFAULT_AVATAR_URLS
                    # Подготовим список TCP endpoint'ов из HTTP-ответа; иначе — дефолт
                    endpoints: list[tuple[str,int]] = []
                    try:
                        eps = list(getattr(api, 'tcp_entries', []) or [])
                        for ep in eps:
                            try:
                                h, p = ep
                                endpoints.append((str(h), int(p or 5000)))
                            except Exception:
                                pass
                    except Exception:
                        endpoints = []
                    if not endpoints:
                        host = getattr(api, 'tcp_host', None) or CLUB_SERVER_HOST
                        port = int(getattr(api, 'tcp_port', None) or CLUB_SERVER_PORT)
                        endpoints = [(host, port)]
                    # URL аватарки (если требуется)
                    avatar_url = None
                    if change_avatar:
                        if avatar_url_common:
                            avatar_url = avatar_url_common
                        else:
                            try:
                                avatar_url = DEFAULT_AVATAR_URLS[0] if DEFAULT_AVATAR_URLS else None
                            except Exception:
                                avatar_url = None
                        if not avatar_url:
                            self.log.emit(f"{Icons.INFO} Смена аватара [{username}]: пропущено (нет URL)")
                    # Ретраи TCP: ровно 3 попытки (1 + 2 ретрая), 7с пауза, с ротацией endpoint'ов
                    max_attempts = 3
                    ok_name = (not change_nick)
                    ok_av = (not change_avatar) or (avatar_url is None)
                    for attempt_n in range(1, max_attempts+1):
                        if self._stop:
                            break
                        ehost, eport = endpoints[(attempt_n-1) % len(endpoints)]
                        fallbacks = [ep for ep in endpoints if ep != (ehost, eport)]
                        tcp = None
                        try:
                            self.log.emit(f"{Icons.PROCESS} TCP попытка {attempt_n}/{max_attempts} для [{username}] через {ehost}:{eport}")
                            tcp = XClubTCPClient(host=ehost, port=eport, timeout=4.5, proxy=api.proxy_url, disable_bootstrap=True, frida_strict=True, fallback_endpoints=fallbacks)
                            try:
                                tcp.set_cancel_event(self._cancel_event)
                            except Exception:
                                pass
                            try:
                                self._live_tcps.add(tcp)
                            except Exception:
                                pass
                            # connect
                            try:
                                tcp.connect()
                            except socket.timeout as e:
                                raise RuntimeError(f"tcp_connect: timed out ({e})")
                            except Exception as e:
                                raise RuntimeError(f"tcp_connect: {e}")
                            # login
                            try:
                                _ = tcp.tcp_login(uid=int(uid), token=api.token)
                            except socket.timeout as e:
                                raise RuntimeError(f"tcp_login: timed out ({e})")
                            except Exception as e:
                                raise RuntimeError(f"tcp_login: {e}")
                            # change name
                            if change_nick and not ok_name:
                                try:
                                    ok, cmsg = tcp.change_name(nick)
                                except socket.timeout as e:
                                    ok, cmsg = False, f"tcp_change_name: timed out ({e})"
                                except Exception as e:
                                    ok, cmsg = False, f"tcp_change_name: {e}"
                                self.log.emit(f"{Icons.INFO} Смена ника [{username}] → '{nick}': {'успех' if ok else cmsg}")
                                ok_name = ok or ok_name
                            # change avatar
                            if change_avatar and avatar_url and not ok_av:
                                try:
                                    ok_av1, msg_av = tcp.change_avatar(avatar_url)
                                except socket.timeout as e:
                                    ok_av1, msg_av = False, f"tcp_change_avatar: timed out ({e})"
                                except Exception as e:
                                    ok_av1, msg_av = False, f"tcp_change_avatar: {e}"
                                self.log.emit(f"{Icons.INFO} Смена аватара [{username}] → '{avatar_url}': {'успех' if ok_av1 else msg_av}")
                                ok_av = ok_av1 or ok_av
                            if ok_name and ok_av:
                                break
                        except Exception as e:
                            self.log.emit(f"{Icons.WARNING} TCP попытка {attempt_n}/{max_attempts} для [{username}] не удалась: {e}")
                        finally:
                            try:
                                if tcp is not None:
                                    tcp.close()
                                try:
                                    if tcp is not None:
                                        self._live_tcps.discard(tcp)
                                except Exception:
                                    pass
                            except Exception:
                                pass
                        # Пауза между повторами
                        time.sleep(7)
                    if not (ok_name and ok_av):
                        self.log.emit(f"{Icons.WARNING} Не удалось полностью применить TCP-изменения для [{username}] (ник={'ok' if ok_name else 'fail'}, аватар={'ok' if ok_av else 'fail'})")
                # Создаём Account и отдаём в UI
                acc = Account(username=username, password=password, device_id=device_id)
                acc.proxy = api.proxy_url
                acc.token = api.token
                acc.refresh_token = api.refresh_token
                acc.access_token_expire = api.access_token_expire
                acc.refresh_token_expire = api.refresh_token_expire
                acc.uid = int(uid) if uid else None
                acc.last_login_at = time.time()
                try:
                    acc.headers = api.session.headers.copy() if hasattr(api, 'session') else {}
                except Exception:
                    acc.headers = {}
                # Обновим CSV uid (допишем success)
                try:
                    if regs_writer:
                        regs_writer.writerow([
                            datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, 0, 'Success', acc.uid or ''
                        ])
                        regs_file.flush()
                except Exception:
                    pass
                self.log.emit(f"{Icons.SUCCESS} Зарегистрирован аккаунт: {username} (uid={acc.uid})")
                self.new_account.emit(acc)
                success_total += 1
                processed_total += 1
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} Ошибка на шаге регистрации: {e}")
            finally:
                # Закрываем HTTP-сессию (если создавалась) по окончании итерации
                try:
                    if api is not None:
                        sess = getattr(api, 'session', None)
                        if sess is not None:
                            sess.close()
                        try:
                            self._live_apis.discard(api)
                        except Exception:
                            pass
                except Exception:
                    pass
            time.sleep(self._rand_delay())
        try:
            if regs_file:
                regs_file.close()
        except Exception:
            pass
        # Финальный отчёт
        try:
            total_target = int(count)
        except Exception:
            total_target = 0
        if not finished_cause:
            if proxy_count > 0 and len(ip_limit_marked) >= proxy_count:
                finished_cause = "Все прокси помечены как 'Register IP Limit'"
            else:
                finished_cause = "Все задачи выполнены"
        icon = Icons.SUCCESS if processed_total >= total_target and finished_cause == "Все задачи выполнены" else Icons.WARNING if "Register IP Limit" in finished_cause else Icons.INFO
        self.log.emit(f"{icon} 🏁 Конец: {finished_cause}. Прогресс: {processed_total}/{total_target} (успешно: {success_total}, ошибки: {fail_total})")


    def task_register_accounts_parallel(self, count: int, change_nick: bool = True, change_avatar: bool = True, words_file: Optional[str] = None, reg_proxy: Optional[str] = None, delay_min_ms: int = 400, delay_max_ms: int = 900, proxies: Optional[List[str]] = None, threads: int = 1, proxies_per_thread: int = 0, avatar_path: Optional[str] = None):
        """Параллельная регистрация аккаунтов с разбиением по потокам и спискам прокси.
        - threads: количество потоков (>=1)
        - proxies_per_thread: сколько прокси выделить на поток (0 = авто-деление)
        Прочая логика (ретраи, CSV, смена ника/аватара, cooldown на 5xx) совпадает с последовательной.
        """
        # Сброс сигнала остановки/паузы и очистка события отмены перед стартом задачи
        try:
            self._stop = False
            if getattr(self, "_pause", False):
                self._pause = False
                try:
                    self.pause_changed.emit(False)
                except Exception:
                    pass
            if hasattr(self, "_cancel_event"):
                self._cancel_event.clear()
        except Exception:
            pass
        try:
            threads = max(1, int(threads))
        except Exception:
            threads = 1
        # Если один поток — используем стандартную последовательную реализацию
        if threads <= 1:
            return self.task_register_accounts(count, change_nick, change_avatar, words_file, reg_proxy, delay_min_ms, delay_max_ms, proxies)
        # Установим общий джиттер
        try:
            a = int(delay_min_ms); b = int(delay_max_ms)
            if b < a: a,b = b,a
            self.jitter_ms = (max(0,a), max(0,b))
        except Exception:
            self.jitter_ms = (400,900)
        import threading
        from pathlib import Path
        # Подготовим CSV writer один раз и общий лок
        regs_path = Path('logs')/"registrations.csv"
        regs_path.parent.mkdir(parents=True, exist_ok=True)
        regs_file = regs_path.open('a', encoding='utf-8', newline='')
        import csv, datetime, random
        regs_writer = csv.writer(regs_file)
        if regs_path.stat().st_size == 0:
            regs_writer.writerow(["ts","username","password","nick","device_id","code","msg","uid"])
        csv_lock = threading.Lock()
        # Разобьём количество по потокам
        total = int(count)
        base = total // threads
        rem = total % threads
        counts = [base + (1 if i < rem else 0) for i in range(threads)]
        # Подготовим группы прокси
        proxies_all = [p.strip() for p in (proxies or []) if p and p.strip()]
        random.shuffle(proxies_all)
        ppt = max(0, int(proxies_per_thread))
        proxy_groups: list[list[str]] = []
        if ppt > 0 and proxies_all:
            # Уникальное распределение без повторов между потоками
            n = len(proxies_all)
            needed = threads * ppt
            if n < needed:
                try:
                    self.log.emit(f"{Icons.WARNING} Прокси меньше, чем требуется ({n} < {needed}); распределяем без повторов, часть потоков получит меньше прокси")
                except Exception:
                    pass
            it = iter(proxies_all)
            for i in range(threads):
                grp = []
                for k in range(ppt):
                    try:
                        grp.append(next(it))
                    except StopIteration:
                        break
                proxy_groups.append(grp)
        else:
            # Авто-деление: равномерные чанки (также без повторов между потоками)
            if proxies_all:
                chunk = (len(proxies_all) + threads - 1)//threads
                for i in range(threads):
                    s = i*chunk; e = min(len(proxies_all), (i+1)*chunk)
                    proxy_groups.append(proxies_all[s:e])
            else:
                proxy_groups = [[] for _ in range(threads)]
        # Однократная загрузка аватара для всех потоков (если нужно)
        avatar_url_common: Optional[str] = None
        if change_avatar and avatar_path:
            try:
                avatar_url_common = self._upload_avatar_tmpfiles(avatar_path)
                if avatar_url_common:
                    self.log.emit(f"{Icons.SUCCESS} [AVATAR] Загружен на tmpfiles: {avatar_url_common}")
            except Exception as e:
                self.log.emit(f"{Icons.WARNING} [AVATAR] Не удалось загрузить аватар: {e}")
        # Глобальная пометка IP Limit прокси (на случай дубликатов между группами)
        import threading, queue
        ip_limit_global: Set[str] = set()
        ip_lock = threading.Lock()
        # Глобальный набор уже занятых/использованных имён пользователя, чтобы не генерить повторно между потоками
        usernames_global: Set[str] = set()
        usernames_lock = threading.Lock()
        def _global_mark_ip_limit(p: Optional[str]):
            if not p: return
            try:
                with ip_lock:
                    ip_limit_global.add(p)
            except Exception:
                pass
        def _global_is_marked(p: Optional[str]) -> bool:
            if not p: return False
            try:
                with ip_lock:
                    return p in ip_limit_global
            except Exception:
                return False
        # Общая очередь задач (динамическое перераспределение)
        job_queue: "queue.Queue[int]" = queue.Queue()
        total = int(count)
        for j in range(total):
            job_queue.put(j+1)
            # Глобальные счётчики прогресса
        counts_lock = threading.Lock()
        processed_total = 0
        success_total = 0
        fail_total = 0
        # Внутренняя функция — одна рабочая нить (вытягивает задачи из общей очереди)
        def worker_fn(worker_idx: int, pgroup: list[str], q: "queue.Queue[int]"):
            nonlocal processed_total, success_total, fail_total
            # Локальный генератор
            try:
                from core.credgen import CredGenerator
                gen = CredGenerator(words_file=words_file)
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [T{worker_idx}] Генератор недоступен: {e}")
                return
            # Индексы по прокси и пометки лимита
            proxy_count = len(pgroup)
            proxy_idx = 0 if proxy_count>0 else -1
            ip_limit_local: Set[str] = set()
            def current_proxy() -> Optional[str]:
                nonlocal proxy_idx
                # Если группа пуста — используем общий reg_proxy; иначе ищем не помеченный локально/глобально
                if proxy_count == 0:
                    return reg_proxy
                if len(ip_limit_local) >= proxy_count:
                    return None
                for _ in range(proxy_count):
                    p = pgroup[proxy_idx]
                    if p not in ip_limit_local and not _global_is_marked(p):
                        return p
                    # иначе — шаг вперёд
                    proxy_idx = (proxy_idx + 1) % proxy_count
                return None
            def rotate_proxy_local(reason: str = "") -> None:
                nonlocal proxy_idx
                if proxy_count <= 1:
                    return
                for _ in range(proxy_count):
                    proxy_idx = (proxy_idx + 1) % proxy_count
                    cand = pgroup[proxy_idx]
                    if cand not in ip_limit_local and not _global_is_marked(cand):
                        break
                try:
                    from core.api import mask_proxy_for_log as _mask
                    newp = current_proxy()
                    masked = _mask(newp) if newp else "(нет)"
                    self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Смена прокси [{proxy_idx+1}/{proxy_count}] — {reason}. Новый: {masked}")
                except Exception:
                    pass
            def is_username_busy(code: int, msg: str) -> bool:
                m = (msg or "").lower()
                return code == 10010008 or "username unavailable" in m
            def should_rotate_on(code: int, msg: str) -> bool:
                m = (msg or "").lower()
                return (code in (10000044, 20010029)) or ("accessdenied" in m) or ("register ip limit" in m)
            def _is_ip_limit(code: int, msg: str) -> bool:
                m = (msg or "").lower()
                return (code == 20010029) or ("register ip limit" in m)
            done_local = 0
            # Локальный набор тоже, чтобы избежать лишних попыток внутри потока
            used_local: Set[str] = set()
            while not self._stop:
                try:
                    token = q.get_nowait()
                except queue.Empty:
                    break
                requeue_token = False
                api = None
                try:
                    # Сначала резервируем уникальное имя глобально
                    while True:
                        candidate = gen.generate_login(min_len=8, max_len=16)
                        with usernames_lock:
                            if candidate not in usernames_global:
                                usernames_global.add(candidate)
                                break
                    username = candidate
                    used_local.add(username)
                    nick = gen.derive_nick(username, min_len=6, max_len=20)
                    password = gen.generate_password(min_len=6, max_len=16)
                    import uuid
                    device_id = str(uuid.uuid4())
                    self.log.emit(f"{Icons.PROCESS} [T{worker_idx}] Регистрация [{done_local+1}] {username}")
                    max_username_retries = 5
                    username_attempt = 0
                    code = -1; msg = ''
                    uid = None
                    data = {}
                    # Выбор прокси с учётом пометок
                    curp = current_proxy()
                    if proxy_count>0 and curp is None:
                        # Все прокси в группе выведены из работы — возвращаем задачу и завершаем поток
                        self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Все прокси помечены как 'Register IP Limit' — поток завершает работу, задача будет передана другим потокам")
                        requeue_token = True
                        break
                    api = self.api_class(proxy=curp)

                    try:
                        self._live_apis.add(api)
                    except Exception:
                        pass
                    # UI: прокси для потока
                    try:
                        from core.api import mask_proxy_for_log as _mask
                        if curp:
                            self.log.emit(f"{Icons.INFO} [T{worker_idx}] HTTP через прокси: {_mask(curp)}")
                        else:
                            self.log.emit(f"{Icons.INFO} [T{worker_idx}] HTTP без прокси")
                    except Exception:
                        pass
                    rotated = 0
                    while True:
                        if rotated > proxy_count and proxy_count>0:
                            break
                        try:
                            data = api.register(username=username, password=password, device_id=device_id)
                            code = int(data.get('code', -1)) if isinstance(data, dict) else -1
                            msg = str(data.get('msg','')) if isinstance(data, dict) else ''
                        except self.api_error_class as e:
                            code = -1; msg = str(e)
                            mlow = (msg or "").lower()
                            if ("too many 500" in mlow) or ("max retries exceeded" in mlow) or ("retry error" in mlow):
                                self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Серверные 5xx — исчерпаны повторы (2 шт, задержка ≈3с). Пауза 20с")
                                for _ in range(20):
                                    if self._stop: break
                                    time.sleep(1.0)
                            if proxy_count>0:
                                rotate_proxy_local(msg)
                                curp = current_proxy()
                                # Закрываем предыдущую HTTP-сессию перед ротацией
                                try:
                                    if api is not None:
                                        sess = getattr(api, 'session', None)
                                        if sess is not None:
                                            sess.close()
                                        try:
                                            self._live_apis.discard(api)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                                api = self.api_class(proxy=curp)
                                try:
                                    self._live_apis.add(api)
                                except Exception:
                                    pass
                                rotated += 1
                                time.sleep(self._rand_delay())
                                continue
                            else:
                                break
                        except Exception as e:
                            code = -1; msg = str(e)
                            mlow = (msg or "").lower()
                            if ("too many 500" in mlow) or ("max retries exceeded" in mlow) or ("retry error" in mlow):
                                self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Серверные 5xx — исчерпаны повторы (2 шт, задержка ≈3с). Пауза 20с")
                                for _ in range(20):
                                    if self._stop: break
                                    time.sleep(1.0)
                                if proxy_count>0:
                                    rotate_proxy_local(msg)
                                    curp = current_proxy()
                                    # Закрываем предыдущую HTTP-сессию перед ротацией
                                    try:
                                        if api is not None:
                                            sess = getattr(api, 'session', None)
                                            if sess is not None:
                                                sess.close()
                                            try:
                                                self._live_apis.discard(api)
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                                    api = self.api_class(proxy=curp)
                                    try:
                                        self._live_apis.add(api)
                                    except Exception:
                                        pass
                                    rotated += 1
                                    time.sleep(self._rand_delay())
                                    continue
                            break
                        if code == 0:
                            break
                        if is_username_busy(code, msg):
                            if username_attempt + 1 >= max_username_retries:
                                self.log.emit(f"{Icons.ERROR} [T{worker_idx}] Слишком много коллизий имени для {username} — пропускаем задачу")
                                break
                            old_username = username
                            try:
                                with usernames_lock:
                                    usernames_global.add(old_username)
                                used_local.add(old_username)
                            except Exception:
                                pass
                            # Эскалация длины/уникальности с каждой попыткой
                            while True:
                                candidate = gen.generate_login(min_len=min(16, 8 + username_attempt), max_len=16)
                                with usernames_lock:
                                    if candidate not in usernames_global:
                                        usernames_global.add(candidate)
                                        break
                            username = candidate
                            used_local.add(username)
                            nick = gen.derive_nick(username, min_len=6, max_len=20)
                            username_attempt += 1
                            self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Имя занято: {old_username} → новая попытка: {username} ({username_attempt}/{max_username_retries})")
                            time.sleep(self._rand_delay())
                            continue
                        if proxy_count > 0 and should_rotate_on(code, msg):
                            # Если это лимит IP — помечаем локально и глобально
                            if _is_ip_limit(code, msg) and curp:
                                try:
                                    ip_limit_local.add(curp)
                                    _global_mark_ip_limit(curp)
                                    from core.api import mask_proxy_for_log as _mask
                                    self.log.emit(f"{Icons.INFO} [T{worker_idx}] Пометка прокси как 'Register IP Limit': {_mask(curp)} — будет пропускаться в этом и других потоках")
                                except Exception:
                                    pass
                            rotate_proxy_local(f"code={code} msg={msg}")
                            curp = current_proxy()
                            if proxy_count>0 and curp is None:
                                # Все прокси выведены — ре-доставим задачу в очередь и завершим поток
                                requeue_token = True
                                self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Все прокси помечены как 'Register IP Limit' — задача будет передана другим потокам")
                                break
                            # Закрываем предыдущую HTTP-сессию перед ротацией
                            try:
                                if api is not None:
                                    sess = getattr(api, 'session', None)
                                    if sess is not None:
                                        sess.close()
                                    try:
                                        self._live_apis.discard(api)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            api = self.api_class(proxy=curp)
                            rotated += 1
                            time.sleep(self._rand_delay())
                            continue
                        break
                    # Запись результата
                    try:
                        with csv_lock:
                            regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, code, msg, ''])
                            regs_file.flush()
                    except Exception:
                        pass
                    if code != 0:
                        # Более понятная причина вместо raw code/msg
                        try:
                            reason_h = _classify_reason(f"code={code} {msg}")
                        except Exception:
                            reason_h = f"code={code} {msg}"
                        self.log.emit(f"{Icons.ERROR} [T{worker_idx}] Регистрация {username} отклонена: {reason_h}")
                        # задача считается выполненной (попытка была), не возвращаем в очередь
                        with counts_lock:
                            fail_total += 1
                            processed_total += 1
                        time.sleep(self._rand_delay())
                        done_local += 1
                        q.task_done()
                        continue
                    # Успех: uid/token
                    try:
                        uid = self.api_class().get_uid_from_login_response(data)
                    except Exception:
                        uid = None
                    if not api.token:
                        try:
                            data_login = api.login(username=username, password=password, device_id=device_id)
                            uid = uid or api.get_uid_from_login_response(data_login)
                        except Exception as e:
                            self.log.emit(f"{Icons.ERROR} [T{worker_idx}] Повторный login после регистрации не удался: {e}")
                    if (change_nick or change_avatar) and api.token and uid:
                        from core.constants import CLUB_SERVER_HOST, CLUB_SERVER_PORT, DEFAULT_AVATAR_URLS
                        endpoints = []
                        try:
                            eps = list(getattr(api,'tcp_entries',[]) or [])
                            for ep in eps:
                                try:
                                    h,p = ep; endpoints.append((str(h), int(p or 5000)))
                                except Exception:
                                    pass
                        except Exception:
                            endpoints = []
                        if not endpoints:
                            host = getattr(api,'tcp_host',None) or CLUB_SERVER_HOST
                            port = int(getattr(api,'tcp_port',None) or CLUB_SERVER_PORT)
                            endpoints = [(host,port)]
                        avatar_url = None
                        if change_avatar:
                            if avatar_url_common:
                                avatar_url = avatar_url_common
                            else:
                                try:
                                    avatar_url = DEFAULT_AVATAR_URLS[0] if DEFAULT_AVATAR_URLS else None
                                except Exception:
                                    avatar_url = None
                            if not avatar_url:
                                self.log.emit(f"{Icons.INFO} [T{worker_idx}] Смена аватара [{username}]: пропущено (нет URL)")
                        max_attempts = max(1, min(3, 1+len(endpoints)))
                        ok_name = (not change_nick)
                        ok_av = (not change_avatar) or (avatar_url is None)
                        for attempt_n in range(1, max_attempts+1):
                            if self._stop: break
                            ehost, eport = endpoints[(attempt_n-1)%len(endpoints)]
                            fallbacks = [ep for ep in endpoints if ep != (ehost,eport)]
                            tcp = None
                            try:
                                self.log.emit(f"{Icons.PROCESS} [T{worker_idx}] TCP попытка {attempt_n}/{max_attempts} для [{username}] через {ehost}:{eport}")
                                tcp = XClubTCPClient(host=ehost, port=eport, timeout=4.5, proxy=api.proxy_url, disable_bootstrap=True, frida_strict=True, fallback_endpoints=fallbacks)
                                try:
                                    tcp.set_cancel_event(self._cancel_event)
                                except Exception:
                                    pass
                                try:
                                    self._live_tcps.add(tcp)
                                except Exception:
                                    pass
                                tcp.connect(); _ = tcp.tcp_login(uid=int(uid), token=api.token)
                                if change_nick and not ok_name:
                                    ok, cmsg = tcp.change_name(nick)
                                    self.log.emit(f"{Icons.INFO} [T{worker_idx}] Смена ника [{username}] → '{nick}': {'успех' if ok else cmsg}")
                                    ok_name = ok or ok_name
                                if change_avatar and avatar_url and not ok_av:
                                    ok_av1, msg_av = tcp.change_avatar(avatar_url)
                                    self.log.emit(f"{Icons.INFO} [T{worker_idx}] Смена аватара [{username}] → '{avatar_url}': {'успех' if ok_av1 else msg_av}")
                                    ok_av = ok_av1 or ok_av
                                if ok_name and ok_av:
                                    break
                            except Exception as e:
                                self.log.emit(f"{Icons.WARNING} [T{worker_idx}] TCP попытка {attempt_n}/{max_attempts} для [{username}] не удалась: {e}")
                            finally:
                                try:
                                    if tcp is not None: tcp.close()
                                    try:
                                        if tcp is not None:
                                            self._live_tcps.discard(tcp)
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                            time.sleep(self._rand_delay())
                        if not (ok_name and ok_av):
                            self.log.emit(f"{Icons.WARNING} [T{worker_idx}] Не удалось применить TCP-изменения для [{username}] (ник={'ok' if ok_name else 'fail'}, аватар={'ok' if ok_av else 'fail'})")
                    # Создаём Account + эмитим
                    acc = Account(username=username, password=password, device_id=device_id)
                    acc.proxy = api.proxy_url
                    acc.token = api.token
                    acc.refresh_token = api.refresh_token
                    acc.access_token_expire = api.access_token_expire
                    acc.refresh_token_expire = api.refresh_token_expire
                    acc.uid = int(uid) if uid else None
                    acc.last_login_at = time.time()
                    try:
                        acc.headers = api.session.headers.copy() if hasattr(api,'session') else {}
                    except Exception:
                        acc.headers = {}
                    try:
                        with csv_lock:
                            regs_writer.writerow([datetime.datetime.utcnow().isoformat(), username, password, nick, device_id, 0, 'Success', acc.uid or ''])
                            regs_file.flush()
                    except Exception:
                        pass
                    self.log.emit(f"{Icons.SUCCESS} [T{worker_idx}] Зарегистрирован аккаунт: {username} (uid={acc.uid})")
                    self.new_account.emit(acc)
                    with counts_lock:
                        success_total += 1
                        processed_total += 1
                    done_local += 1
                    q.task_done()
                finally:
                    # Закрываем HTTP-сессию по окончании обработки задачи
                    try:
                        if api is not None:
                            sess = getattr(api, 'session', None)
                            if sess is not None:
                                sess.close()
                            try:
                                self._live_apis.discard(api)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    if requeue_token:
                        try:
                            q.put(token)
                        except Exception:
                            pass
                        # Выходим из потока — оставшиеся задачи возьмут другие
                        break
                time.sleep(self._rand_delay())
        # Запуск потоков
        ths = []
        for t in range(threads):
            pg = proxy_groups[t] if t < len(proxy_groups) else []
            th = threading.Thread(target=worker_fn, args=(t+1, pg, job_queue), daemon=True)
            th.start(); ths.append(th)
        # Ждём завершения
        for th in ths:
            th.join()
        # Финальный отчёт по параллельной регистрации
        remaining = 0
        try:
            remaining = job_queue.qsize()
        except Exception:
            remaining = 0
        total_planned = int(count)
        reason = ""
        if self._stop:
            reason = "Остановлено пользователем"
        elif proxies_all and len(ip_limit_global) >= len(proxies_all) and remaining > 0:
            reason = f"Все прокси помечены как 'Register IP Limit' — осталось задач: {remaining}"
        elif remaining == 0:
            reason = "Все задачи выполнены"
        else:
            reason = f"Потоки завершены, но остались задачи: {remaining} (возможна нехватка рабочих прокси)"
        icon = Icons.SUCCESS if remaining == 0 and processed_total >= total_planned else Icons.WARNING if "Register IP Limit" in reason else Icons.INFO
        self.log.emit(f"{icon} 🏁 Конец: {reason}. Прогресс: {processed_total}/{total_planned} (успешно: {success_total}, ошибки: {fail_total}). IP Limit помечено: {len(ip_limit_global)}/{len(proxies_all)} прокси")
        try:
            regs_file.close()
        except Exception:
            pass

class AccountDialog(QDialog):
    """Диалог для добавления/редактирования аккаунта."""
    
    def __init__(self, account: Optional[Account] = None, parent=None):
        super().__init__(parent)
        self.account = account
        self.setWindowTitle("Редактировать аккаунт" if account else "Добавить аккаунт")
        self.setModal(True)
        self.resize(450, 260)
        
        layout = QVBoxLayout(self)
        
        # Создаем форму
        form_group = QGroupBox("Данные аккаунта")
        form_layout = QFormLayout(form_group)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Например: Maria122131242")
        form_layout.addRow("Имя пользователя:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Пароль аккаунта")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Пароль:", self.password_edit)
        
        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("логин:пароль@ip:порт или ip:порт (схема определяется автоматически)")
        form_layout.addRow("Прокси (опционально):", self.proxy_edit)
        
        layout.addWidget(form_group)
        
        # Кнопки
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # Заполняем данными если редактируем
        if account:
            self.username_edit.setText(account.username)
            self.password_edit.setText(account.password)
            # При редактировании существующего аккаунта — пароль менять нельзя
            self.password_edit.setReadOnly(True)
            self.password_edit.setToolTip("Изменение пароля отключено")
            self.proxy_edit.setText(account.proxy or "")
    
    def get_account_data(self) -> dict:
        """Получить данные из формы."""
        return {
            'username': self.username_edit.text().strip(),
            'password': self.password_edit.text().strip(),
            'proxy': self.proxy_edit.text().strip() or None
        }
    
    def validate(self) -> bool:
        """Проверить корректность введенных данных."""
        data = self.get_account_data()
        
        if not data['username']:
            QMessageBox.warning(self, "Ошибка", "Имя пользователя не может быть пустым!")
            self.username_edit.setFocus()
            return False
            
        if not data['password']:
            QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым!")
            self.password_edit.setFocus()
            return False
            
        return True
    
    def accept(self):
        if self.validate():
            super().accept()


class ClubIdDialog(QDialog):
    """Диалог для добавления ID клубов."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить ID клубов")
        self.setModal(True)
        self.resize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # Инструкция
        info_label = QLabel(
            "Введите ID клубов для вступления:\n"
            "• Каждый ID на новой строке\n"
            "• Например: 123, 202051, 456\n"
            "• Пустые строки будут пропущены"
        )
        info_label.setStyleSheet("color: #666; font-size: 11px; margin-bottom: 10px;")
        layout.addWidget(info_label)
        
        # Поле для ввода ID клубов
        self.clubs_edit = QPlainTextEdit()
        self.clubs_edit.setPlaceholderText(
            "123\n"
            "202051\n"
            "456\n"
            "789"
        )
        layout.addWidget(self.clubs_edit)
        
        # Кнопки
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_club_ids(self) -> List[str]:
        """Получить список ID клубов."""
        text = self.clubs_edit.toPlainText()
        club_ids = []
        
        for line in text.split('\n'):
            line = line.strip()
            if line and line.isdigit():
                club_ids.append(line)
        
        return club_ids

class DebugTCPDialog(QDialog):
    """Диалог для отладки TCP последовательности."""
    
    def __init__(self, accounts: List[Account], parent=None):
        super().__init__(parent)
        self.accounts = accounts
        self.setWindowTitle("Отладка TCP последовательности")
        self.setModal(True)
        self.resize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Инструкция
        info_label = QLabel(
            "🔧 Отладочная функция для проверки корректности TCP последовательности\n\n"
            "Эта функция выполнит полную последовательность команд:\n"
            "1. TCP Login\n"
            "2. Heartbeat (HBREQ)\n"
            "3. GetSelfData\n"
            "4. GetClubDescList\n"
            "5. Heartbeat\n"
            "6. GetClubDesc для указанного клуба\n"
            "7. Heartbeat\n"
            "8. ApplyClub (заявка на вступление)\n"
            "9. Финальный Heartbeat\n\n"
            "⚠️ Это будет реальная попытка вступления в клуб!"
        )
        info_label.setStyleSheet("color: #333; font-size: 11px; margin-bottom: 10px; padding: 10px; background: #f0f0f0; border: 1px solid #ccc;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Выбор аккаунта
        account_group = QGroupBox("Выбор аккаунта")
        account_layout = QFormLayout(account_group)
        
        self.account_combo = QComboBox()
        authorized_accounts = [acc for acc in self.accounts if acc.token and acc.uid]
        
        if not authorized_accounts:
            self.account_combo.addItem("Нет авторизованных аккаунтов с UID")
            self.account_combo.setEnabled(False)
        else:
            for acc in authorized_accounts:
                uid_text = f" (uid={acc.uid})" if acc.uid else ""
                proxy_text = f" via {acc.proxy}" if acc.proxy else ""
                self.account_combo.addItem(f"{acc.username}{uid_text}{proxy_text}", acc)
                
        account_layout.addRow("Аккаунт:", self.account_combo)
        layout.addWidget(account_group)
        
        # ID клуба
        club_group = QGroupBox("Настройки тестирования")
        club_layout = QFormLayout(club_group)
        
        self.club_id_edit = QLineEdit()
        self.club_id_edit.setPlaceholderText("Например: 123456")
        self.club_id_edit.setText("123456")  # Значение по умолчанию для тестов
        club_layout.addRow("ID клуба для тестирования:", self.club_id_edit)
        
        self.version_edit = QLineEdit()
        self.version_edit.setText("1.12.67")
        self.version_edit.setPlaceholderText("Версия клиента")
        club_layout.addRow("Версия клиента:", self.version_edit)
        
        layout.addWidget(club_group)
        
        # Результаты будут показаны в основном окне
        result_label = QLabel(
            "📋 Результаты отладки будут показаны в журнале событий основного окна.\n"
            "Вы увидите детальную информацию по каждому шагу."
        )
        result_label.setStyleSheet("color: #666; font-size: 10px; font-style: italic; margin-top: 10px;")
        result_label.setWordWrap(True)
        layout.addWidget(result_label)
        
        # Кнопки
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("🚀 Запустить отладку")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_debug_params(self) -> Optional[dict]:
        """Получить параметры для отладки."""
        if self.account_combo.currentData() is None:
            return None
            
        club_id_text = self.club_id_edit.text().strip()
        if not club_id_text or not club_id_text.isdigit():
            return None
            
        return {
            'account': self.account_combo.currentData(),
            'club_id': int(club_id_text),
            'version': self.version_edit.text().strip() or "1.12.67"
        }
    
    def validate(self) -> bool:
        """Проверить корректность введенных данных."""
        if self.account_combo.currentData() is None:
            QMessageBox.warning(self, "Ошибка", "Выберите аккаунт для отладки!")
            return False
            
        club_id_text = self.club_id_edit.text().strip()
        if not club_id_text:
            QMessageBox.warning(self, "Ошибка", "Введите ID клуба!")
            self.club_id_edit.setFocus()
            return False
            
        if not club_id_text.isdigit():
            QMessageBox.warning(self, "Ошибка", "ID клуба должен содержать только цифры!")
            self.club_id_edit.setFocus()
            return False
            
        return True
    
    def accept(self):
        if self.validate():
            super().accept()


class GenerateAccountsDialog(QDialog):
    """Диалог генерации аккаунтов.
    Поля:
    - Количество
    - Список прокси (по одному на строке)
    - Задержка MIN (мс)
    - Задержка MAX (мс)
    - Добавить аватарку (по умолчанию включено)
    - Путь к файлу аватара (один раз заливается и используется для всех)
    """
    def __init__(self, *, default_count: int = 100, default_proxies_text: str = "", default_dmin: int = 400, default_dmax: int = 900, default_set_avatar: bool = True, default_threads: int = 1, default_ppt: int = 0, default_avatar_path: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Сгенерировать аккаунты")
        self.setModal(True)
        self.resize(600, 520)
        v = QVBoxLayout(self)
        form = QFormLayout()
        # Кол-во
        self.spn_count = QSpinBox(); self.spn_count.setRange(1, 500000); self.spn_count.setValue(int(max(1, min(500000, default_count))))
        form.addRow("Количество:", self.spn_count)
        # Прокси (многострочный ввод)
        self.txt_proxies = QPlainTextEdit();
        self.txt_proxies.setPlaceholderText("Каждый прокси на новой строке:\nuser:pass@host:port\nили host:port\n(схема auto: http/socks5h)")
        self.txt_proxies.setPlainText(default_proxies_text or "")
        self.txt_proxies.setMinimumHeight(120)
        form.addRow("Прокси (список):", self.txt_proxies)
        # Опции параллелизма
        par_row = QHBoxLayout()
        self.spn_threads = QSpinBox(); self.spn_threads.setRange(1, 64); self.spn_threads.setValue(max(1, int(default_threads)))
        self.spn_ppt = QSpinBox(); self.spn_ppt.setRange(0, 1000); self.spn_ppt.setValue(max(0, int(default_ppt)))
        par_row.addWidget(QLabel("Потоков:")); par_row.addWidget(self.spn_threads)
        par_row.addSpacing(16)
        par_row.addWidget(QLabel("Прокси на поток (0=авто):")); par_row.addWidget(self.spn_ppt)
        form.addRow("Параллелизм:", par_row)
        # Опция: добавить аватарку + выбор файла
        self.chk_set_avatar = QCheckBox("Добавить аватарку")
        self.chk_set_avatar.setChecked(bool(default_set_avatar))
        form.addRow("Добавить аватарку:", self.chk_set_avatar)
        avatar_row = QHBoxLayout()
        self.ed_avatar_path = QLineEdit()
        self.ed_avatar_path.setPlaceholderText("Путь к картинке (png/jpg)")
        if default_avatar_path:
            self.ed_avatar_path.setText(default_avatar_path)
        btn_browse = QPushButton("Выбрать файл…")
        def _pick_file():
            path, _ = QFileDialog.getOpenFileName(self, "Выберите картинку", "", "Images (*.png *.jpg *.jpeg *.webp)")
            if path:
                self.ed_avatar_path.setText(path)
        btn_browse.clicked.connect(_pick_file)
        avatar_row.addWidget(self.ed_avatar_path)
        avatar_row.addWidget(btn_browse)
        form.addRow("Файл аватара:", avatar_row)
        def _toggle_avatar(e):
            en = self.chk_set_avatar.isChecked()
            self.ed_avatar_path.setEnabled(en); btn_browse.setEnabled(en)
        self.chk_set_avatar.toggled.connect(_toggle_avatar)
        _toggle_avatar(True)
        # Задержки
        delays_row = QHBoxLayout()
        self.spn_delay_min = QSpinBox(); self.spn_delay_min.setRange(0, 600000); self.spn_delay_min.setValue(max(0, int(default_dmin)))
        self.spn_delay_max = QSpinBox(); self.spn_delay_max.setRange(0, 600000); self.spn_delay_max.setValue(max(0, int(default_dmax)))
        delays_row.addWidget(QLabel("Мин (мс):")); delays_row.addWidget(self.spn_delay_min)
        delays_row.addSpacing(16)
        delays_row.addWidget(QLabel("Макс (мс):")); delays_row.addWidget(self.spn_delay_max)
        form.addRow("Задержка между запросами:", delays_row)
        v.addLayout(form)
        # Кнопки
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        v.addWidget(buttons)

    def get_values(self) -> tuple[int, list[str], int, int, bool, int, int, str]:
        try:
            cnt = int(self.spn_count.value())
            dmin = int(self.spn_delay_min.value())
            dmax = int(self.spn_delay_max.value())
            # нормализуем порядок
            if dmax < dmin:
                dmin, dmax = dmax, dmin
            # парсим список прокси
            raw = self.txt_proxies.toPlainText().splitlines()
            proxies = [line.strip() for line in raw if line.strip()]
            set_avatar = bool(self.chk_set_avatar.isChecked())
            threads = int(self.spn_threads.value())
            ppt = int(self.spn_ppt.value())
            avatar_path = (self.ed_avatar_path.text().strip() if set_avatar else "")
            return cnt, proxies, dmin, dmax, set_avatar, threads, ppt, avatar_path
        except Exception:
            return 0, [], 0, 0, True, 1, 0, ""

    # -------- helper: upload avatar to tmpfiles and return direct dl URL --------
    def _upload_avatar_tmpfiles(self, file_path: str) -> Optional[str]:
        try:
            fn = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                files = {'file': (fn, f, 'application/octet-stream')}
                r = requests.post('https://tmpfiles.org/api/v1/upload', files=files, timeout=25)
            r.raise_for_status()
            try:
                j = r.json()
            except Exception:
                j = None
            url = None
            if isinstance(j, dict):
                url = (j.get('data', {}) or {}).get('url') or j.get('url')
            if not url:
                txt = (r.text or '')
                import re
                m = re.search(r'https?://tmpfiles\.org/[^\s"]+', txt)
                if m:
                    url = m.group(0)
            if not url:
                return None
            # Build direct dl URL
            # Expected share url like https://tmpfiles.org/1234567/filename or /f/1234567/filename
            import re
            m = re.search(r'tmpfiles\.org/(?:f/)?(\d+)/(.*)$', url)
            if m:
                file_id, fname = m.group(1), m.group(2)
                dl = f'https://tmpfiles.org/dl/{file_id}/{fname}'
                return dl
            # If already a direct link or unknown pattern
            if '/dl/' in url:
                return url
            return url
        except Exception:
            return None

class UpdateDownloadThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, mgr: UpdateManager, parent=None):
        super().__init__(parent)
        self.mgr = mgr

    def run(self):
        ok = self.mgr.download(progress_cb=lambda p: self.progress.emit(int(p)))
        if ok:
            installed = self.mgr.install()
            self.finished.emit(bool(installed), "")
        else:
            self.finished.emit(False, "download_failed")


class FishPokerTab(QWidget):
    def update_table_theme(self) -> None:
        """Светлая/тёмная тема таблицы — как у XPoker, но селекторы без id для строгого применения."""
        try:
            t = self.tbl
        except Exception:
            return
        if not isinstance(t, QTableWidget):
            return
        # Определяем эффективный режим темы из окна (QTabWidget может переписать parent)
        eff = 'light'
        try:
            mw = self.window()
            if not (mw and hasattr(mw, 'current_theme_mode')):
                # Поищем выше по иерархии
                p = self.parent()
                while p is not None and not hasattr(p, 'current_theme_mode'):
                    p = getattr(p, 'parent', lambda: None)()
                if p is not None:
                    mw = p
            if mw and getattr(mw, 'current_theme_mode', None) in ('light', 'dark'):
                eff = mw.current_theme_mode
        except Exception:
            pass
        if eff == 'dark':
            try:
                t.setStyleSheet(
                    "QTableWidget, QTableView, QTableWidget::viewport, QTableView::viewport {"
                    " background-color: #1e1e1e;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #1e1e1e;"
                    "}"
                )
                t.viewport().setStyleSheet("background-color: #1e1e1e;")
            except Exception:
                pass
            try:
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet(
                        "QHeaderView { background-color: #1e1e1e; }"
                        "QHeaderView::section { background-color: #1e1e1e; color: #d0d0d0; border: none; }"
                    )
                    pal = vh.palette()
                    pal.setColor(QPalette.ColorRole.Button, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
                    vh.setPalette(pal)
                    vh.setAutoFillBackground(True)
            except Exception:
                pass
        else:
            try:
                # Сбрасываем QSS/палитры
                t.setStyleSheet("")
                t.viewport().setStyleSheet("")
                try:
                    pal = QApplication.palette()
                    t.setPalette(pal)
                    t.viewport().setAutoFillBackground(False)
                except Exception:
                    pass
                # Хедеры
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet("")
                    vh.setAutoFillBackground(False)
                    try:
                        vh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                hh = t.horizontalHeader()
                if hh is not None:
                    hh.setStyleSheet("")
                    try:
                        hh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                # Стиль как у XPoker (без id)
                ss_light = (
                    "QTableWidget, QTableWidget::viewport {"
                    " background-color: #f7f7f7;"
                    " alternate-background-color: #ffffff;"
                    "}"
                    "QTableWidget {"
                    " gridline-color: #e0e0e0;"
                    "}"
                    "QHeaderView::section:horizontal {"
                    " background-color: #fafafa; color: #222; border: 1px solid #e6e6e6; padding: 4px;"
                    "}"
                    "QHeaderView::section:vertical {"
                    " background-color: #f7f7f7; color: #666; border: none;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #fafafa; border: 1px solid #e6e6e6;"
                    "}"
                    "QTableWidget::item:selected {"
                    " background-color: #cfe8ff; color: #000;"
                    "}"
                )
                try:
                    t.setAlternatingRowColors(True)
                except Exception:
                    pass
                try:
                    t.setStyleSheet(ss_light)
                except Exception:
                    pass
                try:
                    t.style().unpolish(t)
                    t.style().polish(t)
                    t.update()
                except Exception:
                    pass
            except Exception:
                pass

    def _gen_device_id(self, seed: str) -> str:
        """FishPoker uses a MAC-like device id (6 bytes hex with hyphens)."""
        try:
            import hashlib
            import secrets

            if seed:
                h = hashlib.md5(str(seed).encode('utf-8')).digest()
                b = bytearray(h[:6])
            else:
                b = bytearray(secrets.token_bytes(6))
            b[0] = (b[0] & 0xFE) | 0x02
            return '-'.join(f"{x:02X}" for x in b)
        except Exception:
            return '02-00-00-00-00-01'

    def _ensure_device_id(self, value: str, username: str) -> str:
        import re

        v = (value or '').strip()
        if not v:
            return self._gen_device_id(username)
        s = v.strip().replace(':', '-').replace(' ', '').upper()
        # XX-XX-XX-XX-XX-XX
        if re.fullmatch(r'[0-9A-F]{2}(-[0-9A-F]{2}){5}', s):
            return s
        # 12 hex -> format
        s2 = s.replace('-', '')
        if re.fullmatch(r'[0-9A-F]{12}', s2):
            return '-'.join(s2[i:i+2] for i in range(0, 12, 2))
        # 40-hex (например PPPoker imei40) -> стабильно преобразуем
        if re.fullmatch(r'[0-9A-F]{40}', s2):
            try:
                import hashlib

                h = hashlib.md5(s2.encode('utf-8')).hexdigest()[:12].upper()
                return '-'.join(h[i:i+2] for i in range(0, 12, 2))
            except Exception:
                return self._gen_device_id(s2)
        # Вытаскиваем первые 6 байт, если похоже на MAC в другом формате
        pairs = re.findall(r'[0-9A-F]{2}', s2)
        if len(pairs) >= 6:
            return '-'.join(pairs[:6])
        return self._gen_device_id(s or username)

    def __init__(self, parent=None):
        super().__init__(parent)
        from fishpoker.api import FishPokerAPI, ApiError as FishApiError
        # State
        self.accounts: List[Account] = []
        self.club_ids: List[str] = []
        self.report_rows: List[dict] = []
        self.account_row_by_username: Dict[str, int] = {}
        self._suppress_item_changed = False

        # Layout
        v = QVBoxLayout(self)

        # Accounts group
        accounts_group = QGroupBox("📋 Управление аккаунтами")
        accounts_layout = QHBoxLayout(accounts_group)
        self.btn_add_account = QPushButton("➕ Добавить аккаунт")
        self.btn_edit_account = QPushButton("✏️ Редактировать")
        self.btn_delete_account = QPushButton("🗑️ Удалить")
        self.btn_load_accounts = QPushButton("📁 Из Excel файла")
        self.btn_save_accounts = QPushButton("💾 Сохранить настройки")
        self.btn_generate_accounts = QPushButton("🧪 Сгенерировать аккаунты")
        for b in (self.btn_add_account, self.btn_edit_account, self.btn_delete_account, self.btn_load_accounts, self.btn_save_accounts, self.btn_generate_accounts):
            accounts_layout.addWidget(b)
        accounts_layout.addStretch()
        v.addWidget(accounts_group)

        # Clubs group
        clubs_group = QGroupBox("🏛️ Управление клубами")
        clubs_layout = QHBoxLayout(clubs_group)
        self.btn_add_clubs = QPushButton("➕ Добавить клубы")
        self.btn_clear_clubs = QPushButton("🗑️ Очистить список")
        self.btn_load_clubs = QPushButton("📁 Из Excel файла")
        self.btn_load_club_distribution = QPushButton("📊 Распределение клубов")
        self.clubs_count_label = QLabel("Клубов: 0")
        for b in (self.btn_add_clubs, self.btn_clear_clubs, self.btn_load_clubs, self.btn_load_club_distribution):
            clubs_layout.addWidget(b)
        clubs_layout.addWidget(self.clubs_count_label)
        clubs_layout.addStretch()
        v.addWidget(clubs_group)

        # Operations group
        operations_group = QGroupBox("🚀 Операции")
        operations_layout = QHBoxLayout(operations_group)
        self.btn_login = QPushButton("🔐 Войти во все")
        self.btn_logout = QPushButton("🚪 Выйти из выбранных")
        self.btn_join = QPushButton("🎯 Начать вступление")
        self.btn_pause = QPushButton("⏸ Пауза"); self.btn_pause.setEnabled(False)
        self.btn_stop = QPushButton("🛑 Остановить"); self.btn_stop.setEnabled(False)
        self.btn_export = QPushButton("📊 Экспорт отчета")
        for b in (self.btn_login, self.btn_logout, self.btn_join, self.btn_pause, self.btn_stop, self.btn_export):
            operations_layout.addWidget(b)
        operations_layout.addStretch()
        v.addWidget(operations_group)

        # Knobs
        knobs = QHBoxLayout()
        knobs.addWidget(QLabel("Клубов на аккаунт (0 = все клубы):"))
        self.spn_clubs_per_account = QSpinBox(); self.spn_clubs_per_account.setRange(0, 1000000); self.spn_clubs_per_account.setValue(500)
        knobs.addWidget(self.spn_clubs_per_account)
        knobs.addWidget(QLabel("Задержка мин (мс):"))
        self.spn_delay_min = QSpinBox(); self.spn_delay_min.setRange(0, 10000); self.spn_delay_min.setValue(500)
        knobs.addWidget(self.spn_delay_min)
        knobs.addWidget(QLabel("Задержка макс (мс):"))
        self.spn_delay_max = QSpinBox(); self.spn_delay_max.setRange(0, 20000); self.spn_delay_max.setValue(1500)
        knobs.addWidget(self.spn_delay_max)
        knobs.addWidget(QLabel("Параллельно (TCP):"))
        self.spn_join_threads = QSpinBox(); self.spn_join_threads.setRange(1, 1000); self.spn_join_threads.setValue(64)
        knobs.addWidget(self.spn_join_threads)
        self.chk_shuffle = QCheckBox("Перемешать ID клубов"); self.chk_shuffle.setChecked(True)
        knobs.addWidget(self.chk_shuffle)
        v.addLayout(knobs)

        # Message field (40 chars)
        msg_row = QHBoxLayout()
        msg_row.addWidget(QLabel("Сообщение заявки (до 40 символов):"))
        self.txt_message = QLineEdit(); self.txt_message.setMaxLength(40); self.txt_message.setPlaceholderText("Например: Примите, пожалуйста")
        msg_row.addWidget(self.txt_message)
        v.addLayout(msg_row)

        # Accounts table
        base_cols = len(ACCOUNTS_COLUMNS)
        self.PROG_COL = base_cols + 0
        self.STATUS_COL = base_cols + 1
        self.CURRENT_COL = base_cols + 2
        self.tbl = QTableWidget(0, base_cols + len(EXTRA_COLUMNS))
        self.tbl.setObjectName("accountsTable")
        self.tbl.setHorizontalHeaderLabels(ACCOUNTS_COLUMNS + EXTRA_COLUMNS)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.itemChanged.connect(self.on_cell_changed)
        v.addWidget(self.tbl, stretch=1)

        v.addWidget(QLabel("Журнал событий:"))
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        v.addWidget(self.log, stretch=1)

        # Worker
        self.worker = Worker(self.accounts, api_class=FishPokerAPI, api_error_class=FishApiError)
        self.worker.log.connect(self.on_worker_log)
        self.worker.account_updated.connect(self.on_account_updated)
        self.worker.join_result.connect(self.on_join_result)
        self.worker.task_finished.connect(self.on_task_finished)
        self.worker.pause_changed.connect(self.on_worker_pause_changed)
        self.worker.account_progress.connect(self.on_account_progress)
        try:
            self.worker.new_account.connect(self.on_new_account)
        except Exception:
            pass
        try:
            self.worker.started.connect(self.on_worker_started)
            self.worker.finished.connect(self.on_worker_finished)
        except Exception:
            pass

        # Wire up buttons
        self.btn_add_account.clicked.connect(self.on_add_account)
        self.btn_edit_account.clicked.connect(self.on_edit_account)
        self.btn_delete_account.clicked.connect(self.on_delete_account)
        self.btn_load_accounts.clicked.connect(self.on_load_accounts)
        self.btn_save_accounts.clicked.connect(self.on_save_accounts)
        self.btn_generate_accounts.clicked.connect(self.on_generate_accounts)
        self.btn_add_clubs.clicked.connect(self.on_add_clubs)
        self.btn_clear_clubs.clicked.connect(self.on_clear_clubs)
        self.btn_load_clubs.clicked.connect(self.on_load_clubs)
        self.btn_load_club_distribution.clicked.connect(self.on_load_club_distribution)
        self.btn_login.clicked.connect(self.on_login_all)
        self.btn_logout.clicked.connect(self.on_logout_selected)
        self.btn_join.clicked.connect(self.on_join)
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_export.clicked.connect(self.on_export_report)
        try:
            self.spn_clubs_per_account.valueChanged.connect(self.save_settings)
            self.spn_delay_min.valueChanged.connect(self.save_settings)
            self.spn_delay_max.valueChanged.connect(self.save_settings)
            self.chk_shuffle.toggled.connect(self.save_settings)
            self.txt_message.textChanged.connect(self.save_settings)
        except Exception:
            pass

        self.load_settings()
        try:
            self.update_table_theme()
        except Exception:
            pass

    # ====== Event handlers / helpers (FishPoker) ======
    def on_worker_log(self, line: str):
        self.log.appendPlainText(line)

    def on_save_accounts(self):
        try:
            self.save_settings()
            QMessageBox.information(self, "Сохранение", "Настройки сохранены успешно!")
            self.log.appendPlainText(f"{Icons.SUCCESS} Настройки сохранены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить настройки: {e}")

    def _append_account_row(self, acc: Account):
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        data = acc.as_row()
        self._suppress_item_changed = True
        try:
            for c, v in enumerate(data):
                it = QTableWidgetItem(str(v))
                if c in (1, 4, 5):
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(r, c, it)
            prog = QProgressBar(); prog.setRange(0,1); prog.setValue(0); prog.setTextVisible(True); prog.setFormat("0/0 (0%)")
            self.tbl.setCellWidget(r, self.PROG_COL, prog)
            st_it = QTableWidgetItem("⏳ Ожидание"); st_it.setFlags(st_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.STATUS_COL, st_it)
            cur_it = QTableWidgetItem("-"); cur_it.setFlags(cur_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.CURRENT_COL, cur_it)
        finally:
            self._suppress_item_changed = False
        self.account_row_by_username[acc.username.lower()] = r

    def on_cell_changed(self, item: QTableWidgetItem):
        if self._suppress_item_changed:
            return
        row = item.row(); col = item.column()
        if row < 0 or row >= len(self.accounts):
            return
        acc = self.accounts[row]
        text = item.text().strip()
        if col in (1,4,5):
            self._suppress_item_changed = True
            try:
                current = acc.as_row()[col]
                item.setText(str(current))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            finally:
                self._suppress_item_changed = False
            return
        changed = False
        if col == 0 and text and text != acc.username:
            acc.username = text; changed = True
        elif col == 2:
            new_proxy = text or None
            if new_proxy != (acc.proxy or None):
                acc.proxy = new_proxy; changed = True
        elif col == 3 and text != (acc.device_id or ""):
            acc.device_id = self._ensure_device_id(text, acc.username); changed = True
            self._suppress_item_changed = True
            try:
                it = QTableWidgetItem(acc.device_id)
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 3, it)
            finally:
                self._suppress_item_changed = False
        if changed:
            acc.token = None; acc.last_login_at = None
            self._suppress_item_changed = True
            try:
                tok_it = QTableWidgetItem(""); tok_it.setFlags(tok_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 4, tok_it)
                last_it = QTableWidgetItem(""); last_it.setFlags(last_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 5, last_it)
            finally:
                self._suppress_item_changed = False
            self.account_row_by_username = {a.username.lower(): i for i,a in enumerate(self.accounts)}
            self.worker.accounts = self.accounts
            self.save_settings()

    def on_account_updated(self, row: int, data: list):
        self._suppress_item_changed = True
        try:
            for col, val in enumerate(data):
                it = QTableWidgetItem(str(val))
                if col in (1, 4, 5):
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, col, it)
            it_status = self.tbl.item(row, self.STATUS_COL)
            if it_status:
                it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
            it_curr = self.tbl.item(row, self.CURRENT_COL)
            if it_curr:
                it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        finally:
            self._suppress_item_changed = False

    def on_account_progress(self, username: str, done: int, total: int, status_text: str, current_club: str):
        row = self.account_row_by_username.get(username.lower())
        if row is None:
            return
        w = self.tbl.cellWidget(row, self.PROG_COL)
        if isinstance(w, QProgressBar):
            w.setRange(0, max(total,1))
            w.setValue(max(0, min(done, total)))
            percent = (0 if total == 0 else int((done/total)*100))
            w.setFormat(f"{done}/{total} ({percent}%)")
        it_status = QTableWidgetItem(status_text); it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.STATUS_COL, it_status)
        it_curr = QTableWidgetItem(current_club); it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.CURRENT_COL, it_curr)

    def on_join_result(self, jr: JoinResult):
        self.report_rows.append(jr)

    def on_add_account(self):
        dialog = AccountDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            dev = self._ensure_device_id('', data['username'])
            acc = Account(username=data['username'], password=data['password'], device_id=dev, proxy=data['proxy'])
            self.accounts.append(acc)
            self._append_account_row(acc)
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен аккаунт: {acc.username}")

    def on_edit_account(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строку для редактирования"); return
        if len(rows) > 1:
            QMessageBox.information(self, "Выбор", "Выберите только одну строку для редактирования"); return
        row = rows[0]
        if row >= len(self.accounts):
            return
        acc = self.accounts[row]
        dialog = AccountDialog(account=acc, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            acc.username = data['username']; acc.password = data['password']; acc.proxy = data['proxy']
            acc.token = None; acc.last_login_at = None
            for col, val in enumerate(acc.as_row()):
                self.tbl.setItem(row, col, QTableWidgetItem(str(val)))
            self.account_row_by_username[acc.username.lower()] = row
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Отредактирован аккаунт: {acc.username}")

    def on_delete_account(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()}, reverse=True)
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для удаления"); return
        reply = QMessageBox.question(self, "Подтверждение", f"Удалить {len(rows)} аккаунт(ов)?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            deleted = []
            for r in rows:
                if r < len(self.accounts):
                    deleted.append(self.accounts[r].username)
                    del self.accounts[r]; self.tbl.removeRow(r)
            self.worker.accounts = self.accounts
            self.save_settings()
            if deleted:
                self.log.appendPlainText(f"{Icons.SUCCESS} Удалены аккаунты: {', '.join(deleted)}")

    def on_add_clubs(self):
        dialog = ClubIdDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_club_ids = dialog.get_club_ids()
            if new_club_ids:
                existing = set(self.club_ids)
                added = []
                for club_id in new_club_ids:
                    if club_id not in existing:
                        self.club_ids.append(club_id)
                        existing.add(club_id)
                        added.append(club_id)
                if self.chk_shuffle.isChecked() and self.club_ids:
                    import random; random.shuffle(self.club_ids)
                    self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан")
                self.update_clubs_count(); self.save_settings()
                if added:
                    self.log.appendPlainText(f"{Icons.SUCCESS} Добавлено {len(added)} новых клубов: {', '.join(added)}")
                else:
                    self.log.appendPlainText(f"{Icons.INFO} Все введённые клубы уже есть в списке")
            else:
                QMessageBox.information(self, "Данные", "Не введено ни одного корректного ID клуба")

    def on_clear_clubs(self):
        if self.club_ids:
            reply = QMessageBox.question(self, "Подтверждение", f"Очистить список из {len(self.club_ids)} клубов?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.club_ids.clear(); self.update_clubs_count(); self.save_settings(); self.log.appendPlainText(f"{Icons.SUCCESS} Список клубов очищен")
        else:
            QMessageBox.information(self, "Список пуст", "Список клубов уже пуст")

    def on_load_accounts(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с аккаунтами", "", "Excel (*.xlsx)")
        if not path:
            return
        import pandas as pd
        df = pd.read_excel(path)
        df.columns = [str(c).lower().strip() for c in df.columns]
        if not {"username", "password"}.issubset(df.columns):
            QMessageBox.critical(self, "Ошибка", "Требуются колонки: username, password"); return
        self.accounts.clear(); self.tbl.setRowCount(0)
        for _, row in df.iterrows():
            proxy_val = row.get("proxy"); proxy_val = (None if (pd.isna(proxy_val) or str(proxy_val).strip()=="") else str(proxy_val).strip())
            device_id_val = row.get("device_id"); device_id_str = str(device_id_val).strip() if device_id_val is not None and not pd.isna(device_id_val) else ""
            username = str(row['username']).strip()
            dev = self._ensure_device_id(device_id_str, username)
            acc = Account(username=username, password=str(row['password']).strip(), proxy=proxy_val, device_id=dev)
            self.accounts.append(acc); self._append_account_row(acc)
        self.worker.accounts = self.accounts
        self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.accounts)} аккаунтов")

    def on_load_clubs(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с клубами", "", "Excel (*.xlsx)")
        if not path: return
        import pandas as pd
        df = pd.read_excel(path)
        col = None
        for c in df.columns:
            if str(c).lower() in ("club_id","id","clubid"):
                col = c; break
        if not col:
            QMessageBox.critical(self, "Ошибка", "Не найдена колонка 'club_id'"); return
        self.club_ids = [str(x) for x in df[col].dropna().astype(str).tolist()]
        if self.chk_shuffle.isChecked():
            import random; random.shuffle(self.club_ids)
        self.update_clubs_count(); self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.club_ids)} ID клубов")

    def on_load_club_distribution(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты!"); return
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с распределением клубов", "", "Excel (*.xlsx)")
        if not path: return
        try:
            import pandas as pd
            df = pd.read_excel(path)
            df.columns = [str(c).lower().strip() for c in df.columns]
            username_col = clubs_count_col = None
            for c in df.columns:
                if str(c).lower() in ("username", "user", "имя пользователя", "логин", "аккаунт"):
                    username_col = c
                if str(c).lower() in ("clubs_count", "clubs", "количество клубов", "клубов", "count"):
                    clubs_count_col = c
            if not username_col or not clubs_count_col:
                QMessageBox.critical(self, "Ошибка", "Не найдены нужные колонки в файле"); return
            self.worker.account_club_limits.clear()
            loaded = 0
            for _, row in df.iterrows():
                username = str(row[username_col]).strip()
                try:
                    clubs_count = int(row[clubs_count_col]); clubs_count = max(0, clubs_count)
                except Exception:
                    continue
                if any(acc.username.lower()==username.lower() for acc in self.accounts):
                    self.worker.account_club_limits[username.lower()] = clubs_count
                    loaded += 1
            if loaded == 0:
                QMessageBox.warning(self, "Предупреждение", "Не найдено совпадений аккаунтов"); return
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружено распределение для {loaded} аккаунтов")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка загрузки", str(e))

    def on_login_all(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        self.worker.set_task(self.worker.task_login_all)
        self.worker.start()

    def on_logout_selected(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для выхода"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        self.worker.set_task(self.worker.task_logout_selected, rows)
        self.worker.start()

    def on_join(self):
        if not self.club_ids:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите клубы"); return
        if not any(a.token for a in self.accounts):
            QMessageBox.critical(self, "Ошибка", "Сначала войдите в аккаунты (нет токенов)"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        clubs_to_process = self.club_ids.copy()
        if self.chk_shuffle.isChecked():
            import random; random.shuffle(clubs_to_process); self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан для обработки")
        limit = self.spn_clubs_per_account.value()
        dmin = self.spn_delay_min.value(); dmax = self.spn_delay_max.value()
        if dmax < dmin:
            dmin, dmax = dmax, dmin
        message_text = self.txt_message.text().strip()
        self.worker.set_task(self.worker.task_join_round, clubs_to_process, limit, dmin, dmax, message_text, int(self.spn_join_threads.value()))
        self.worker.start()

    def on_pause(self):
        if not self.worker.isRunning():
            QMessageBox.information(self, "Пауза", "Нет активного процесса для паузы"); return
        self.worker.pause_toggle()

    def on_worker_pause_changed(self, paused: bool):
        self.btn_pause.setText("▶️ Продолжить" if paused else "⏸ Пауза")
        self.save_settings()

    def on_worker_started(self):
        try:
            self.btn_stop.setEnabled(True)
            self.btn_pause.setEnabled(True)
            self.btn_pause.setText("⏸ Пауза")
            self.btn_join.setEnabled(False)
            self.btn_login.setEnabled(False)
            self.btn_logout.setEnabled(False)
        except Exception:
            pass

    def on_worker_finished(self):
        try:
            self.btn_stop.setEnabled(False)
            self.btn_pause.setEnabled(False)
            self.btn_pause.setText("⏸ Пауза")
            self.btn_join.setEnabled(True)
            self.btn_login.setEnabled(True)
            self.btn_logout.setEnabled(True)
        except Exception:
            pass

    def on_generate_accounts(self):
        default_proxies_text = getattr(self, 'reg_proxies_last', '')
        dmin = getattr(self, 'reg_delay_min_last', 400)
        dmax = getattr(self, 'reg_delay_max_last', 900)
        def_set_avatar = getattr(self, 'reg_set_avatar_last', True)
        def_threads = getattr(self, 'reg_threads_last', 1)
        def_ppt = getattr(self, 'reg_ppt_last', 0)
        def_avatar_path = getattr(self, 'reg_avatar_path_last', '')
        dlg = GenerateAccountsDialog(default_count=int(getattr(self, 'reg_count_last', 100)), default_proxies_text=default_proxies_text, default_dmin=dmin, default_dmax=dmax, default_set_avatar=def_set_avatar, default_threads=def_threads, default_ppt=def_ppt, default_avatar_path=def_avatar_path, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cnt, proxies_list, delay_min_ms, delay_max_ms, set_avatar, threads, ppt, avatar_path = dlg.get_values()
        if cnt <= 0:
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        self.reg_count_last = int(cnt)
        self.reg_proxies_last = "\n".join(proxies_list)
        self.reg_delay_min_last = int(delay_min_ms)
        self.reg_delay_max_last = int(delay_max_ms)
        self.reg_set_avatar_last = bool(set_avatar)
        self.reg_threads_last = int(max(1, threads))
        self.reg_ppt_last = int(max(0, ppt))
        self.reg_avatar_path_last = avatar_path or getattr(self, 'reg_avatar_path_last', '')
        self.save_settings()
        if int(threads) > 1:
            self.worker.set_task(self.worker.task_register_fishpoker_parallel, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, int(threads), int(ppt), (avatar_path or None))
        else:
            self.worker.set_task(self.worker.task_register_fishpoker, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, (avatar_path or None))
        self.worker.start()

    def on_stop(self):
        if self.worker.isRunning():
            self.worker.stop(); self.log.appendPlainText(f"{Icons.WARNING} 🛑 Запрос на остановку отправлен...")
        else:
            QMessageBox.information(self, "Остановка", "Нет активных процессов для остановки")

    def on_task_finished(self):
        # Не сбрасываем внутренние флаги worker здесь — это ломает мгновенную остановку.
        try:
            self.btn_stop.setEnabled(False)
            self.btn_pause.setEnabled(False)
            self.btn_pause.setText("⏸ Пауза")
        except Exception:
            pass

    def on_new_account(self, acc: Account):
        self.accounts.append(acc)
        self._append_account_row(acc)
        self.worker.accounts = self.accounts
        try:
            self.account_row_by_username[acc.username.lower()] = len(self.accounts)-1
        except Exception:
            pass
        self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен зарегистрированный аккаунт: {acc.username}")
        self.save_settings()

    def on_export_report(self):
        if not self.report_rows:
            QMessageBox.information(self, "Нет данных", "Пока нет данных для отчета"); return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "", "Excel (*.xlsx)")
        if not path: return
        try:
            import pandas as pd
            report_data = []
            for jr in self.report_rows:
                report_data.append(jr.as_dict() if hasattr(jr, 'as_dict') else jr)
            df = pd.DataFrame(report_data)
            if len(df.columns) > 0:
                column_order = [col for col in REPORT_COLUMNS if col in df.columns]
                if column_order:
                    df = df[column_order]
            df.to_excel(path, index=False)
            self.log.appendPlainText(f"{Icons.SUCCESS} Отчет сохранен: {path}")
            self.log.appendPlainText(f"{Icons.INFO} Экспортировано записей: {len(report_data)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))

    def update_clubs_count(self):
        self.clubs_count_label.setText(f"Клубов: {len(self.club_ids)}")

    def save_settings(self):
        settings = {
            'accounts': [{
                'username': acc.username,
                'password': acc.password,
                'device_id': acc.device_id,
                'proxy': acc.proxy,
                'refresh_token': acc.refresh_token,
                'access_token_expire': acc.access_token_expire,
                'refresh_token_expire': acc.refresh_token_expire,
            } for acc in self.accounts],
            'club_ids': self.club_ids,
            'settings': {
                'clubs_per_account': self.spn_clubs_per_account.value(),
                'delay_min_ms': self.spn_delay_min.value(),
                'delay_max_ms': self.spn_delay_max.value(),
                'shuffle_clubs': self.chk_shuffle.isChecked(),
                'apply_message': self.txt_message.text(),
                'join_threads': int(self.spn_join_threads.value()),
                'reg_count': int(getattr(self, 'reg_count_last', 100)),
                'reg_proxies': getattr(self, 'reg_proxies_last', ''),
                'reg_delay_min_ms': int(getattr(self, 'reg_delay_min_last', 400)),
                'reg_delay_max_ms': int(getattr(self, 'reg_delay_max_last', 900)),
                'reg_set_avatar': bool(getattr(self, 'reg_set_avatar_last', True)),
                'reg_threads': int(getattr(self, 'reg_threads_last', 1)),
                'reg_proxies_per_thread': int(getattr(self, 'reg_ppt_last', 0)),
                'reg_avatar_path': str(getattr(self, 'reg_avatar_path_last', '')),
            }
        }
        try:
            from pathlib import Path
            p = Path('files')/"fishpoker_settings.json"
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def load_settings(self):
        from pathlib import Path
        p = Path('files')/"fishpoker_settings.json"
        if not p.exists():
            self.log.appendPlainText(f"{Icons.INFO} Файл настроек FishPoker не найден, используем значения по умолчанию")
            return
        try:
            if p.stat().st_size == 0:
                raise ValueError("empty settings file")
            with open(p, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            self.accounts.clear(); self.tbl.setRowCount(0)
            for acc_data in settings.get('accounts', []):
                raw_dev = acc_data.get('device_id') or ""
                uname = acc_data.get('username','')
                acc = Account(
                    username=uname,
                    password=acc_data.get('password',''),
                    device_id=self._ensure_device_id(raw_dev, uname),
                    proxy=acc_data.get('proxy'),
                )
                acc.refresh_token = acc_data.get('refresh_token')
                acc.access_token_expire = acc_data.get('access_token_expire')
                acc.refresh_token_expire = acc_data.get('refresh_token_expire')
                self.accounts.append(acc); self._append_account_row(acc)
            self.club_ids = settings.get('club_ids', [])
            self.update_clubs_count()
            ui = settings.get('settings', {})
            self.spn_clubs_per_account.setValue(ui.get('clubs_per_account', 500))
            self.spn_delay_min.setValue(ui.get('delay_min_ms', 500))
            self.spn_delay_max.setValue(ui.get('delay_max_ms', 1500))
            self.chk_shuffle.setChecked(ui.get('shuffle_clubs', True))
            self.txt_message.setText(ui.get('apply_message',''))
            try:
                self.spn_join_threads.setValue(int(ui.get('join_threads', 64)))
            except Exception:
                pass
            self.reg_count_last = int(ui.get('reg_count', 100))
            self.reg_proxies_last = ui.get('reg_proxies','')
            self.reg_delay_min_last = int(ui.get('reg_delay_min_ms', 400))
            self.reg_delay_max_last = int(ui.get('reg_delay_max_ms', 900))
            self.reg_set_avatar_last = bool(ui.get('reg_set_avatar', True))
            self.reg_threads_last = int(ui.get('reg_threads', 1))
            self.reg_ppt_last = int(ui.get('reg_proxies_per_thread', 0))
            self.reg_avatar_path_last = ui.get('reg_avatar_path', '')
            self.worker.accounts = self.accounts
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружены настройки: {len(self.accounts)} аккаунтов, {len(self.club_ids)} клубов")
        except Exception:
            try:
                p.rename(p.with_suffix('.bak'))
            except Exception:
                pass
            self.accounts.clear(); self.tbl.setRowCount(0); self.club_ids = []; self.update_clubs_count()
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка загрузки настроек FishPoker. Загружены значения по умолчанию")


class PPPokerTab(QWidget):
    def update_table_theme(self) -> None:
        """Светлая/тёмная тема таблицы — как у XPoker, но селекторы без id для строгого применения."""
        try:
            t = self.tbl
        except Exception:
            return
        if not isinstance(t, QTableWidget):
            return
        # Определяем эффективный режим темы из окна (QTabWidget может переписать parent)
        eff = 'light'
        try:
            mw = self.window()
            if not (mw and hasattr(mw, 'current_theme_mode')):
                # Поищем выше по иерархии
                p = self.parent()
                while p is not None and not hasattr(p, 'current_theme_mode'):
                    p = getattr(p, 'parent', lambda: None)()
                if p is not None:
                    mw = p
            if mw and getattr(mw, 'current_theme_mode', None) in ('light', 'dark'):
                eff = mw.current_theme_mode
        except Exception:
            pass
        if eff == 'dark':
            try:
                t.setStyleSheet(
                    "QTableWidget, QTableView, QTableWidget::viewport, QTableView::viewport {"
                    " background-color: #1e1e1e;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #1e1e1e;"
                    "}"
                )
                t.viewport().setStyleSheet("background-color: #1e1e1e;")
            except Exception:
                pass
            try:
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet(
                        "QHeaderView { background-color: #1e1e1e; }"
                        "QHeaderView::section { background-color: #1e1e1e; color: #d0d0d0; border: none; }"
                    )
                    pal = vh.palette()
                    pal.setColor(QPalette.ColorRole.Button, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
                    vh.setPalette(pal)
                    vh.setAutoFillBackground(True)
            except Exception:
                pass
        else:
            try:
                # Сбрасываем QSS/палитры
                t.setStyleSheet("")
                t.viewport().setStyleSheet("")
                try:
                    pal = QApplication.palette()
                    t.setPalette(pal)
                    t.viewport().setAutoFillBackground(False)
                except Exception:
                    pass
                # Хедеры
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet("")
                    vh.setAutoFillBackground(False)
                    try:
                        vh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                hh = t.horizontalHeader()
                if hh is not None:
                    hh.setStyleSheet("")
                    try:
                        hh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                # Стиль как у XPoker (без id)
                ss_light = (
                    "QTableWidget, QTableWidget::viewport {"
                    " background-color: #f7f7f7;"
                    " alternate-background-color: #ffffff;"
                    "}"
                    "QTableWidget {"
                    " gridline-color: #e0e0e0;"
                    "}"
                    "QHeaderView::section:horizontal {"
                    " background-color: #fafafa; color: #222; border: 1px solid #e6e6e6; padding: 4px;"
                    "}"
                    "QHeaderView::section:vertical {"
                    " background-color: #f7f7f7; color: #666; border: none;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #fafafa; border: 1px solid #e6e6e6;"
                    "}"
                    "QTableWidget::item:selected {"
                    " background-color: #cfe8ff; color: #000;"
                    "}"
                )
                try:
                    t.setAlternatingRowColors(True)
                except Exception:
                    pass
                try:
                    t.setStyleSheet(ss_light)
                except Exception:
                    pass
                try:
                    t.style().unpolish(t)
                    t.style().polish(t)
                    t.update()
                except Exception:
                    pass
            except Exception:
                pass

    def _imei40(self, seed: str) -> str:
        try:
            import hashlib
            s = (seed or '').replace('-', '').strip()
            if not s:
                s = 'pppoker'
            return hashlib.sha1(s.encode('utf-8')).hexdigest()
        except Exception:
            # Фолбэк на фиксированное значение
            return 'd98cc29319f8ff44f171963a3f959a0c07803c4a'

    def _ensure_imei(self, value: str, username: str) -> str:
        import re
        v = (value or '').strip()
        if re.fullmatch(r'[0-9a-fA-F]{40}', v):
            return v.lower()
        # если это UUID — уберём дефисы и захешируем; иначе возьмём username
        seed = v if v else username
        return self._imei40(seed)

    def __init__(self, parent=None):
        super().__init__(parent)
        from pppoker.api import PPPokerAPI, ApiError as PPPApiError
        # State
        self.accounts: List[Account] = []
        self.club_ids: List[str] = []
        self.report_rows: List[dict] = []
        self.account_row_by_username: Dict[str, int] = {}
        self._suppress_item_changed = False

        # Layout
        v = QVBoxLayout(self)

        # Accounts group
        accounts_group = QGroupBox("📋 Управление аккаунтами")
        accounts_layout = QHBoxLayout(accounts_group)
        self.btn_add_account = QPushButton("➕ Добавить аккаунт")
        self.btn_edit_account = QPushButton("✏️ Редактировать")
        self.btn_delete_account = QPushButton("🗑️ Удалить")
        self.btn_load_accounts = QPushButton("📁 Из Excel файла")
        self.btn_save_accounts = QPushButton("💾 Сохранить настройки")
        self.btn_generate_accounts = QPushButton("🧪 Сгенерировать аккаунты")
        for b in (self.btn_add_account, self.btn_edit_account, self.btn_delete_account, self.btn_load_accounts, self.btn_save_accounts, self.btn_generate_accounts):
            accounts_layout.addWidget(b)
        accounts_layout.addStretch()
        v.addWidget(accounts_group)

        # Clubs group
        clubs_group = QGroupBox("🏛️ Управление клубами")
        clubs_layout = QHBoxLayout(clubs_group)
        self.btn_add_clubs = QPushButton("➕ Добавить клубы")
        self.btn_clear_clubs = QPushButton("🗑️ Очистить список")
        self.btn_load_clubs = QPushButton("📁 Из Excel файла")
        self.btn_load_club_distribution = QPushButton("📊 Распределение клубов")
        self.clubs_count_label = QLabel("Клубов: 0")
        for b in (self.btn_add_clubs, self.btn_clear_clubs, self.btn_load_clubs, self.btn_load_club_distribution):
            clubs_layout.addWidget(b)
        clubs_layout.addWidget(self.clubs_count_label)
        clubs_layout.addStretch()
        v.addWidget(clubs_group)

        # Operations group
        operations_group = QGroupBox("🚀 Операции")
        operations_layout = QHBoxLayout(operations_group)
        self.btn_login = QPushButton("🔐 Войти во все")
        self.btn_logout = QPushButton("🚪 Выйти из выбранных")
        self.btn_join = QPushButton("🎯 Начать вступление")
        self.btn_pause = QPushButton("⏸ Пауза"); self.btn_pause.setEnabled(False)
        self.btn_stop = QPushButton("🛑 Остановить"); self.btn_stop.setEnabled(False)
        self.btn_export = QPushButton("📊 Экспорт отчета")
        for b in (self.btn_login, self.btn_logout, self.btn_join, self.btn_pause, self.btn_stop, self.btn_export):
            operations_layout.addWidget(b)
        operations_layout.addStretch()
        v.addWidget(operations_group)

        # Knobs
        knobs = QHBoxLayout()
        knobs.addWidget(QLabel("Клубов на аккаунт (0 = все клубы):"))
        self.spn_clubs_per_account = QSpinBox(); self.spn_clubs_per_account.setRange(0, 1000000); self.spn_clubs_per_account.setValue(500)
        knobs.addWidget(self.spn_clubs_per_account)
        knobs.addWidget(QLabel("Задержка мин (мс):"))
        self.spn_delay_min = QSpinBox(); self.spn_delay_min.setRange(0, 10000); self.spn_delay_min.setValue(500)
        knobs.addWidget(self.spn_delay_min)
        knobs.addWidget(QLabel("Задержка макс (мс):"))
        self.spn_delay_max = QSpinBox(); self.spn_delay_max.setRange(0, 20000); self.spn_delay_max.setValue(1500)
        knobs.addWidget(self.spn_delay_max)
        knobs.addWidget(QLabel("Параллельно (TCP):"))
        self.spn_join_threads = QSpinBox(); self.spn_join_threads.setRange(1, 1000); self.spn_join_threads.setValue(64)
        knobs.addWidget(self.spn_join_threads)
        self.chk_shuffle = QCheckBox("Перемешать ID клубов"); self.chk_shuffle.setChecked(True)
        knobs.addWidget(self.chk_shuffle)
        v.addLayout(knobs)

        # Message field (40 chars)
        msg_row = QHBoxLayout()
        msg_row.addWidget(QLabel("Сообщение заявки (до 40 символов):"))
        self.txt_message = QLineEdit(); self.txt_message.setMaxLength(40); self.txt_message.setPlaceholderText("Например: Примите, пожалуйста")
        msg_row.addWidget(self.txt_message)
        v.addLayout(msg_row)

        # Accounts table
        base_cols = len(ACCOUNTS_COLUMNS)
        self.PROG_COL = base_cols + 0
        self.STATUS_COL = base_cols + 1
        self.CURRENT_COL = base_cols + 2
        self.tbl = QTableWidget(0, base_cols + len(EXTRA_COLUMNS))
        self.tbl.setObjectName("accountsTable")
        self.tbl.setHorizontalHeaderLabels(ACCOUNTS_COLUMNS + EXTRA_COLUMNS)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.itemChanged.connect(self.on_cell_changed)
        v.addWidget(self.tbl, stretch=1)

        v.addWidget(QLabel("Журнал событий:"))
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        v.addWidget(self.log, stretch=1)

        # Worker
        self.worker = Worker(self.accounts, api_class=PPPokerAPI, api_error_class=PPPApiError)
        self.worker.log.connect(self.on_worker_log)
        self.worker.account_updated.connect(self.on_account_updated)
        self.worker.join_result.connect(self.on_join_result)
        self.worker.task_finished.connect(self.on_task_finished)
        self.worker.pause_changed.connect(self.on_worker_pause_changed)
        self.worker.account_progress.connect(self.on_account_progress)
        try:
            self.worker.new_account.connect(self.on_new_account)
        except Exception:
            pass
        # Управление состоянием кнопок как в XPoker
        try:
            self.worker.started.connect(self.on_worker_started)
            self.worker.finished.connect(self.on_worker_finished)
        except Exception:
            pass

        # Wire up buttons
        self.btn_add_account.clicked.connect(self.on_add_account)
        self.btn_edit_account.clicked.connect(self.on_edit_account)
        self.btn_delete_account.clicked.connect(self.on_delete_account)
        self.btn_load_accounts.clicked.connect(self.on_load_accounts)
        self.btn_save_accounts.clicked.connect(self.on_save_accounts)
        self.btn_generate_accounts.clicked.connect(self.on_generate_accounts)
        self.btn_add_clubs.clicked.connect(self.on_add_clubs)
        self.btn_clear_clubs.clicked.connect(self.on_clear_clubs)
        self.btn_load_clubs.clicked.connect(self.on_load_clubs)
        self.btn_load_club_distribution.clicked.connect(self.on_load_club_distribution)
        self.btn_login.clicked.connect(self.on_login_all)
        self.btn_logout.clicked.connect(self.on_logout_selected)
        self.btn_join.clicked.connect(self.on_join)
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_export.clicked.connect(self.on_export_report)
        # Auto-save UI knobs on change
        try:
            self.spn_clubs_per_account.valueChanged.connect(self.save_settings)
            self.spn_delay_min.valueChanged.connect(self.save_settings)
            self.spn_delay_max.valueChanged.connect(self.save_settings)
            self.chk_shuffle.toggled.connect(self.save_settings)
            self.txt_message.textChanged.connect(self.save_settings)
        except Exception:
            pass

        # Load settings
        self.load_settings()
        # Apply table theme now and when main theme changes
        try:
            self.update_table_theme()
        except Exception:
            pass

    # ====== Event handlers / helpers (PPPoker) ======
    def on_worker_log(self, line: str):
        self.log.appendPlainText(line)

    def on_save_accounts(self):
        try:
            self.save_settings()
            QMessageBox.information(self, "Сохранение", "Настройки сохранены успешно!")
            self.log.appendPlainText(f"{Icons.SUCCESS} Настройки сохранены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить настройки: {e}")

    def _append_account_row(self, acc: Account):
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        data = acc.as_row()
        self._suppress_item_changed = True
        try:
            for c, v in enumerate(data):
                it = QTableWidgetItem(str(v))
                if c in (1, 4, 5):
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(r, c, it)
            prog = QProgressBar(); prog.setRange(0,1); prog.setValue(0); prog.setTextVisible(True); prog.setFormat("0/0 (0%)")
            self.tbl.setCellWidget(r, self.PROG_COL, prog)
            st_it = QTableWidgetItem("⏳ Ожидание"); st_it.setFlags(st_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.STATUS_COL, st_it)
            cur_it = QTableWidgetItem("-"); cur_it.setFlags(cur_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.CURRENT_COL, cur_it)
        finally:
            self._suppress_item_changed = False
        self.account_row_by_username[acc.username.lower()] = r

    def on_cell_changed(self, item: QTableWidgetItem):
        if self._suppress_item_changed:
            return
        row = item.row(); col = item.column()
        if row < 0 or row >= len(self.accounts):
            return
        acc = self.accounts[row]
        text = item.text().strip()
        if col in (1,4,5):
            self._suppress_item_changed = True
            try:
                current = acc.as_row()[col]
                item.setText(str(current))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            finally:
                self._suppress_item_changed = False
            return
        changed = False
        if col == 0 and text and text != acc.username:
            acc.username = text; changed = True
        elif col == 2:
            new_proxy = text or None
            if new_proxy != (acc.proxy or None):
                acc.proxy = new_proxy; changed = True
        elif col == 3 and text != (acc.device_id or ""):
            acc.device_id = self._ensure_imei(text, acc.username); changed = True
            # Обновим ячейку нормализованным значением
            self._suppress_item_changed = True
            try:
                it = QTableWidgetItem(acc.device_id)
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 3, it)
            finally:
                self._suppress_item_changed = False
        if changed:
            acc.token = None; acc.last_login_at = None
            self._suppress_item_changed = True
            try:
                tok_it = QTableWidgetItem(""); tok_it.setFlags(tok_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 4, tok_it)
                last_it = QTableWidgetItem(""); last_it.setFlags(last_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 5, last_it)
            finally:
                self._suppress_item_changed = False
            self.account_row_by_username = {a.username.lower(): i for i,a in enumerate(self.accounts)}
            self.worker.accounts = self.accounts
            self.save_settings()

    def on_account_updated(self, row: int, data: list):
        self._suppress_item_changed = True
        try:
            for col, val in enumerate(data):
                it = QTableWidgetItem(str(val))
                if col in (1, 4, 5):
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, col, it)
            it_status = self.tbl.item(row, self.STATUS_COL)
            if it_status:
                it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
            it_curr = self.tbl.item(row, self.CURRENT_COL)
            if it_curr:
                it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        finally:
            self._suppress_item_changed = False

    def on_account_progress(self, username: str, done: int, total: int, status_text: str, current_club: str):
        row = self.account_row_by_username.get(username.lower())
        if row is None:
            return
        w = self.tbl.cellWidget(row, self.PROG_COL)
        if isinstance(w, QProgressBar):
            w.setRange(0, max(total,1))
            w.setValue(max(0, min(done, total)))
            percent = (0 if total == 0 else int((done/total)*100))
            w.setFormat(f"{done}/{total} ({percent}%)")
        it_status = QTableWidgetItem(status_text); it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.STATUS_COL, it_status)
        it_curr = QTableWidgetItem(current_club); it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.CURRENT_COL, it_curr)

    def on_join_result(self, jr: JoinResult):
        self.report_rows.append(jr)

    def on_add_account(self):
        dialog = AccountDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            # Сразу формируем IMEI (40-hex)
            imei = self._ensure_imei('', data['username'])
            acc = Account(username=data['username'], password=data['password'], device_id=imei, proxy=data['proxy'])
            self.accounts.append(acc)
            self._append_account_row(acc)
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен аккаунт: {acc.username}")

    def on_edit_account(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строку для редактирования"); return
        if len(rows) > 1:
            QMessageBox.information(self, "Выбор", "Выберите только одну строку для редактирования"); return
        row = rows[0]
        if row >= len(self.accounts):
            return
        acc = self.accounts[row]
        dialog = AccountDialog(account=acc, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            acc.username = data['username']; acc.password = data['password']; acc.proxy = data['proxy']
            acc.token = None; acc.last_login_at = None
            for col, val in enumerate(acc.as_row()):
                self.tbl.setItem(row, col, QTableWidgetItem(str(val)))
            self.account_row_by_username[acc.username.lower()] = row
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Отредактирован аккаунт: {acc.username}")

    def on_delete_account(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()}, reverse=True)
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для удаления"); return
        reply = QMessageBox.question(self, "Подтверждение", f"Удалить {len(rows)} аккаунт(ов)?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            deleted = []
            for r in rows:
                if r < len(self.accounts):
                    deleted.append(self.accounts[r].username)
                    del self.accounts[r]; self.tbl.removeRow(r)
            self.worker.accounts = self.accounts
            self.save_settings()
            if deleted:
                self.log.appendPlainText(f"{Icons.SUCCESS} Удалены аккаунты: {', '.join(deleted)}")

    def on_add_clubs(self):
        dialog = ClubIdDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_club_ids = dialog.get_club_ids()
            if new_club_ids:
                existing = set(self.club_ids)
                added = []
                for club_id in new_club_ids:
                    if club_id not in existing:
                        self.club_ids.append(club_id)
                        existing.add(club_id)
                        added.append(club_id)
                if self.chk_shuffle.isChecked() and self.club_ids:
                    import random; random.shuffle(self.club_ids)
                    self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан")
                self.update_clubs_count(); self.save_settings()
                if added:
                    self.log.appendPlainText(f"{Icons.SUCCESS} Добавлено {len(added)} новых клубов: {', '.join(added)}")
                else:
                    self.log.appendPlainText(f"{Icons.INFO} Все введённые клубы уже есть в списке")
            else:
                QMessageBox.information(self, "Данные", "Не введено ни одного корректного ID клуба")

    def on_clear_clubs(self):
        if self.club_ids:
            reply = QMessageBox.question(self, "Подтверждение", f"Очистить список из {len(self.club_ids)} клубов?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.club_ids.clear(); self.update_clubs_count(); self.save_settings(); self.log.appendPlainText(f"{Icons.SUCCESS} Список клубов очищен")
        else:
            QMessageBox.information(self, "Список пуст", "Список клубов уже пуст")

    def on_load_accounts(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с аккаунтами", "", "Excel (*.xlsx)")
        if not path:
            return
        import pandas as pd
        df = pd.read_excel(path)
        df.columns = [str(c).lower().strip() for c in df.columns]
        if not {"username", "password"}.issubset(df.columns):
            QMessageBox.critical(self, "Ошибка", "Требуются колонки: username, password"); return
        self.accounts.clear(); self.tbl.setRowCount(0)
        for _, row in df.iterrows():
            proxy_val = row.get("proxy"); proxy_val = (None if (pd.isna(proxy_val) or str(proxy_val).strip()=="") else str(proxy_val).strip())
            device_id_val = row.get("device_id"); device_id_str = str(device_id_val).strip() if device_id_val is not None and not pd.isna(device_id_val) else ""
            username = str(row['username']).strip()
            imei = self._ensure_imei(device_id_str, username)
            acc = Account(username=username, password=str(row['password']).strip(), proxy=proxy_val, device_id=imei)
            self.accounts.append(acc); self._append_account_row(acc)
        self.worker.accounts = self.accounts
        self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.accounts)} аккаунтов")

    def on_load_clubs(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с клубами", "", "Excel (*.xlsx)")
        if not path: return
        import pandas as pd
        df = pd.read_excel(path)
        col = None
        for c in df.columns:
            if str(c).lower() in ("club_id","id","clubid"):
                col = c; break
        if not col:
            QMessageBox.critical(self, "Ошибка", "Не найдена колонка 'club_id'"); return
        self.club_ids = [str(x) for x in df[col].dropna().astype(str).tolist()]
        if self.chk_shuffle.isChecked():
            import random; random.shuffle(self.club_ids)
        self.update_clubs_count(); self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.club_ids)} ID клубов")

    def on_load_club_distribution(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты!"); return
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с распределением клубов", "", "Excel (*.xlsx)")
        if not path: return
        try:
            import pandas as pd
            df = pd.read_excel(path)
            df.columns = [str(c).lower().strip() for c in df.columns]
            username_col = clubs_count_col = None
            for c in df.columns:
                if str(c).lower() in ("username", "user", "имя пользователя", "логин", "аккаунт"):
                    username_col = c
                if str(c).lower() in ("clubs_count", "clubs", "количество клубов", "клубов", "count"):
                    clubs_count_col = c
            if not username_col or not clubs_count_col:
                QMessageBox.critical(self, "Ошибка", "Не найдены нужные колонки в файле"); return
            self.worker.account_club_limits.clear()
            loaded = 0
            for _, row in df.iterrows():
                username = str(row[username_col]).strip()
                try:
                    clubs_count = int(row[clubs_count_col]); clubs_count = max(0, clubs_count)
                except Exception:
                    continue
                if any(acc.username.lower()==username.lower() for acc in self.accounts):
                    self.worker.account_club_limits[username.lower()] = clubs_count
                    loaded += 1
            if loaded == 0:
                QMessageBox.warning(self, "Предупреждение", "Не найдено совпадений аккаунтов"); return
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружено распределение для {loaded} аккаунтов")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка загрузки", str(e))

    def on_login_all(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        self.worker.set_task(self.worker.task_login_all)
        self.worker.start()

    def on_logout_selected(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для выхода"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        self.worker.set_task(self.worker.task_logout_selected, rows)
        self.worker.start()

    def on_join(self):
        if not self.club_ids:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите клубы"); return
        if not any(a.token for a in self.accounts):
            QMessageBox.critical(self, "Ошибка", "Сначала войдите в аккаунты (нет токенов)"); return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        clubs_to_process = self.club_ids.copy()
        if self.chk_shuffle.isChecked():
            import random; random.shuffle(clubs_to_process); self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан для обработки")
        limit = self.spn_clubs_per_account.value()
        dmin = self.spn_delay_min.value(); dmax = self.spn_delay_max.value()
        if dmax < dmin:
            dmin, dmax = dmax, dmin
        message_text = self.txt_message.text().strip()
        self.worker.set_task(self.worker.task_join_round, clubs_to_process, limit, dmin, dmax, message_text, int(self.spn_join_threads.value()))
        self.worker.start()

    def on_pause(self):
        if not self.worker.isRunning():
            QMessageBox.information(self, "Пауза", "Нет активного процесса для паузы"); return
        self.worker.pause_toggle()

    def on_worker_pause_changed(self, paused: bool):
        self.btn_pause.setText("▶️ Продолжить" if paused else "⏸ Пауза")
        self.save_settings()

    def on_worker_started(self):
        try:
            self.btn_stop.setEnabled(True)
            self.btn_pause.setEnabled(True)
            self.btn_pause.setText("⏸ Пауза")
            # Отключить операции на время выполнения
            self.btn_join.setEnabled(False)
            self.btn_login.setEnabled(False)
            self.btn_logout.setEnabled(False)
        except Exception:
            pass

    def on_worker_finished(self):
        try:
            self.btn_stop.setEnabled(False)
            self.btn_pause.setEnabled(False)
            self.btn_pause.setText("⏸ Пауза")
            # Вернуть операции
            self.btn_join.setEnabled(True)
            self.btn_login.setEnabled(True)
            self.btn_logout.setEnabled(True)
        except Exception:
            pass
        # Сброс прогресса после завершения задачи (оставляем полосу видимой)
        try:
            if hasattr(self, 'status_progress'):
                self._progress_mode = ""
                self._progress_total = 0
                self._progress_done = 0
                self._progress_seen = set()
                self.status_progress.setRange(0, 1)
                self.status_progress.setValue(0)
                self.status_progress.setFormat("Готово")
        except Exception:
            pass

    def on_generate_accounts(self):
        # Диалог как в XPoker
        default_proxies_text = getattr(self, 'reg_proxies_last', '')
        dmin = getattr(self, 'reg_delay_min_last', 400)
        dmax = getattr(self, 'reg_delay_max_last', 900)
        def_set_avatar = getattr(self, 'reg_set_avatar_last', True)
        def_threads = getattr(self, 'reg_threads_last', 1)
        def_ppt = getattr(self, 'reg_ppt_last', 0)
        def_avatar_path = getattr(self, 'reg_avatar_path_last', '')
        dlg = GenerateAccountsDialog(default_count=int(getattr(self, 'reg_count_last', 100)), default_proxies_text=default_proxies_text, default_dmin=dmin, default_dmax=dmax, default_set_avatar=def_set_avatar, default_threads=def_threads, default_ppt=def_ppt, default_avatar_path=def_avatar_path, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cnt, proxies_list, delay_min_ms, delay_max_ms, set_avatar, threads, ppt, avatar_path = dlg.get_values()
        if cnt <= 0:
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        # Сохраняем последние параметры
        self.reg_count_last = int(cnt)
        self.reg_proxies_last = "\n".join(proxies_list)
        self.reg_delay_min_last = int(delay_min_ms)
        self.reg_delay_max_last = int(delay_max_ms)
        self.reg_set_avatar_last = bool(set_avatar)
        self.reg_threads_last = int(max(1, threads))
        self.reg_ppt_last = int(max(0, ppt))
        self.reg_avatar_path_last = avatar_path or getattr(self, 'reg_avatar_path_last', '')
        self.save_settings()
        # Запускаем задачу регистрации PPPoker (параллельно если threads>1)
        if int(threads) > 1:
            self.worker.set_task(self.worker.task_register_pppoker_parallel, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, int(threads), int(ppt), (avatar_path or None))
        else:
            self.worker.set_task(self.worker.task_register_pppoker, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, (avatar_path or None))
        self.worker.start()

    def on_stop(self):
        if self.worker.isRunning():
            self.worker.stop(); self.log.appendPlainText(f"{Icons.WARNING} 🛑 Запрос на остановку отправлен...")
        else:
            QMessageBox.information(self, "Остановка", "Нет активных процессов для остановки")

    def on_task_finished(self):
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸ Пауза")


    def on_new_account(self, acc: Account):
        # Добавляем аккаунт в таблицу
        self.accounts.append(acc)
        self._append_account_row(acc)
        self.worker.accounts = self.accounts
        try:
            self.account_row_by_username[acc.username.lower()] = len(self.accounts)-1
        except Exception:
            pass
        self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен зарегистрированный аккаунт: {acc.username}")
        # Автосохранение настроек
        self.save_settings()

    def on_export_report(self):
        if not self.report_rows:
            QMessageBox.information(self, "Нет данных", "Пока нет данных для отчета"); return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "", "Excel (*.xlsx)")
        if not path: return
        try:
            import pandas as pd
            report_data = []
            for jr in self.report_rows:
                report_data.append(jr.as_dict() if hasattr(jr, 'as_dict') else jr)
            df = pd.DataFrame(report_data)
            if len(df.columns) > 0:
                column_order = [col for col in REPORT_COLUMNS if col in df.columns]
                if column_order:
                    df = df[column_order]
            df.to_excel(path, index=False)
            self.log.appendPlainText(f"{Icons.SUCCESS} Отчет сохранен: {path}")
            self.log.appendPlainText(f"{Icons.INFO} Экспортировано записей: {len(report_data)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))

    def update_clubs_count(self):
        self.clubs_count_label.setText(f"Клубов: {len(self.club_ids)}")

    def save_settings(self):
        settings = {
            'accounts': [{
                'username': acc.username,
                'password': acc.password,
                'device_id': acc.device_id,
                'proxy': acc.proxy,
                'refresh_token': acc.refresh_token,
                'access_token_expire': acc.access_token_expire,
                'refresh_token_expire': acc.refresh_token_expire,
            } for acc in self.accounts],
            'club_ids': self.club_ids,
'settings': {
                'clubs_per_account': self.spn_clubs_per_account.value(),
                'delay_min_ms': self.spn_delay_min.value(),
                'delay_max_ms': self.spn_delay_max.value(),
                'shuffle_clubs': self.chk_shuffle.isChecked(),
                'apply_message': self.txt_message.text(),
                'join_threads': int(self.spn_join_threads.value()),
                'reg_count': int(getattr(self, 'reg_count_last', 100)),
                'reg_proxies': getattr(self, 'reg_proxies_last', ''),
                'reg_delay_min_ms': int(getattr(self, 'reg_delay_min_last', 400)),
                'reg_delay_max_ms': int(getattr(self, 'reg_delay_max_last', 900)),
                'reg_set_avatar': bool(getattr(self, 'reg_set_avatar_last', True)),
                'reg_threads': int(getattr(self, 'reg_threads_last', 1)),
                'reg_proxies_per_thread': int(getattr(self, 'reg_ppt_last', 0)),
                'reg_avatar_path': str(getattr(self, 'reg_avatar_path_last', '')),
            }
        }
        try:
            from pathlib import Path
            p = Path('files')/"pppoker_settings.json"
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def load_settings(self):
        from pathlib import Path
        p = Path('files')/"pppoker_settings.json"
        if not p.exists():
            self.log.appendPlainText(f"{Icons.INFO} Файл настроек PPPoker не найден, используем значения по умолчанию")
            return
        try:
            if p.stat().st_size == 0:
                raise ValueError("empty settings file")
            with open(p, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            self.accounts.clear(); self.tbl.setRowCount(0)
            for acc_data in settings.get('accounts', []):
                raw_dev = acc_data.get('device_id') or ""
                uname = acc_data.get('username','')
                acc = Account(
                    username=uname,
                    password=acc_data.get('password',''),
                    device_id=self._ensure_imei(raw_dev, uname),
                    proxy=acc_data.get('proxy'),
                )
                acc.refresh_token = acc_data.get('refresh_token')
                acc.access_token_expire = acc_data.get('access_token_expire')
                acc.refresh_token_expire = acc_data.get('refresh_token_expire')
                self.accounts.append(acc); self._append_account_row(acc)
            self.club_ids = settings.get('club_ids', [])
            self.update_clubs_count()
            ui = settings.get('settings', {})
            self.spn_clubs_per_account.setValue(ui.get('clubs_per_account', 500))
            self.spn_delay_min.setValue(ui.get('delay_min_ms', 500))
            self.spn_delay_max.setValue(ui.get('delay_max_ms', 1500))
            self.chk_shuffle.setChecked(ui.get('shuffle_clubs', True))
            self.txt_message.setText(ui.get('apply_message',''))
            try:
                self.spn_join_threads.setValue(int(ui.get('join_threads', 64)))
            except Exception:
                pass
            # restore last reg params
            self.reg_count_last = int(ui.get('reg_count', 100))
            self.reg_proxies_last = ui.get('reg_proxies','')
            self.reg_delay_min_last = int(ui.get('reg_delay_min_ms', 400))
            self.reg_delay_max_last = int(ui.get('reg_delay_max_ms', 900))
            self.reg_set_avatar_last = bool(ui.get('reg_set_avatar', True))
            self.reg_threads_last = int(ui.get('reg_threads', 1))
            self.reg_ppt_last = int(ui.get('reg_proxies_per_thread', 0))
            self.reg_avatar_path_last = ui.get('reg_avatar_path', '')
            self.worker.accounts = self.accounts
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружены настройки: {len(self.accounts)} аккаунтов, {len(self.club_ids)} клубов")
        except Exception:
            try:
                p.rename(p.with_suffix('.bak'))
            except Exception:
                pass
            self.accounts.clear(); self.tbl.setRowCount(0); self.club_ids = []; self.update_clubs_count()
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка загрузки настроек PPPoker. Загружены значения по умолчанию")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 760)

        self.accounts: List[Account] = []
        self.club_ids: List[str] = []
        self.report_rows: List[dict] = []

        # Вкладки: XPoker (основной) + PPPoker
        self.tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tabs)

        xp_root = QWidget()
        self.tabs.addTab(xp_root, "XPoker")
        v = QVBoxLayout(xp_root)

        # 🔸 СЕКЦИЯ УПРАВЛЕНИЯ АККАУНТАМИ
        accounts_group = QGroupBox("📋 Управление аккаунтами")
        accounts_layout = QHBoxLayout(accounts_group)
        
        self.btn_add_account = QPushButton("➕ Добавить аккаунт")
        self.btn_edit_account = QPushButton("✏️ Редактировать")
        self.btn_delete_account = QPushButton("🗑️ Удалить")
        self.btn_load_accounts = QPushButton("📁 Из Excel файла")
        self.btn_save_accounts = QPushButton("💾 Сохранить настройки")
        self.btn_generate_accounts = QPushButton("🧪 Сгенерировать аккаунты")
        
        accounts_layout.addWidget(self.btn_add_account)
        accounts_layout.addWidget(self.btn_edit_account)
        accounts_layout.addWidget(self.btn_delete_account)
        accounts_layout.addWidget(self.btn_load_accounts)
        accounts_layout.addWidget(self.btn_save_accounts)
        accounts_layout.addWidget(self.btn_generate_accounts)
        accounts_layout.addStretch()
        v.addWidget(accounts_group)
        
        # 🔸 СЕКЦИЯ УПРАВЛЕНИЯ КЛУБАМИ
        clubs_group = QGroupBox("🏛️ Управление клубами")
        clubs_layout = QHBoxLayout(clubs_group)
        
        self.btn_add_clubs = QPushButton("➕ Добавить клубы")
        self.btn_clear_clubs = QPushButton("🗑️ Очистить список")
        self.btn_load_clubs = QPushButton("📁 Из Excel файла")
        self.btn_load_club_distribution = QPushButton("📊 Распределение клубов")
        self.clubs_count_label = QLabel("Клубов: 0")
        
        clubs_layout.addWidget(self.btn_add_clubs)
        clubs_layout.addWidget(self.btn_clear_clubs)
        clubs_layout.addWidget(self.btn_load_clubs)
        clubs_layout.addWidget(self.btn_load_club_distribution)
        clubs_layout.addWidget(self.clubs_count_label)
        clubs_layout.addStretch()
        v.addWidget(clubs_group)
        
        # 🔸 СЕКЦИЯ ОПЕРАЦИЙ
        operations_group = QGroupBox("🚀 Операции")
        operations_layout = QHBoxLayout(operations_group)
        
        self.btn_login = QPushButton("🔐 Войти во все")
        self.btn_logout = QPushButton("🚪 Выйти из выбранных")
        self.btn_join = QPushButton("🎯 Начать вступление")
        self.btn_pause = QPushButton("⏸ Пауза")
        self.btn_pause.setEnabled(False)
        self.btn_stop = QPushButton("🛑 Остановить")
        self.btn_export = QPushButton("📊 Экспорт отчета")
        self.btn_check_update = QPushButton("🔄 Проверить обновление")
        
        # Изначально кнопка остановки неактивна
        self.btn_stop.setEnabled(False)
        
        operations_layout.addWidget(self.btn_login)
        operations_layout.addWidget(self.btn_logout)
        operations_layout.addWidget(self.btn_join)
        operations_layout.addWidget(self.btn_pause)
        operations_layout.addWidget(self.btn_stop)
        operations_layout.addWidget(self.btn_export)
        # Контрол темы перенесён в статус-бар
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItem("Системная", userData='system')
        self.cmb_theme.addItem("Светлая", userData='light')
        self.cmb_theme.addItem("Тёмная", userData='dark')
        operations_layout.addStretch()
        v.addWidget(operations_group)

        knobs = QHBoxLayout()
        knobs.addWidget(QLabel("Клубов на аккаунт (0 = все клубы):"))
        self.spn_clubs_per_account = QSpinBox(); self.spn_clubs_per_account.setRange(0, 1000000); self.spn_clubs_per_account.setValue(500)
        knobs.addWidget(self.spn_clubs_per_account)
        knobs.addWidget(QLabel("Задержка мин (мс):"))
        self.spn_delay_min = QSpinBox(); self.spn_delay_min.setRange(0, 10000); self.spn_delay_min.setValue(500)
        knobs.addWidget(self.spn_delay_min)
        knobs.addWidget(QLabel("Задержка макс (мс):"))
        self.spn_delay_max = QSpinBox(); self.spn_delay_max.setRange(0, 20000); self.spn_delay_max.setValue(1500)
        knobs.addWidget(self.spn_delay_max)
        knobs.addWidget(QLabel("Параллельно (TCP):"))
        self.spn_join_threads = QSpinBox(); self.spn_join_threads.setRange(1, 1000); self.spn_join_threads.setValue(64)
        knobs.addWidget(self.spn_join_threads)
        self.chk_shuffle = QCheckBox("Перемешать ID клубов")
        self.chk_shuffle.setChecked(True)
        knobs.addWidget(self.chk_shuffle)
        v.addLayout(knobs)
        
        # Поле сообщения заявки (до 40 символов)
        msg_row = QHBoxLayout()
        msg_row.addWidget(QLabel("Сообщение заявки (до 40 символов):"))
        self.txt_message = QLineEdit()
        self.txt_message.setMaxLength(40)
        self.txt_message.setPlaceholderText("Например: Примите, пожалуйста")
        msg_row.addWidget(self.txt_message)
        v.addLayout(msg_row)
        
        # Таблица аккаунтов с дополнительными колонками прогресса
        base_cols = len(ACCOUNTS_COLUMNS)
        self.PROG_COL = base_cols + 0
        self.STATUS_COL = base_cols + 1
        self.CURRENT_COL = base_cols + 2
        self.tbl = QTableWidget(0, base_cols + len(EXTRA_COLUMNS))
        self.tbl.setObjectName("accountsTable")
        self.tbl.setHorizontalHeaderLabels(ACCOUNTS_COLUMNS + EXTRA_COLUMNS)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.tbl, stretch=1)
        
        # Флаг подавления обработчика изменений при программном заполнении
        self._suppress_item_changed = False
        # Реакция на ручное редактирование ячеек — сохраняем сразу в настройки
        self.tbl.itemChanged.connect(self.on_cell_changed)

        v.addWidget(QLabel("Журнал событий:"))
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        v.addWidget(self.log, stretch=1)

        # Подключаем обработчики событий для новых кнопок
        self.btn_add_account.clicked.connect(self.on_add_account)
        self.btn_edit_account.clicked.connect(self.on_edit_account)
        self.btn_delete_account.clicked.connect(self.on_delete_account)
        self.btn_load_accounts.clicked.connect(self.on_load_accounts)
        self.btn_save_accounts.clicked.connect(self.on_save_accounts)
        self.btn_generate_accounts.clicked.connect(self.on_generate_accounts)
        
        self.btn_add_clubs.clicked.connect(self.on_add_clubs)
        self.btn_clear_clubs.clicked.connect(self.on_clear_clubs)
        self.btn_load_clubs.clicked.connect(self.on_load_clubs)
        self.btn_load_club_distribution.clicked.connect(self.on_load_club_distribution)
        
        self.btn_login.clicked.connect(self.on_login_all)
        self.btn_logout.clicked.connect(self.on_logout_selected)
        self.btn_join.clicked.connect(self.on_join)
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_export.clicked.connect(self.on_export_report)
        self.btn_check_update.clicked.connect(self.on_check_update)
        self.cmb_theme.currentIndexChanged.connect(self.on_theme_combo_changed)

        # Элементы обновлений
        self._upd_thread: Optional[UpdateDownloadThread] = None
        self._upd_dialog: Optional[QDialog] = None
        
        self.worker = Worker(self.accounts, api_class=XPokerAPI, api_error_class=ApiError)
        self.worker.log.connect(self.on_worker_log)
        self.worker.account_updated.connect(self.on_account_updated)
        self.worker.join_result.connect(self.on_join_result)
        self.worker.task_finished.connect(self.on_task_finished)
        self.worker.started.connect(self.on_worker_started)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.pause_changed.connect(self.on_worker_pause_changed)
        # Отображение прогресса по аккаунтам
        self.account_row_by_username: Dict[str, int] = {}
        self.worker.account_progress.connect(self.on_account_progress)
        # Новый аккаунт из генератора/регистрации
        try:
            self.worker.new_account.connect(self.on_new_account)
        except Exception:
            pass
        
        # Базовый стиль системы для режима "Системная"
        try:
            app = QApplication.instance()
            self._initial_style_name = app.style().objectName()
        except Exception:
            self._initial_style_name = 'Fusion'
        # Значение темы по умолчанию
        self.theme_pref = 'system'      # 'system' | 'light' | 'dark'
        self.current_theme_mode = 'light'  # эффективная ('light'|'dark')
        # Загружаем сохранённые настройки
        self.load_settings()
        # Автопроверка обновлений при старте (не блокирует задачи)
        try:
            QtCore.QTimer.singleShot(2000, lambda: self.check_update_silent())
        except Exception:
            pass
        # Применим текущую настройку/системную по умолчанию
        self.apply_theme(self.theme_pref)
        # Статус-бар: кнопка обновления рядом с версией
        try:
            sb = self.statusBar()
            sb.showMessage("")
            try:
                self.btn_check_update.setFlat(True)
            except Exception:
                pass
            sb.addPermanentWidget(self.btn_check_update)
            # Тема в статус-баре (видна на любой вкладке)
            try:
                sb.addPermanentWidget(QLabel("Тема:"))
                sb.addPermanentWidget(self.cmb_theme)
            except Exception:
                pass
            # Глобальная полоса прогресса (всегда видима, слева)
            try:
                self._progress_total = 0
                self._progress_done = 0
                self._progress_mode = ""  # 'login' | 'join' | 'register' | ''
                self._progress_seen = set()  # для режима 'login'
                self.status_progress = QProgressBar()
                self.status_progress.setRange(0, 1)
                self.status_progress.setValue(0)
                self.status_progress.setTextVisible(True)
                self.status_progress.setFixedWidth(390)
                self.status_progress.setFormat("Готово")
                # Обёртка с отступами слева/справа
                _prog_wrap = QWidget()
                _prog_lay = QHBoxLayout(_prog_wrap)
                _prog_lay.setContentsMargins(12, 0, 8, 0)
                _prog_lay.setSpacing(0)
                _prog_lay.addWidget(self.status_progress)
                sb.addWidget(_prog_wrap, 0)
            except Exception:
                pass
            ver_lbl = QLabel(f"Версия: {__version__}")
            sb.addPermanentWidget(ver_lbl)
        except Exception:
            pass

        # Добавляем вкладку PPPoker
        try:
            from pppoker.api import PPPokerAPI, ApiError as PPPApiError
            self.pp_tab = PPPokerTab(parent=self)
            self.tabs.addTab(self.pp_tab, "PPPoker")
            try:
                self.pp_tab.update_table_theme()
            except Exception:
                pass
        except Exception as e:
            logging.getLogger(__name__).exception(f"PPPoker tab init failed: {e}")

        # Добавляем вкладку FishPoker
        try:
            from fishpoker.api import FishPokerAPI, ApiError as FishApiError
            self.fp_tab = FishPokerTab(parent=self)
            self.tabs.addTab(self.fp_tab, "FishPoker")
            try:
                self.fp_tab.update_table_theme()
            except Exception:
                pass
        except Exception as e:
            logging.getLogger(__name__).exception(f"FishPoker tab init failed: {e}")

    def on_load_accounts(self):
        """Загрузить аккаунты из Excel файла."""
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с аккаунтами", "", "Excel (*.xlsx)")
        if not path:
            return
        df = pd.read_excel(path)

        df.columns = [str(col).lower().strip() for col in df.columns]

        # Требуем только username и password, остальные поля опциональны
        need_cols = {"username", "password"}
        missing = need_cols - set(df.columns)
        if missing:
            QMessageBox.critical(self, "Ошибка", f"Отсутствуют колонки: {', '.join(missing)}")
            return
        self.accounts.clear()
        self.tbl.setRowCount(0)
        for _, row in df.iterrows():
            proxy_val = row.get("proxy")
            if pd.isna(proxy_val) or str(proxy_val).strip() == "":
                proxy_val = None
            else:
                proxy_val = str(proxy_val).strip()

            device_id_val = row.get("device_id")
            device_id_str = str(device_id_val).strip() if device_id_val is not None and not pd.isna(device_id_val) else ""

            acc = Account(
                username=str(row["username"]).strip(),
                password=str(row["password"]).strip(),
                proxy=proxy_val,
                device_id=device_id_str,
            )
            # Сгенерировать device_id если отсутствует
            if not acc.device_id:
                import uuid
                acc.device_id = str(uuid.uuid4())
            self.accounts.append(acc)
            self._append_account_row(acc)
        self.worker.accounts = self.accounts
        self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.accounts)} аккаунтов")

    def on_load_clubs(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с клубами", "", "Excel (*.xlsx)")
        if not path: return
        df = pd.read_excel(path)
        col = None
        for c in df.columns:
            if str(c).lower() in ("club_id","id","clubid"):
                col = c; break
        if not col:
            QMessageBox.critical(self, "Ошибка", "Не найдена колонка 'club_id'")
            return
        self.club_ids = [str(x) for x in df[col].dropna().astype(str).tolist()]
        if self.chk_shuffle.isChecked():
            import random; random.shuffle(self.club_ids)
        self.update_clubs_count()
        self.save_settings()
        self.log.appendPlainText(f"{Icons.SUCCESS} Загружено {len(self.club_ids)} ID клубов")

    def on_load_club_distribution(self):
        """Загрузить распределение клубов по аккаунтам из Excel файла."""
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты!")
            return
            
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл с распределением клубов", "", "Excel (*.xlsx)")
        if not path:
            return
            
        try:
            df = pd.read_excel(path)
            df.columns = [str(col).lower().strip() for col in df.columns]
            
            # Ищем нужные колонки
            username_col = None
            clubs_count_col = None
            
            for c in df.columns:
                if str(c).lower() in ("username", "user", "имя пользователя", "логин", "аккаунт"):
                    username_col = c
                if str(c).lower() in ("clubs_count", "clubs", "количество клубов", "клубов", "count"):
                    clubs_count_col = c
                    
            if not username_col:
                QMessageBox.critical(self, "Ошибка", 
                    "Не найдена колонка с именами пользователей.\n"
                    "Ожидаемые названия: username, user, имя пользователя, логин, аккаунт")
                return
                
            if not clubs_count_col:
                QMessageBox.critical(self, "Ошибка", 
                    "Не найдена колонка с количеством клубов.\n"
                    "Ожидаемые названия: clubs_count, clubs, количество клубов, клубов, count")
                return
            
            # Очищаем предыдущее распределение
            self.worker.account_club_limits.clear()
            
            # Загружаем распределение
            loaded_accounts = 0
            for _, row in df.iterrows():
                username = str(row[username_col]).strip()
                try:
                    clubs_count = int(row[clubs_count_col])
                    if clubs_count < 0:
                        clubs_count = 0
                except (ValueError, TypeError):
                    continue
                
                # Проверяем, есть ли такой аккаунт в загруженных
                account_exists = any(acc.username.lower() == username.lower() for acc in self.accounts)
                if account_exists:
                    self.worker.account_club_limits[username.lower()] = clubs_count
                    loaded_accounts += 1
                    
            if loaded_accounts == 0:
                QMessageBox.warning(self, "Предупреждение", 
                    "Не найдено совпадений между аккаунтами в файле и загруженными аккаунтами.\n"
                    "Проверьте правильность имен пользователей.")
                return
                
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружено распределение для {loaded_accounts} аккаунтов")
            
            # Показываем сводку распределения
            total_clubs_needed = sum(self.worker.account_club_limits.values())
            self.log.appendPlainText(f"{Icons.INFO} 📊 Сводка распределения:")
            self.log.appendPlainText(f"{Icons.INFO} • Аккаунтов с индивидуальным лимитом: {loaded_accounts}")
            self.log.appendPlainText(f"{Icons.INFO} • Общее количество клубов требуется: {total_clubs_needed}")
            self.log.appendPlainText(f"{Icons.INFO} • Доступно клубов: {len(self.club_ids)}")
            
            if total_clubs_needed > len(self.club_ids):
                self.log.appendPlainText(f"{Icons.WARNING} ⚠️ Внимание! Требуется больше клубов чем доступно")
                
        except Exception as e:
            QMessageBox.critical(self, "Ошибка загрузки", f"Не удалось загрузить файл распределения:\n{str(e)}")
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка загрузки распределения: {e}")

    def on_generate_accounts(self):
        # Диалог: количество + список прокси + задержки + опция аватара
        default_proxies_text = getattr(self, 'reg_proxies_last', '')
        dmin = getattr(self, 'reg_delay_min_last', 400)
        dmax = getattr(self, 'reg_delay_max_last', 900)
        def_set_avatar = getattr(self, 'reg_set_avatar_last', True)
        def_threads = getattr(self, 'reg_threads_last', 1)
        def_ppt = getattr(self, 'reg_ppt_last', 0)
        def_avatar_path = getattr(self, 'reg_avatar_path_last', '')
        dlg = GenerateAccountsDialog(default_count=int(getattr(self, 'reg_count_last', 100)), default_proxies_text=default_proxies_text, default_dmin=dmin, default_dmax=dmax, default_set_avatar=def_set_avatar, default_threads=def_threads, default_ppt=def_ppt, default_avatar_path=def_avatar_path, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cnt, proxies_list, delay_min_ms, delay_max_ms, set_avatar, threads, ppt, avatar_path = dlg.get_values()
        # Глобальный прогресс: регистрация X/Y
        try:
            self._progress_mode = "register"
            self._progress_total = int(cnt)
            self._progress_done = 0
            if self._progress_total <= 0:
                self._progress_total = 1
            self.status_progress.setRange(0, self._progress_total)
            self.status_progress.setValue(0)
            self.status_progress.setFormat(f"Регистрация 0/{self._progress_total}")
            self.status_progress.show()
        except Exception:
            pass
        if cnt <= 0:
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется"); return
        # Сохраняем последние параметры
        self.reg_count_last = int(cnt)
        self.reg_proxies_last = "\n".join(proxies_list)
        self.reg_delay_min_last = int(delay_min_ms)
        self.reg_delay_max_last = int(delay_max_ms)
        self.reg_set_avatar_last = bool(set_avatar)
        self.reg_threads_last = int(max(1, threads))
        self.reg_ppt_last = int(max(0, ppt))
        self.reg_avatar_path_last = avatar_path or getattr(self, 'reg_avatar_path_last', '')
        self.save_settings()
        # Запускаем задачу регистрации (параллельно если threads>1)
        if int(threads) > 1:
            self.worker.set_task(self.worker.task_register_accounts_parallel, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, int(threads), int(ppt), (avatar_path or None))
        else:
            self.worker.set_task(self.worker.task_register_accounts, cnt, True, bool(set_avatar), 'files/words.txt', None, delay_min_ms, delay_max_ms, proxies_list, (avatar_path or None))
        self.worker.start()

    def on_new_account(self, acc: Account):
        """Обработчик добавления нового аккаунта (после успешной регистрации)."""
        # Обновляем глобальный прогресс для регистрации
        try:
            if getattr(self, '_progress_mode', '') == 'register' and hasattr(self, 'status_progress'):
                self._progress_done = int(self._progress_done) + 1
                total = max(1, int(self._progress_total))
                done = min(int(self._progress_done), total)
                self.status_progress.setRange(0, total)
                self.status_progress.setValue(done)
                self.status_progress.setFormat(f"Регистрация {done}/{total}")
        except Exception:
            pass
        try:
            self.accounts.append(acc)
            self._append_account_row(acc)
            self.account_row_by_username[acc.username.lower()] = len(self.accounts) - 1
            self.worker.accounts = self.accounts
            self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен зарегистрированный аккаунт: {acc.username}")
            self.save_settings()
        except Exception as e:
            self.log.appendPlainText(f"{Icons.ERROR} Не удалось добавить аккаунт в таблицу: {e}")

    def on_login_all(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты")
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется")
            return
        # Прогресс: вход X/Y
        try:
            self._progress_mode = "login"
            self._progress_total = len(self.accounts)
            self._progress_done = 0
            self._progress_seen = set()
            total = max(1, int(self._progress_total))
            self.status_progress.setRange(0, total)
            self.status_progress.setValue(0)
            self.status_progress.setFormat(f"Вход 0/{total}")
        except Exception:
            pass
        self.worker.set_task(self.worker.task_login_all)
        self.worker.start()

    def on_logout_selected(self):
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для выхода")
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется")
            return
        self.worker.set_task(self.worker.task_logout_selected, rows)
        self.worker.start()

    def on_join(self):
        if not self.club_ids:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите клубы")
            return
        if not any(a.token for a in self.accounts):
            QMessageBox.critical(self, "Ошибка", "Сначала войдите в аккаунты (нет токенов)")
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется")
            return
        
        # Создаём копию списка клубов для обработки
        clubs_to_process = self.club_ids.copy()
        
        # Перемешиваем копию списка, если включена опция
        if self.chk_shuffle.isChecked():
            import random
            random.shuffle(clubs_to_process)
            self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан для обработки")
        
        limit = self.spn_clubs_per_account.value()
        dmin = self.spn_delay_min.value()
        dmax = self.spn_delay_max.value()
        if dmax < dmin:
            dmin, dmax = dmax, dmin
        # Текст сообщения (ограничен виджетом до 41 символа)
        message_text = self.txt_message.text().strip()
        # Глобальный прогресс: заявки X/Y
        try:
            self._progress_mode = "join"
            self._progress_total = len(clubs_to_process)
            self._progress_done = 0
            if self._progress_total <= 0:
                self._progress_total = 1
            self.status_progress.setRange(0, int(self._progress_total))
            self.status_progress.setValue(0)
            self.status_progress.setFormat(f"Заявки 0/{int(self._progress_total)}")
            self.status_progress.show()
        except Exception:
            pass
        self.worker.set_task(self.worker.task_join_round, clubs_to_process, limit, dmin, dmax, message_text, int(self.spn_join_threads.value()))
        self.worker.start()

    def on_debug_tcp(self):
        """Запуск отладки TCP последовательности."""
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется")
            return
            
        # Показываем диалог выбора настроек
        dialog = DebugTCPDialog(self.accounts, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
            
        debug_params = dialog.get_debug_params()
        if not debug_params:
            QMessageBox.warning(self, "Ошибка", "Не удалось получить параметры отладки")
            return
            
        account = debug_params['account']
        club_id = debug_params['club_id']
        version = debug_params['version']
        
        self.log.appendPlainText(f"\n" + "="*80)
        self.log.appendPlainText(f"{Icons.INFO} 🔧 НАЧАЛО ОТЛАДКИ TCP ПОСЛЕДОВАТЕЛЬНОСТИ")
        self.log.appendPlainText(f"{Icons.INFO} Аккаунт: {account.username} (uid={account.uid})")
        self.log.appendPlainText(f"{Icons.INFO} ID клуба: {club_id}")
        self.log.appendPlainText(f"{Icons.INFO} Версия клиента: {version}")
        self.log.appendPlainText(f"" + "="*80 + "\n")
        
        # Запускаем отладку в worker
        def task_debug_tcp_sequence():
            try:
                # Создаем TCP клиент
                from core.client import XClubTCPClient
                
                tcp_client = XClubTCPClient(proxy=account.proxy)
                tcp_client.connect()
                
                # Запускаем отладочную последовательность  
                results = tcp_client.debug_club_join_sequence(
                    uid=account.uid,
                    token=account.token, 
                    club_id=club_id,
                    version=version
                )
                
                # Выводим сводку результатов
                self.worker.log.emit(f"\n" + "="*80)
                self.worker.log.emit(f"{Icons.INFO} 📊 СВОДКА РЕЗУЛЬТАТОВ ОТЛАДКИ:")
                self.worker.log.emit(f"" + "="*80)
                
                success_count = sum(1 for step in results['steps'] if step['success'])
                total_steps = len(results['steps'])
                
                self.worker.log.emit(f"{Icons.INFO} Выполнено шагов: {success_count}/{total_steps}")
                self.worker.log.emit(f"{Icons.INFO} Общий результат: {'✅ УСПЕШНО' if results['success'] else '❌ НЕУДАЧНО'}")
                self.worker.log.emit(f"{Icons.INFO} Финальное сообщение: {results['final_message']}")
                
                if results.get('club_info', {}):
                    club_info = results['club_info']
                    self.worker.log.emit(f"{Icons.INFO} Информация о клубе: {club_info.get('name', 'N/A')}")
                    
                if results.get('apply_status') is not None:
                    self.worker.log.emit(f"{Icons.INFO} Статус заявки: {results['apply_status']}")
                
                self.worker.log.emit(f"\n{Icons.INFO} 🔍 Детали по шагам:")
                for i, step in enumerate(results['steps'], 1):
                    status = "✅" if step['success'] else "❌"
                    self.worker.log.emit(f"{Icons.INFO} {i:2d}. {status} {step['name']}: {step['message']}")
                
                self.worker.log.emit(f"\n" + "="*80)
                self.worker.log.emit(f"{Icons.SUCCESS if results['success'] else Icons.ERROR} ОТЛАДКА TCP ЗАВЕРШЕНА")
                self.worker.log.emit(f"" + "="*80 + "\n")
                
                # Создаем JoinResult для отчета
                join_result = JoinResult(
                    ts=time.time(),
                    username=account.username,
                    club_id=str(club_id),
                    ok=results['success'],
                    message=f"[DEBUG] {results['final_message']}"
                )
                self.worker.join_result.emit(join_result)
                
            except Exception as e:
                error_msg = f"Ошибка отладки TCP: {e}"
                self.worker.log.emit(f"{Icons.ERROR} {error_msg}")
                self.worker.log.emit(f"{Icons.ERROR} Traceback: {traceback.format_exc()}")
                
                # Создаем JoinResult для ошибки
                join_result = JoinResult(
                    ts=time.time(),
                    username=account.username,
                    club_id=str(club_id),
                    ok=False,
                    message=f"[DEBUG ERROR] {error_msg}"
                )
                self.worker.join_result.emit(join_result)
            finally:
                try:
                    if 'tcp_client' in locals():
                        tcp_client.close()
                except:
                    pass
                self.worker.task_finished.emit()
        
        # Запускаем задачу
        self.worker.set_task(task_debug_tcp_sequence)
        self.worker.start()

    def on_check_update(self):
        if UpdateManager is None:
            QMessageBox.information(self, "Обновление", "Модуль обновления не установлен")
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Сначала дождитесь завершения текущей задачи")
            return
        try:
            mgr = UpdateManager(__version__)
            upd = mgr.check_for_update()
            if not upd:
                QMessageBox.information(self, "Обновление", f"Обновлений нет (версия {__version__})")
                return
            new_ver = getattr(upd, 'version', 'new')
            if not self._ask_yes_no("Обновление доступно", f"Найдена версия {new_ver}. Скачать?"):
                return
            self._start_update_download(mgr, str(new_ver))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка обновления", str(e))

    def check_update_silent(self):
        if UpdateManager is None:
            return
        try:
            mgr = UpdateManager(__version__)
            upd = mgr.check_for_update()
            if upd:
                new_ver = getattr(upd, 'version', 'new')
                if self._ask_yes_no("Доступно обновление", f"Найдена версия {new_ver}. Скачать сейчас?"):
                    self._start_update_download(mgr, str(new_ver))
        except Exception:
            pass

    def _start_update_download(self, mgr: UpdateManager, new_ver: str):
        # Диалог прогресса, не блокирует UI полностью
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Загрузка обновления {new_ver}")
        lay = QVBoxLayout(dlg)
        lbl = QLabel(f"Скачивание {new_ver}...")
        bar = QProgressBar(dlg)
        bar.setRange(0, 100); bar.setValue(0)
        lay.addWidget(lbl); lay.addWidget(bar)
        self._upd_dialog = dlg
        th = UpdateDownloadThread(mgr, self)
        self._upd_thread = th
        th.progress.connect(lambda p: (bar.setValue(int(p)), self.log.appendPlainText(f"{Icons.INFO} Загрузка обновления: {int(p)}%")))
        def _done(ok: bool, err: str):
            try:
                try:
                    dlg.close()
                except Exception:
                    pass
                if ok:
                    self.log.appendPlainText(f"{Icons.SUCCESS} Обновление скачано и установка запущена. Перезапуск...")
                    # Дадим апдейтеру стартануть, затем завершим приложение
                    QTimer.singleShot(200, lambda: QApplication.instance().quit())
                else:
                    self.log.appendPlainText(f"{Icons.ERROR} Обновление: ошибка загрузки/установки ({err or 'unknown'})")
                    QMessageBox.critical(self, "Обновление", "Ошибка загрузки/установки")
            except Exception:
                logging.getLogger(__name__).exception("[update] _done callback error")
        th.finished.connect(_done)
        th.start()
        dlg.show()

    def _ask_yes_no(self, title: str, text: str) -> bool:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(text)
        yes = box.addButton("Да", QMessageBox.ButtonRole.YesRole)
        no = box.addButton("Нет", QMessageBox.ButtonRole.NoRole)
        box.setIcon(QMessageBox.Icon.Question)
        box.exec()
        return box.clickedButton() is yes

    def on_export_report(self):
        if not self.report_rows:
            QMessageBox.information(self, "Нет данных", "Пока нет данных для отчета")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "", "Excel (*.xlsx)")
        if not path: 
            return
            
        try:
            # Преобразуем JoinResult объекты в словари
            report_data = []
            for jr in self.report_rows:
                if hasattr(jr, 'as_dict'):
                    report_data.append(jr.as_dict())
                else:
                    # Если это уже словарь
                    report_data.append(jr)
            
            # Создаем DataFrame из словарей (колонки определятся автоматически)
            df = pd.DataFrame(report_data)
            
            # Убеждаемся что колонки в правильном порядке
            if len(df.columns) > 0:
                # Переупорядочиваем колонки согласно REPORT_COLUMNS
                column_order = [col for col in REPORT_COLUMNS if col in df.columns]
                if column_order:
                    df = df[column_order]
            
            df.to_excel(path, index=False)
            self.log.appendPlainText(f"{Icons.SUCCESS} Отчет сохранен: {path}")
            self.log.appendPlainText(f"{Icons.INFO} Экспортировано записей: {len(report_data)}")
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить отчет:\n{str(e)}")
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка экспорта отчета: {e}")

    def on_worker_log(self, line: str):
        self.log.appendPlainText(line)

    def on_cell_changed(self, item: QTableWidgetItem):
        """Обработчик ручного редактирования ячеек: синхронизируем self.accounts и сохраняем настройки.
        Отключаем редактирование для пароля/токена/последнего входа.
        """
        if self._suppress_item_changed:
            return
        row = item.row()
        col = item.column()
        if row < 0 or row >= len(self.accounts):
            return
        acc = self.accounts[row]
        text = item.text().strip()
        # Колонки: 0=Имя, 1=Пароль(маск), 2=Прокси, 3=DeviceID, 4=Токен(кратко), 5=Последний вход
        if col == 1 or col == 4 or col == 5:
            # Эти колонки не редактируемы: откатываем изменение
            self._suppress_item_changed = True
            try:
                # Восстановим отображаемое значение из модели
                current = acc.as_row()[col]
                item.setText(str(current))
                # И убедимся, что флаг редактирования снят
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            finally:
                self._suppress_item_changed = False
            return
        changed = False
        if col == 0:  # username
            if text and text != acc.username:
                acc.username = text
                changed = True
        elif col == 2:  # proxy
            new_proxy = text or None
            if new_proxy != (acc.proxy or None):
                acc.proxy = new_proxy
                changed = True
        elif col == 3:  # device_id
            if text != (acc.device_id or ""):
                acc.device_id = text
                changed = True
        # Синхронизация и сохранение
        if changed:
            # При изменении критичных полей сбрасываем токен/последний вход
            acc.token = None
            acc.last_login_at = None
            # Обновим визуально токен/последний вход
            self._suppress_item_changed = True
            try:
                tok_it = QTableWidgetItem("")
                tok_it.setFlags(tok_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 4, tok_it)
                last_it = QTableWidgetItem("")
                last_it.setFlags(last_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, 5, last_it)
            finally:
                self._suppress_item_changed = False
            # Перестроим индекс по имени
            self.account_row_by_username = {a.username.lower(): i for i, a in enumerate(self.accounts)}
            # Прокинем обновлённый список в worker и сохраним JSON
            self.worker.accounts = self.accounts
            self.save_settings()

    def on_account_progress(self, username: str, done: int, total: int, status_text: str, current_club: str):
        row = self.account_row_by_username.get(username.lower())
        if row is None:
            return
        # Прогрессбар
        w = self.tbl.cellWidget(row, self.PROG_COL)
        if isinstance(w, QProgressBar):
            w.setRange(0, max(total, 1))
            w.setValue(max(0, min(done, total)))
            percent = (0 if total == 0 else int((done/total)*100))
            w.setFormat(f"{done}/{total} ({percent}%)")
        # Статус и текущий клуб (только для чтения)
        it_status = QTableWidgetItem(status_text)
        it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.STATUS_COL, it_status)
        it_curr = QTableWidgetItem(current_club)
        it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.tbl.setItem(row, self.CURRENT_COL, it_curr)

    def on_account_updated(self, row: int, data: list):
        # Обновление строки из бэкэнда — без триггера сохранения
        # Обновим глобальный прогресс для режима 'login'
        try:
            if getattr(self, '_progress_mode', '') == 'login' and hasattr(self, 'status_progress'):
                uname = None
                try:
                    uname = str(data[0]) if isinstance(data, list) and len(data) > 0 else None
                except Exception:
                    uname = None
                if uname and uname not in self._progress_seen:
                    self._progress_seen.add(uname)
                    self._progress_done = int(self._progress_done) + 1
                    total = max(1, int(self._progress_total))
                    done = min(int(self._progress_done), total)
                    self.status_progress.setRange(0, total)
                    self.status_progress.setValue(done)
                    self.status_progress.setFormat(f"Вход {done}/{total}")
        except Exception:
            pass
        self._suppress_item_changed = True
        try:
            for col, val in enumerate(data):
                it = QTableWidgetItem(str(val))
                # Запрещаем редактирование пароля/токена/последнего входа
                if col in (1, 4, 5):
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(row, col, it)
            # Доп. колонки статуса/текущего клуба тоже только для чтения
            it_status = self.tbl.item(row, self.STATUS_COL)
            if it_status:
                it_status.setFlags(it_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
            it_curr = self.tbl.item(row, self.CURRENT_COL)
            if it_curr:
                it_curr.setFlags(it_curr.flags() & ~Qt.ItemFlag.ItemIsEditable)
        finally:
            self._suppress_item_changed = False

    def on_join_result(self, jr: JoinResult):
        # Сохраняем объект JoinResult напрямую, преобразование в словарь делаем при экспорте
        self.report_rows.append(jr)
        # Обновляем глобальный прогресс (XPoker)
        try:
            if getattr(self, '_progress_mode', '') == 'join' and hasattr(self, 'status_progress'):
                self._progress_done = int(self._progress_done) + 1
                total = max(1, int(self._progress_total))
                done = min(int(self._progress_done), total)
                self.status_progress.setRange(0, total)
                self.status_progress.setValue(done)
                self.status_progress.setFormat(f"Заявки {done}/{total}")
        except Exception:
            pass

    def _append_account_row(self, acc: Account):
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        data = acc.as_row()
        self._suppress_item_changed = True
        try:
            for c, v in enumerate(data):
                it = QTableWidgetItem(str(v))
                # Делает некоторые колонки только для чтения
                if c in (1, 4, 5):  # Пароль(маскир.), Токен(кратко), Последний вход
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tbl.setItem(r, c, it)
            # Инициализация дополнительных колонок: прогресс, статус, текущий клуб
            prog = QProgressBar()
            prog.setRange(0, 1)
            prog.setValue(0)
            prog.setTextVisible(True)
            prog.setFormat("0/0 (0%)")
            self.tbl.setCellWidget(r, self.PROG_COL, prog)
            st_it = QTableWidgetItem("⏳ Ожидание")
            st_it.setFlags(st_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.STATUS_COL, st_it)
            cur_it = QTableWidgetItem("-")
            cur_it.setFlags(cur_it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.tbl.setItem(r, self.CURRENT_COL, cur_it)
        finally:
            self._suppress_item_changed = False
        # Индекс по имени
        self.account_row_by_username[acc.username.lower()] = r
        prog.setRange(0, 1)
        prog.setValue(0)
        prog.setTextVisible(True)
        prog.setFormat("0/0 (0%)")
        self.tbl.setCellWidget(r, self.PROG_COL, prog)
        self.tbl.setItem(r, self.STATUS_COL, QTableWidgetItem("⏳ Ожидание"))
        self.tbl.setItem(r, self.CURRENT_COL, QTableWidgetItem("-"))
        # Индекс по имени
        self.account_row_by_username[acc.username.lower()] = r
    
    def on_add_account(self):
        """Добавить новый аккаунт."""
        dialog = AccountDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            # Генерируем device_id сразу
            import uuid
            acc = Account(
                username=data['username'],
                password=data['password'],
                device_id=str(uuid.uuid4()),
                proxy=data['proxy']
            )
            self.accounts.append(acc)
            self._append_account_row(acc)
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Добавлен аккаунт: {acc.username}")
    
    def on_edit_account(self):
        """Редактировать выбранный аккаунт."""
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строку для редактирования")
            return
        if len(rows) > 1:
            QMessageBox.information(self, "Выбор", "Выберите только одну строку для редактирования")
            return
        
        row = rows[0]
        if row >= len(self.accounts):
            return
            
        acc = self.accounts[row]
        dialog = AccountDialog(account=acc, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_account_data()
            
            # Обновляем данные аккаунта
            acc.username = data['username']
            acc.password = data['password']
            acc.proxy = data['proxy']
            
            # Сбрасываем токен и дату входа при изменении критических данных
            acc.token = None
            acc.last_login_at = None
            
            # Обновляем строку в таблице
            acc_data = acc.as_row()
            for col, val in enumerate(acc_data):
                self.tbl.setItem(row, col, QTableWidgetItem(str(val)))
            # Обновляем индекс по имени
            self.account_row_by_username[acc.username.lower()] = row
            
            self.worker.accounts = self.accounts
            self.save_settings()
            self.log.appendPlainText(f"{Icons.SUCCESS} Отредактирован аккаунт: {acc.username}")
    
    def on_delete_account(self):
        """Удалить выбранные аккаунты."""
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()}, reverse=True)
        if not rows:
            QMessageBox.information(self, "Выбор", "Выберите строки для удаления")
            return
        
        reply = QMessageBox.question(
            self, "Подтверждение", 
            f"Удалить {len(rows)} аккаунт(ов)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            deleted_usernames = []
            for row in rows:
                if row < len(self.accounts):
                    deleted_usernames.append(self.accounts[row].username)
                    del self.accounts[row]
                    self.tbl.removeRow(row)
            
            self.worker.accounts = self.accounts
            self.save_settings()
            if deleted_usernames:
                self.log.appendPlainText(f"{Icons.SUCCESS} Удалены аккаунты: {', '.join(deleted_usernames)}")
    
    def on_save_accounts(self):
        """Сохранить аккаунты в файл настроек."""
        try:
            self.save_settings()
            QMessageBox.information(self, "Сохранение", "Настройки сохранены успешно!")
            self.log.appendPlainText(f"{Icons.SUCCESS} Настройки сохранены")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить настройки: {e}")
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка сохранения: {e}")
    
    def on_add_clubs(self):
        """Добавить ID клубов вручную."""
        dialog = ClubIdDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_club_ids = dialog.get_club_ids()
            if new_club_ids:
                # Добавляем новые ID к существующим (избегаем дубликатов)
                existing = set(self.club_ids)
                added = []
                for club_id in new_club_ids:
                    if club_id not in existing:
                        self.club_ids.append(club_id)
                        existing.add(club_id)
                        added.append(club_id)
                
                # Перемешиваем если включена опция
                if self.chk_shuffle.isChecked() and self.club_ids:
                    import random
                    random.shuffle(self.club_ids)
                    self.log.appendPlainText(f"{Icons.INFO} Список клубов перемешан")
                
                self.update_clubs_count()
                self.save_settings()
                if added:
                    self.log.appendPlainText(f"{Icons.SUCCESS} Добавлено {len(added)} новых клубов: {', '.join(added)}")
                else:
                    self.log.appendPlainText(f"{Icons.INFO} Все введённые клубы уже есть в списке")
            else:
                QMessageBox.information(self, "Данные", "Не введено ни одного корректного ID клуба")
    
    def on_clear_clubs(self):
        """Очистить список клубов."""
        if self.club_ids:
            reply = QMessageBox.question(
                self, "Подтверждение", 
                f"Очистить список из {len(self.club_ids)} клубов?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.club_ids.clear()
                self.update_clubs_count()
                self.save_settings()
                self.log.appendPlainText(f"{Icons.SUCCESS} Список клубов очищен")
        else:
            QMessageBox.information(self, "Список пуст", "Список клубов уже пуст")
    
    def update_clubs_count(self):
        """Обновить отображение количества клубов."""
        self.clubs_count_label.setText(f"Клубов: {len(self.club_ids)}")
    
    def save_settings(self):
        """Сохранить настройки в JSON файл."""
        settings = {
            'accounts': [{
                'username': acc.username,
                'password': acc.password,
                'device_id': acc.device_id,
                'proxy': acc.proxy,
                'refresh_token': acc.refresh_token,
                'access_token_expire': acc.access_token_expire,
                'refresh_token_expire': acc.refresh_token_expire,
            } for acc in self.accounts],
            'club_ids': self.club_ids,
'settings': {
                'clubs_per_account': self.spn_clubs_per_account.value(),
                'delay_min_ms': self.spn_delay_min.value(),
                'delay_max_ms': self.spn_delay_max.value(),
                'shuffle_clubs': self.chk_shuffle.isChecked(),
                'apply_message': self.txt_message.text(),
                'join_threads': int(self.spn_join_threads.value()),
                'theme': getattr(self, 'theme_pref', 'system'),
                'reg_count': int(getattr(self, 'reg_count_last', 100)),
                'reg_proxies': getattr(self, 'reg_proxies_last', ''),
                'reg_delay_min_ms': int(getattr(self, 'reg_delay_min_last', 400)),
                'reg_delay_max_ms': int(getattr(self, 'reg_delay_max_last', 900)),
                'reg_set_avatar': bool(getattr(self, 'reg_set_avatar_last', True)),
                'reg_threads': int(getattr(self, 'reg_threads_last', 1)),
                'reg_proxies_per_thread': int(getattr(self, 'reg_ppt_last', 0)),
                'reg_avatar_path': str(getattr(self, 'reg_avatar_path_last', '')),
            }
        }
        try:
            settings_path = Path("files")/"xpoker_settings.json"
            with open(settings_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка сохранения настроек: {e}")

    def on_pause(self):
        """Включить/выключить паузу процесса вступления."""
        if not self.worker.isRunning():
            QMessageBox.information(self, "Пауза", "Нет активного процесса для паузы")
            return
        self.worker.pause_toggle()

    def on_worker_pause_changed(self, paused: bool):
        """Обновить UI при изменении состояния паузы."""
        self.btn_pause.setText("▶️ Продолжить" if paused else "⏸ Пауза")
        # Сохраняем актуальные настройки UI при изменении паузы
        self.save_settings()
    
    def load_settings(self):
        """Загрузить настройки из JSON файла."""
        settings_path = Path("files")/"xpoker_settings.json"
        if not settings_path.exists():
            self.log.appendPlainText(f"{Icons.INFO} Файл настроек не найден, используем значения по умолчанию")
            return
        
        try:
            # Если файл пустой — стартуем с дефолтов
            if settings_path.stat().st_size == 0:
                raise ValueError("empty settings file")
            with open(settings_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            
            # Загружаем аккаунты
            self.accounts.clear()
            self.tbl.setRowCount(0)
            for acc_data in settings.get('accounts', []):
                acc = Account(
                    username=acc_data.get('username', ''),
                    password=acc_data.get('password', ''),
                    device_id=acc_data.get('device_id') or "",
                    proxy=acc_data.get('proxy'),
                )
                # Токены и их сроки
                acc.refresh_token = acc_data.get('refresh_token')
                acc.access_token_expire = acc_data.get('access_token_expire')
                acc.refresh_token_expire = acc_data.get('refresh_token_expire')
                # Генерируем device_id если отсутствует
                if not acc.device_id:
                    import uuid
                    acc.device_id = str(uuid.uuid4())
                self.accounts.append(acc)
                self._append_account_row(acc)
            
            # Загружаем клубы
            self.club_ids = settings.get('club_ids', [])
            # Не перемешиваем при загрузке настроек - сохраняем исходный порядок
            # Перемешивание будет происходить только при старте операции вступления
            self.update_clubs_count()
            
            # Загружаем настройки UI
            ui_settings = settings.get('settings', {})
            self.spn_clubs_per_account.setValue(ui_settings.get('clubs_per_account', 500))
            self.spn_delay_min.setValue(ui_settings.get('delay_min_ms', 500))
            self.spn_delay_max.setValue(ui_settings.get('delay_max_ms', 1500))
            self.chk_shuffle.setChecked(ui_settings.get('shuffle_clubs', True))
            try:
                self.spn_join_threads.setValue(int(ui_settings.get('join_threads', 64)))
            except Exception:
                pass
            # Сообщение заявки
            self.txt_message.setText(ui_settings.get('apply_message', ''))
            # Тема (установить выбор и применить)
            theme_mode = ui_settings.get('theme', 'system')
            # Последние параметры генерации
            self.reg_count_last = int(ui_settings.get('reg_count', 100))
            self.reg_proxies_last = ui_settings.get('reg_proxies','') or ui_settings.get('reg_proxy','') or ''
            self.reg_delay_min_last = int(ui_settings.get('reg_delay_min_ms', 400))
            self.reg_delay_max_last = int(ui_settings.get('reg_delay_max_ms', 900))
            self.reg_set_avatar_last = bool(ui_settings.get('reg_set_avatar', True))
            self.reg_threads_last = int(ui_settings.get('reg_threads', 1))
            self.reg_ppt_last = int(ui_settings.get('reg_proxies_per_thread', 0))
            self.reg_avatar_path_last = ui_settings.get('reg_avatar_path', '')
            # Установить выбор в комбобоксе
            try:
                idx = next(i for i in range(self.cmb_theme.count()) if self.cmb_theme.itemData(i) == theme_mode)
            except StopIteration:
                idx = 0
            self.cmb_theme.setCurrentIndex(idx)
            self.apply_theme(theme_mode)
            
            self.worker.accounts = self.accounts
            self.log.appendPlainText(f"{Icons.SUCCESS} Загружены настройки: {len(self.accounts)} аккаунтов, {len(self.club_ids)} клубов")
            
        except Exception as e:
            # При ошибке разбора — переименовываем файл в резервную копию и стартуем с дефолтов
            try:
                backup = settings_path.with_suffix('.bak')
                settings_path.replace(backup)
                self.log.appendPlainText(f"{Icons.WARNING} Файл настроек повреждён, создана резервная копия: {backup}")
            except Exception:
                pass
            self.accounts.clear()
            self.tbl.setRowCount(0)
            self.club_ids = []
            self.update_clubs_count()
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка загрузки настроек: {e}. Загружены значения по умолчанию")
    
    def on_stop(self):
        """Остановить выполнение текущей задачи."""
        if self.worker.isRunning():
            self.worker.stop()
            self.log.appendPlainText(f"{Icons.WARNING} 🛑 Запрос на остановку отправлен...")
        else:
            QMessageBox.information(self, "Остановка", "Нет активных процессов для остановки")
    
    def on_worker_started(self):
        """Обработчик запуска worker'а - активируем кнопку остановки."""
        self.btn_stop.setEnabled(True)
        self.btn_pause.setEnabled(True)
        self.btn_pause.setText("⏸ Пауза")
        # Деактивируем кнопки, которые нельзя использовать во время выполнения
        self.btn_join.setEnabled(False)
        self.btn_login.setEnabled(False)
        self.btn_logout.setEnabled(False)
    
    def on_worker_finished(self):
        """Обработчик завершения worker'а - деактивируем кнопку остановки."""
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸ Пауза")
        # Активируем обратно кнопки операций
        self.btn_join.setEnabled(True)
        self.btn_login.setEnabled(True)
        self.btn_logout.setEnabled(True)
    
    def on_task_finished(self):
        """Обработчик завершения задачи.
        Важно: не сбрасывать здесь self.worker._stop/_cancel_event — это ломает мгновенную остановку.
        """
        return

    def closeEvent(self, event):
        try:
            self.save_settings()
        except Exception as e:
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка сохранения при выходе: {e}")
        # Сохраним настройки PPPoker вкладки тоже
        try:
            if hasattr(self, 'pp_tab') and self.pp_tab:
                self.pp_tab.save_settings()
        except Exception:
            pass
        # Сохраним настройки FishPoker вкладки тоже
        try:
            if hasattr(self, 'fp_tab') and self.fp_tab:
                self.fp_tab.save_settings()
        except Exception:
            pass
        super().closeEvent(event)


    # ===== Тема (светлая/тёмная/системная) =====
    def detect_system_theme(self) -> str:
        try:
            if platform.system().lower() == 'windows' and winreg is not None:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
                    v, _ = winreg.QueryValueEx(k, 'AppsUseLightTheme')
                    return 'light' if int(v) == 1 else 'dark'
        except Exception:
            pass
        return 'light'

    def apply_theme(self, pref_mode: str) -> None:
        pref_mode = (pref_mode or 'system').lower()
        self.theme_pref = pref_mode
        eff = pref_mode if pref_mode in ('light','dark') else self.detect_system_theme()
        self.current_theme_mode = 'dark' if eff == 'dark' else 'light'
        app = QApplication.instance()
        # Если доступен qdarktheme/pyqtdarktheme — используем его (light/dark/auto)
        if _qdt_mod is not None and _qdt_api is not None:
            try:
                if _qdt_api == 'setup_theme':
                    mode = 'auto' if self.theme_pref == 'system' else self.current_theme_mode
                    _qdt_mod.setup_theme(mode)  # type: ignore[attr-defined]
                elif _qdt_api == 'load_stylesheet':
                    # load_stylesheet(theme='dark'|'light') API
                    theme = 'auto' if self.theme_pref == 'system' else self.current_theme_mode
                    # auto: подстраиваемся под систему — выберем light/dark
                    if theme == 'auto':
                        theme = self.detect_system_theme()
                    css = _qdt_mod.load_stylesheet(theme)  # type: ignore[attr-defined]
                    app.setStyle('Fusion'); app.setStyleSheet(css)
            except Exception:
                try:
                    app.setStyle('Fusion'); app.setStyleSheet("")
                except Exception:
                    pass
        else:
            # Fallback: Fusion
            try:
                app.setStyle('Fusion'); app.setStyleSheet("")
            except Exception:
                pass
        # Применить настройки таблиц (фон/левый служебный столбец)
        self.update_table_theme()
        try:
            if hasattr(self, 'pp_tab') and self.pp_tab:
                self.pp_tab.update_table_theme()
        except Exception:
            pass
        try:
            if hasattr(self, 'fp_tab') and self.fp_tab:
                self.fp_tab.update_table_theme()
        except Exception:
            pass
        # Обновить выбор в комбобоксе (если меняли программно)
        try:
            idx = next(i for i in range(self.cmb_theme.count()) if self.cmb_theme.itemData(i) == self.theme_pref)
            if self.cmb_theme.currentIndex() != idx:
                self.cmb_theme.blockSignals(True)
                self.cmb_theme.setCurrentIndex(idx)
                self.cmb_theme.blockSignals(False)
        except Exception:
            pass

    def update_table_theme(self) -> None:
        """Перенастроить оформление таблицы и её левого служебного столбца под текущую тему.
        Делается пер-виджетно, чтобы перекрыть тему qdarktheme.
        """
        try:
            t = self.tbl
        except Exception:
            return
        if not isinstance(t, QTableWidget):
            return
        if self.current_theme_mode == 'dark':
            # Более тёмный фон таблицы и совпадение фона левого номератора строк
            try:
                # Фон самой таблицы и вьюпорта
                t.setStyleSheet(
                    "QTableWidget, QTableView, QTableWidget::viewport, QTableView::viewport {"
                    " background-color: #1e1e1e;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #1e1e1e;"
                    "}"
                )
                t.viewport().setStyleSheet("background-color: #1e1e1e;")
            except Exception:
                pass
            # Вертикальный хедер (столбец номеров строк)
            try:
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet(
                        "QHeaderView { background-color: #1e1e1e; }"
                        "QHeaderView::section { background-color: #1e1e1e; color: #d0d0d0; border: none; }"
                    )
                    pal = vh.palette()
                    pal.setColor(QPalette.ColorRole.Button, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
                    pal.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
                    vh.setPalette(pal)
                    vh.setAutoFillBackground(True)
            except Exception:
                pass
        else:
            # Светлая/системная тема — аккуратный светлый стиль для таблицы
            try:
                # Снимаем все QSS с таблицы и вьюпорта
                t.setStyleSheet("")
                t.viewport().setStyleSheet("")
                # Сбрасываем палитру к системной
                try:
                    pal = QApplication.palette()
                    t.setPalette(pal)
                    t.viewport().setAutoFillBackground(False)
                except Exception:
                    pass
                # Вертикальный хедер — тоже к системной палитре
                vh = t.verticalHeader()
                if vh is not None:
                    vh.setStyleSheet("")
                    vh.setAutoFillBackground(False)
                    try:
                        vh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                # Горизонтальный хедер — сброс
                hh = t.horizontalHeader()
                if hh is not None:
                    hh.setStyleSheet("")
                    try:
                        hh.setPalette(QApplication.palette())
                    except Exception:
                        pass
                # Лёгкая светлая стилизация (пер-виджетная)
                ss_light = (
                    "QTableWidget#accountsTable, QTableWidget#accountsTable::viewport {"
                    " background-color: #f7f7f7;"
                    " alternate-background-color: #ffffff;"
                    "}"
                    "QTableWidget#accountsTable {"
                    " gridline-color: #e0e0e0;"
                    "}"
                    "QTableWidget#accountsTable QHeaderView::section:horizontal {"
                    " background-color: #fafafa; color: #222; border: 1px solid #e6e6e6; padding: 4px;"
                    "}"
                    "QTableWidget#accountsTable QHeaderView::section:vertical {"
                    " background-color: #f7f7f7; color: #666; border: none;"
                    "}"
                    "QTableCornerButton::section {"
                    " background-color: #fafafa; border: 1px solid #e6e6e6;"
                    "}"
                    "QTableWidget#accountsTable::item:selected {"
                    " background-color: #cfe8ff; color: #000;"
                    "}"
                )
                try:
                    t.setAlternatingRowColors(True)
                except Exception:
                    pass
                try:
                    t.setStyleSheet(ss_light)
                except Exception:
                    pass
                # Переполируем виджет, чтобы применить тему
                try:
                    t.style().unpolish(t)
                    t.style().polish(t)
                    t.update()
                except Exception:
                    pass
            except Exception:
                pass

    def on_theme_combo_changed(self, index: int):
        try:
            pref = self.cmb_theme.itemData(index) or 'system'
        except Exception:
            pref = 'system'
        self.apply_theme(pref)
        self.save_settings()


def _configure_console():
    try:
        if os.name != 'nt':
            return
        import ctypes
        SW_HIDE, SW_SHOW = 0, 5
        GetConsoleWindow = ctypes.windll.kernel32.GetConsoleWindow
        ShowWindow = ctypes.windll.user32.ShowWindow
        hwnd = GetConsoleWindow()
        want_console = any(a in ('--console', '-c', '/c') for a in sys.argv[1:])
        if want_console:
            if hwnd:
                ShowWindow(hwnd, SW_SHOW)
            else:
                try:
                    ctypes.windll.kernel32.AllocConsole()
                except Exception:
                    pass
        else:
            if hwnd:
                ShowWindow(hwnd, SW_HIDE)
    except Exception:
        pass


def main():
    """Старт GUI с расширенной диагностикой стартовых ошибок."""
    try:
        # Для отладки проблем с Qt-плагинами раскомментируйте:
        # os.environ.setdefault("QT_DEBUG_PLUGINS", "1")
        # Ensure files/logs directories exist
        try:
            Path('files').mkdir(parents=True, exist_ok=True)
            Path('logs').mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
            handlers=[
                RotatingFileHandler(str(Path('logs')/'xpoker_gui.log'), maxBytes=2*1024*1024, backupCount=5, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        logging.getLogger(__name__).info("Starting ClubSender GUI...")
        # Console: hidden by default; use --console to show
        _configure_console()
        app = QApplication(sys.argv)
        w = MainWindow()
        w.show()
        sys.exit(app.exec())
    except Exception as e:
        tb = traceback.format_exc()
        try:
            Path('logs').mkdir(parents=True, exist_ok=True)
            with open(Path('logs')/"startup_error.log", 'w', encoding='utf-8') as f:
                f.write(tb)
        except Exception:
            pass
        print("[StartupError]", e, file=sys.stderr)
        print(tb, file=sys.stderr)

if __name__ == "__main__":
    main()

