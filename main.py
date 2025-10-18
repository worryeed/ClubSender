
from __future__ import annotations
import sys, os, time, traceback
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

from core import Account, JoinResult, XPokerAPI, ApiError
from core.messages import Icons, format_login_step, format_join_result, MESSAGES
from core.version import __version__
from update.manager import UpdateManager

APP_TITLE = "ClubSender"
ACCOUNTS_COLUMNS = ["Имя пользователя", "Пароль", "Прокси", "ID устройства", "Токен (кратко)", "Последний вход"]
EXTRA_COLUMNS = ["Прогресс", "Статус", "Текущий клуб"]
REPORT_COLUMNS = ["Время", "Имя пользователя", "ID клуба", "Успешно", "Сообщение"]

class Worker(QThread):
    log = pyqtSignal(str)
    account_updated = pyqtSignal(int, list)
    join_result = pyqtSignal(object)
    task_finished = pyqtSignal()  # Сигнал о завершении задачи
    pause_changed = pyqtSignal(bool)  # Сигнал об изменении состояния паузы
    # username, done, total, status_text, current_club
    account_progress = pyqtSignal(str, int, int, str, str)

    def __init__(self, accounts: List[Account], parent=None):
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

    def stop(self):
        self._stop = True
        try:
            # Сигнализируем всем долгим операциям о необходимости завершения
            self._cancel_event.set()
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
            time.sleep(0.2)

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
        for idx, acc in enumerate(self.accounts):
            if self._stop: break
            try:
                proxy_info = acc.proxy or 'без прокси'
                self.log.emit(f"{Icons.AUTH} [{acc.username}] Авторизация через {proxy_info}")
                api = XPokerAPI(proxy=acc.proxy)
                
                # Генерируем device_id если отсутствует
                if not acc.device_id:
                    import uuid
                    acc.device_id = str(uuid.uuid4())
                    self.log.emit(f"{Icons.INFO} [{acc.username}] Сгенерирован device_id: {acc.device_id[:8]}...")
                        
                data = api.login(
                    username=acc.username,
                    password=acc.password,
                    device_id=acc.device_id
                )
                token = api.token
                acc.token = token
                # Сохраняем refresh token если есть
                acc.refresh_token = api.refresh_token
                acc.access_token_expire = api.access_token_expire
                acc.refresh_token_expire = api.refresh_token_expire
                
                # Try to extract UID from login response
                uid = api.get_uid_from_login_response(data)
                if uid:
                    acc.uid = uid
                    self.log.emit(format_login_step(acc.username, "UID получен", True, f"uid={uid}"))
                else:
                    # If we can't get UID, try to parse from username if it's in XP format
                    if acc.username.startswith("XP"):
                        try:
                            acc.uid = int(acc.username[2:])
                            self.log.emit(format_login_step(acc.username, "UID получен из имени", True, f"uid={acc.uid}"))
                        except:
                            self.log.emit(format_login_step(acc.username, "UID не найден", False, "не удалось извлечь из имени пользователя"))
                
                acc.last_login_at = time.time()
                acc.headers = api.session.headers.copy()
                self.account_updated.emit(idx, acc.as_row())
                token_status = 'получен' if token else 'отсутствует'
                self.log.emit(format_login_step(acc.username, "Авторизация завершена", bool(token), f"токен {token_status}"))
            except ApiError as e:
                self.log.emit(format_login_step(acc.username, "Ошибка API", False, str(e)))
            except Exception as e:
                self.log.emit(format_login_step(acc.username, "Ошибка авторизации", False, str(e)))
            time.sleep(self._rand_delay())

    def task_logout_selected(self, rows: List[int]):
        for r in rows:
            if self._stop: break
            acc = self.accounts[r]
            if not acc.token:
                self.log.emit(f"{Icons.WARNING} [{acc.username}] Выход: нет токена")
                continue
            try:
                api = XPokerAPI(proxy=acc.proxy)
                api.logout(acc.token)
                acc.token = None
                self.account_updated.emit(r, acc.as_row())
                self.log.emit(f"{Icons.SUCCESS} [{acc.username}] Выход выполнен успешно")
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [{acc.username}] Ошибка выхода: {e}")
            time.sleep(self._rand_delay())

    def task_join_round(self, club_ids: List[str], clubs_per_account: int, delay_min_ms: int, delay_max_ms: int, message_text: Optional[str] = None):
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
                self.log.emit(f"{Icons.INFO} [{acc.username}] Клубы закончились, аккаунт пропускается")
                break
            account_clubs = club_ids[start_idx:end_idx]
            club_index = end_idx
            # Логируем диапазон клубов для аккаунта
            if len(account_clubs) > 0:
                clubs_range = f"{account_clubs[0]}-{account_clubs[-1]}" if len(account_clubs) > 1 else account_clubs[0]
                self.log.emit(f"{Icons.INFO} 👤 [{acc.username}] назначено {len(account_clubs)} клубов: {clubs_range}")
            account_jobs.append((acc, account_clubs))
        
        # Параллельная обработка по аккаунтам: одно TCP-соединение на аккаунт
        import threading
        processed_clubs_lock = threading.Lock()
        processed_clubs_total = 0
        threads: list[threading.Thread] = []
        
        def account_worker(acc: Account, account_clubs: list[str]):
            nonlocal processed_clubs_total
            try:
                # Проверка обязательных полей
                if not acc.uid:
                    self.log.emit(f"{Icons.ERROR} [{acc.username}] UID отсутствует — пропуск аккаунта")
                    return
                api = XPokerAPI(proxy=acc.proxy)
                api.token = acc.token
                api.refresh_token = acc.refresh_token
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
                    # done = idx + 1
                    done = idx + 1
                    self.join_result.emit(JoinResult(ts=time.time(), username=acc.username, club_id=str(cid), ok=ok, message=msg))
                    result_msg = format_join_result(acc.username, str(cid), ok, msg)
                    self.log.emit(result_msg)
                    self.account_progress.emit(acc.username, done, total, ("✅ Клуб есть" if ok else "❌ Клуба нет"), str(cid))
                    nonlocal processed_clubs_total
                    with processed_clubs_lock:
                        processed_clubs_total += 1
                    # Избегаем лишнего ожидания после запроса остановки
                    if not self._stop:
                        time.sleep(self._rand_delay())
                # Преобразуем ID клубов в int
                club_ids_int: list[int] = []
                for cid in account_clubs:
                    try:
                        club_ids_int.append(int(cid))
                    except Exception:
                        self.log.emit(f"{Icons.ERROR} [{acc.username}] Неверный формат ID клуба: {cid}")
                if not club_ids_int:
                    return
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
                # Если result_cb уже отдал все, можно дополнительно финализировать статус
                self.account_progress.emit(acc.username, len(results), len(club_ids_int), "🏁 Завершено", "-")
            except Exception as e:
                self.log.emit(f"{Icons.ERROR} [{acc.username}] Ошибка обработки аккаунта: {e}")
        
        # Стартуем потоки по аккаунтам
        for acc, acc_clubs in account_jobs:
            t = threading.Thread(target=account_worker, args=(acc, acc_clubs), daemon=True)
            threads.append(t)
            t.start()
        
        # Ожидаем завершения всех аккаунтов, при этом уважаем стоп/паузу
        # Ожидаем завершения всех аккаунтов, уважая паузу; при остановке ждём корректного завершения текущих попыток
        while any(t.is_alive() for t in threads):
            self._wait_if_paused()
            # При остановке не засоряем лог дополнительными сообщениями — просто ждём корректного завершения
            time.sleep(0.2)
        
        # Завершение задачи
        if not self._stop:
            self.log.emit(f"{Icons.SUCCESS} 🎯 Процесс вступления завершён. Всего обработано клубов: {processed_clubs_total}")
        # При остановке дополнительно ничего не пишем — единственное сообщение уже было при нажатии кнопки
        self.task_finished.emit()

    def _rand_delay(self):
        import random
        a,b = self.jitter_ms
        return random.randint(a,b)/1000.0


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
            QMessageBox.warning(self, "Ошибка", "ID клуба должен быть числом!")
            self.club_id_edit.setFocus()
            return False
            
        return True
    
    def accept(self):
        if self.validate():
            super().accept()

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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 760)

        self.accounts: List[Account] = []
        self.club_ids: List[str] = []
        self.report_rows: List[dict] = []

        root = QWidget()
        self.setCentralWidget(root)
        v = QVBoxLayout(root)

        # 🔸 СЕКЦИЯ УПРАВЛЕНИЯ АККАУНТАМИ
        accounts_group = QGroupBox("📋 Управление аккаунтами")
        accounts_layout = QHBoxLayout(accounts_group)
        
        self.btn_add_account = QPushButton("➕ Добавить аккаунт")
        self.btn_edit_account = QPushButton("✏️ Редактировать")
        self.btn_delete_account = QPushButton("🗑️ Удалить")
        self.btn_load_accounts = QPushButton("📁 Из Excel файла")
        self.btn_save_accounts = QPushButton("💾 Сохранить настройки")
        
        accounts_layout.addWidget(self.btn_add_account)
        accounts_layout.addWidget(self.btn_edit_account)
        accounts_layout.addWidget(self.btn_delete_account)
        accounts_layout.addWidget(self.btn_load_accounts)
        accounts_layout.addWidget(self.btn_save_accounts)
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
        operations_layout.addWidget(self.btn_check_update)
        # Тема (светлая/тёмная/системная)
        operations_layout.addWidget(QLabel("Тема:"))
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItem("Системная", userData='system')
        self.cmb_theme.addItem("Светлая", userData='light')
        self.cmb_theme.addItem("Тёмная", userData='dark')
        operations_layout.addWidget(self.cmb_theme)
        operations_layout.addStretch()
        v.addWidget(operations_group)

        knobs = QHBoxLayout()
        knobs.addWidget(QLabel("Клубов на аккаунт (0 = все клубы):"))
        self.spn_clubs_per_account = QSpinBox(); self.spn_clubs_per_account.setRange(0, 10000); self.spn_clubs_per_account.setValue(500)
        knobs.addWidget(self.spn_clubs_per_account)
        knobs.addWidget(QLabel("Задержка мин (мс):"))
        self.spn_delay_min = QSpinBox(); self.spn_delay_min.setRange(0, 10000); self.spn_delay_min.setValue(500)
        knobs.addWidget(self.spn_delay_min)
        knobs.addWidget(QLabel("Задержка макс (мс):"))
        self.spn_delay_max = QSpinBox(); self.spn_delay_max.setRange(0, 20000); self.spn_delay_max.setValue(1500)
        knobs.addWidget(self.spn_delay_max)
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
        
        self.worker = Worker(self.accounts)
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
        # Статус-бар с версией
        try:
            self.statusBar().showMessage("")
            ver_lbl = QLabel(f"Версия: {__version__}")
            self.statusBar().addPermanentWidget(ver_lbl)
        except Exception:
            pass

    def on_load_accounts(self):
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

    def on_login_all(self):
        if not self.accounts:
            QMessageBox.critical(self, "Ошибка", "Сначала загрузите аккаунты")
            return
        if self.worker.isRunning():
            QMessageBox.information(self, "Занято", "Процесс уже выполняется")
            return
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
        self.worker.set_task(self.worker.task_join_round, clubs_to_process, limit, dmin, dmax, message_text)
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
                'theme': getattr(self, 'theme_pref', 'system'),
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
            # Сообщение заявки
            self.txt_message.setText(ui_settings.get('apply_message', ''))
            # Тема (установить выбор и применить)
            theme_mode = ui_settings.get('theme', 'system')
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
        """Обработчик завершения задачи - сбрасываем флаг остановки."""
        self.worker._stop = False
        self.worker._pause = False
        # Сбрасываем событие отмены для следующего запуска
        try:
            self.worker._cancel_event.clear()
        except Exception:
            pass
        # Очищаем информацию о последнем клубе
        self.worker._last_club_info = {
            'club_id': None,
            'username': None,
            'success': None,
            'message': None
        }

    def closeEvent(self, event):
        try:
            self.save_settings()
        except Exception as e:
            self.log.appendPlainText(f"{Icons.ERROR} Ошибка сохранения при выходе: {e}")
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

