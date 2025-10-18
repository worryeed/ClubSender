from __future__ import annotations
from typing import Optional, Callable
import logging
import os

try:
    from pyupdater.client import Client
except Exception:  # pragma: no cover
    Client = None  # type: ignore

log = logging.getLogger(__name__)


class AppClientConfig(object):
    """PyUpdater client configuration.

    UPDATE_URLS указывает на GitHub Pages ветки gh-pages этого репозитория.
    PUBLIC_KEY должен быть установлен после генерации ключей PyUpdater.
    """

    APP_NAME = "ClubSender"
    COMPANY_NAME = "ClubSender"
    UPDATE_URLS = [
        "https://worryeed.github.io/ClubSender/"
    ]
    # После генерации ключей поместите публичный ключ в переменную окружения
    # CLUBSENDER_PYU_PUBKEY или обновите это значение строкой PEM напрямую.
    PUBLIC_KEY = os.environ.get("CLUBSENDER_PYU_PUBKEY", None)


class UpdateManager:
    def __init__(self, current_version: str):
        self.current_version = current_version
        self._client: Optional[Client] = None
        self._update = None

        if Client is None:
            log.warning("PyUpdater client is not available. Install 'pyupdater'.")
            return
        try:
            self._client = Client(AppClientConfig(), refresh=True)
        except Exception as e:
            log.error(f"Update client init failed: {e}")

    def check_for_update(self):
        if not self._client:
            return None
        try:
            upd = self._client.update_check(AppClientConfig.APP_NAME, self.current_version)
            self._update = upd
            return upd
        except Exception as e:
            log.error(f"Update check failed: {e}")
            return None

    def download(self, progress_cb: Optional[Callable[[int], None]] = None) -> bool:
        if not self._update:
            return False
        try:
            ok = self._update.download(progress=progress_cb)
            return bool(ok)
        except Exception as e:
            log.error(f"Update download failed: {e}")
            return False

    def install(self) -> bool:
        if not self._update:
            return False
        try:
            # Для упакованных сборок (PyInstaller) достаточно extract_restart().
            # Для скриптов — extract() и ручной перезапуск.
            try:
                self._update.extract_restart()  # type: ignore[attr-defined]
                return True
            except Exception:
                self._update.extract()
                return True
        except Exception as e:
            log.error(f"Update install failed: {e}")
            return False
