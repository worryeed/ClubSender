"""Data models for X-Poker client."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import time


@dataclass
class Account:
    """Account information for a user."""
    username: str
    password: str
    proxy: Optional[str] = None
    device_id: str = ""
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    access_token_expire: Optional[int] = None
    refresh_token_expire: Optional[int] = None
    uid: Optional[int] = None  # User ID from login response
    last_login_at: Optional[float] = None
    headers: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> List[str]:
        """Convert account to table row for GUI display."""
        return [
            self.username,
            "******",
            self.proxy or "",
            self.device_id or "",
            self.token[:10] + "..." if self.token else "",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_login_at)) if self.last_login_at else "",
        ]


@dataclass
class JoinResult:
    """Result of a club join attempt."""
    ts: float
    username: str
    club_id: str
    ok: bool
    message: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting - ключи должны соответствовать REPORT_COLUMNS.
        Здесь нормализуем текст сообщения под требования GUI/отчёта:
        - ok=True  -> "Клуб есть"
        - ok=False -> "Клуба нет"
        - отмена   -> "Отменено"
        """
        raw = (self.message or "").strip()
        if (not self.ok) and ("Cancel" in raw or "Отмен" in raw):
            msg = "Отменено"
        else:
            msg = "Клуб есть" if self.ok else "Клуба нет"
        return {
            "Время": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "Имя пользователя": self.username,
            "ID клуба": self.club_id,
            "Успешно": "✅ Да" if self.ok else "❌ Нет",
            "Сообщение": msg,
        }


@dataclass
class ClubInfo:
    """Information about a club."""
    club_id: int
    name: str = ""
    description: str = ""
    member_count: int = 0
    owner: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TCPSession:
    """TCP session state."""
    uid: int
    token: str
    connected: bool = False
    last_heartbeat: Optional[float] = None
    sequence_number: int = 0
