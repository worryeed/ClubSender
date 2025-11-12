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
        Сообщение детализируем:
        - ok=True  -> "Клуб есть"
        - ok=False & отмена -> "Отменено"
        - ok=False & not found -> "Клуба нет"
        - ok=False & прочее -> "Клуб есть, но заявка не отправлена: <причина>"
        """
        raw = (self.message or "").strip()
        low = raw.lower()
        if (not self.ok) and ("cancel" in low or "отмен" in low):
            msg = "Отменено"
        elif self.ok:
            msg = "Клуб есть"
        else:
            not_found_markers = ("не существует", "клуб не найден", "club not found")
            if any(p in low for p in not_found_markers):
                msg = "Клуба нет"
            else:
                reason = raw
                if reason.lower().startswith("join failed:"):
                    reason = reason.split(":", 1)[1].strip() or reason
                msg = f"Клуб есть, но заявка не отправлена: {reason}"
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
