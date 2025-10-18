"""Core business logic modules for X-Poker client."""

# Public API exports
from .api import XPokerAPI, ApiError
from .client import XClubTCPClient
from .models import Account, JoinResult, ClubInfo, TCPSession
from .protocol import (
    varint_encode,
    varint_decode,
    frame_pack,
    frame_send,
    frame_recv,
    patch_varint,
    patch_string,
    build_packet_old,
    build_packet_correct
)
from .constants import (
    CLUB_SERVER_HOST,
    CLUB_SERVER_PORT,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL
)
from .messages import Icons, format_join_result, decode_club_apply_status

__all__ = [
    # API
    "XPokerAPI",
    "ApiError",
    
    # Client
    "XClubTCPClient",
    
    # Models
    "Account",
    "JoinResult",
    "ClubInfo",
    "TCPSession",
    
    # Protocol functions
    "varint_encode",
    "varint_decode",
    "frame_pack",
    "frame_send",
    "frame_recv",
    "patch_varint",
    "patch_string",
    "build_packet_old",
    "build_packet_correct",
    
    # Constants
    "CLUB_SERVER_HOST",
    "CLUB_SERVER_PORT",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_HEARTBEAT_INTERVAL",
    
    # Messages
    "Icons",
    "format_join_result",
    "decode_club_apply_status",
]
