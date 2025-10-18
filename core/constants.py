"""Constants and configuration values for X-Poker client."""

# Server configuration
CLUB_SERVER_HOST = "158.160.128.14"
CLUB_SERVER_PORT = 5000
DEFAULT_TIMEOUT = 10.0

# HTTP API endpoints
DEFAULT_BASE_URL = "https://api.x-poker.net"
LOGIN_PATH = "/api/auth/login"
LOGOUT_PATH = "/api/token/logout"
REFRESH_PATH = "/api/token/refresh"  # предположительно; при ошибке используем повторный login
JOIN_CLUB_PATH = "/api/club/join"
SEARCH_CLUB_PATH = "/api/club/search"

# Protocol message types
MSG_USER_LOGIN_REQ = "pk.UserLoginREQ"
MSG_USER_LOGIN_RSP = "pk.UserLoginRSP"
MSG_GET_CLUB_DESC_REQ = "pk.GetClubDescREQ"
MSG_GET_CLUB_DESC_RSP = "pk.GetClubDescRSP"
MSG_APPLY_CLUB_REQ = "pk.ApplyClubREQ"
MSG_APPLY_CLUB_RSP = "pk.ApplyClubRSP"
MSG_SEARCH_CLUB_REQ = "pk.SearchClubREQ"
MSG_SEARCH_CLUB_RSP = "pk.SearchClubRSP"
MSG_GET_MONEY_REQ = "pk.GetMoneyREQ"  # Used as heartbeat

# Protocol templates extracted from club_logs3 analysis
TEMPLATES = {
    # pk.UserLoginREQ from send_sock0x7f4_158-160-128-14-5000_1755888927_6394.bin
    # Structure: length(4) + 00 00 + "pk.UserLoginREQ" + 00 01 + protobuf_data + 00 01
    "UserLoginREQ": bytes.fromhex(
        "00 0f 00 00 00 00 70 6b 2e 55 73 65 72 4c 6f 67"
        "69 6e 52 45 51 00 01 1a 20 35 35 38 36 35 35 66"
        "39 35 39 62 35 62 61 34 31 63 64 63 37 63 39 66"
        "31 62 64 31 35 30 62 66 38 10 cb 92 d9 01 0a 07"
        "31 2e 31 32 2e 36 36 00 01"
    ),
    
    # pk.GetClubDescREQ from send_sock0x7f4_158-160-128-14-5000_1755888940_2901.bin
    # Structure: field 1 = club_id (varint), field 2 = 0
    "GetClubDescREQ": bytes.fromhex(
        "00 11 00 00 00 00 70 6b 2e 47 65 74 43 6c 75 62"
        "44 65 73 63 52 45 51 00 01 08 7b 10 00 00 01"
    ),
    
    # pk.ApplyClubREQ from send_sock0x7f4_158-160-128-14-5000_1755888944_5516.bin
    # Structure: field 1 = username (string), field 2 = club_id (varint), field 3 = 0
    "ApplyClubREQ": bytes.fromhex(
        "00 0f 00 00 00 00 70 6b 2e 41 70 70 6c 79 43 6c"
        "75 62 52 45 51 00 01 10 7b 0a 0c d0 af 20 58 50"
        "33 35 35 37 37 30 37 18 00 00 01"
    ),
    
    # pk.GetMoneyREQ - used as heartbeat from logs
    "HeartbeatREQ": bytes.fromhex(
        "00 0e 00 00 00 00 70 6b 2e 47 65 74 4d 6f 6e 65"
        "79 52 45 51 00 01 18 02 00 01"
    ),
    
    # pk.HBREQ - proper heartbeat согласно TCP инструкции (18 байт payload)
    "HBREQ": bytes.fromhex(
        "00 08 00 00 00 00 70 6b 2e 48 42 52 45 51 00 01"
        "00 01"
    )
}

# Known values from templates for patching
TEMPLATE_VALUES = {
    "token": b"558655f959b5ba41cdc7c9f1bd150bf8",
    "uid": 27849547,  # Decoded from varint 0xcb92d901 
    "club_id": 123,  # 0x7b from packets
    "username": "Я XP3557707".encode('utf-8'),  # UTF-8 bytes from ApplyClubREQ
    "version": b"1.12.67"
}

# Message headers (DEPRECATED - old 6-byte application headers)
MSG_HEADERS = {
    "UserLoginREQ": bytes.fromhex("00 0f 00 00 00 00"),
    "GetClubDescREQ": bytes.fromhex("00 11 00 00 00 00"),
    "ApplyClubREQ": bytes.fromhex("00 0f 00 00 00 00"),
    "SearchClubREQ": bytes.fromhex("00 12 00 00 00 00"),
    "HeartbeatREQ": bytes.fromhex("00 0e 00 00 00 00"),
}

# Correct message type IDs from real protocol analysis
# Note: По наблюдениям из "TCP инструкция.md" почти все pk.* (кроме HB/Logout) используют код 0x000f.
MSG_TYPE_IDS = {
    # Login / Apply / Heartbeat core
    "UserLoginREQ": 0x000f,
    "UserLoginRSP": 0x000f,
    "ApplyClubREQ": 0x000f,
    "ApplyClubRSP": 0x000f,
    "GetMoneyREQ": 0x000e,
    "HBREQ": 0x0008,
    "HBRSP": 0x0008,

    # Club description
    "GetClubDescREQ": 0x0011,
    "GetClubDescRSP": 0x0011,
    "GetClubDescListREQ": 0x0015,
    "GetClubDescListRSP": 0x0015,

    # Self / user data and related (per logs multiple share 0x0016)
    "GetSelfDataREQ": 0x0011,
    "GetSelfDataRSP": 0x0011,
    "GetSelfGamesInfoREQ": 0x0016,
    "GetSelfGamesInfoRSP": 0x0016,
    "GetUserCustomizeREQ": 0x0016,
    "GetUserCustomizeRSP": 0x0016,
    "GetDailyTaskInfoREQ": 0x0016,
    "GetDailyTaskInfoRSP": 0x0016,

    # Family / activity / rewards
    "GetFamilyGameListREQ": 0x0017,
    "GetFamilyGameListRSP": 0x0017,
    # Risk management
    "GetRiskManageDetailREQ": 0x0019,
    "GetRiskManageDetailRSP": 0x0019,
    # Timing rewards
    "GetTimingRewardStatusREQ": 0x001b,
    "GetTimingRewardStatusRSP": 0x001b,
    "GetDailyLoginRewardStatusREQ": 0x001f,
    "GetDailyLoginRewardStatusRSP": 0x001f,
    "FetchNewUserNDayRewardREQ": 0x001c,
    "FetchNewUserNDayRewardRSP": 0x001c,

    # Appearance / items / email
    "GetAppearanceSystemDataREQ": 0x001d,
    "GetAppearanceSystemDataRSP": 0x001d,
    "GetItemCountByTypeREQ": 0x0018,
    "GetItemCountByTypeRSP": 0x0018,
    "GetCollectHandListREQ": 0x0018,
    "GetCollectHandListRSP": 0x0018,
    "GetEMailListREQ": 0x0012,
    "GetEMailListRSP": 0x0012,

    # Waiting list
    "GetWaitingListDetailREQ": 0x001a,
    "GetWaitingListDetailRSP": 0x001a,

    # Search
    "SearchClubREQ": 0x0012,

    # Logout
    "UserLogoutREQ": 0x0010,
    "UserLogoutRSP": 0x0010,
}

# Heartbeat configuration
DEFAULT_HEARTBEAT_INTERVAL = 3.0  # seconds (согласно TCP инструкции)

# Frame size limits
MAX_FRAME_SIZE = 1024 * 1024  # 1MB
