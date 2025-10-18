# Core Module Documentation

## Overview
The `core` module contains all business logic for the X-Poker client, cleanly separated from GUI code.

## Module Structure

### core/protocol.py
Low-level protocol utilities for TCP communication:
- `varint_encode(n)` - Encode integer as Protocol Buffers varint
- `varint_decode(data, offset)` - Decode varint from bytes
- `frame_pack(payload)` - Pack payload with length prefix
- `frame_send(sock, payload)` - Send framed data over socket
- `frame_recv(sock)` - Receive framed data from socket
- `patch_varint(payload, old, new)` - Replace varint in payload
- `patch_string(payload, old, new)` - Replace string in payload
- `build_packet(msg_id, msg_type, payload)` - Build complete packet

### core/client.py
TCP client implementation:
- `XClubTCPClient` - Main TCP client class
  - `connect()` - Connect to server
  - `close()` - Close connection
  - `tcp_login(uid, token, version)` - Perform TCP login
  - `get_club_desc(club_id)` - Get club description
  - `apply_club(club_id, uid)` - Apply to join club
  - `search_club(search_id)` - Search for club
  - `start_heartbeat(interval)` - Start keepalive heartbeat
  - `full_join_flow(uid, token, club_id)` - Complete join flow

### core/api.py
HTTP API client:
- `XPokerAPI` - Main API client class
  - `login(username, password, ...)` - HTTP login
  - `logout(token)` - HTTP logout
  - `join_club(club_id, token)` - HTTP club join (usually fails)
  - `search_club(query, token)` - HTTP club search
  - `join_club_tcp(club_id, uid, token)` - TCP club join (works)
  - `get_uid_from_login_response(data)` - Extract UID from login

### core/models.py
Data models:
- `Account` - User account information
  - `username`, `password`, `proxy`, `device_id`
  - `token`, `uid`, `last_login_at`
  - `as_row()` - Convert to GUI table row
- `JoinResult` - Club join attempt result
  - `ts`, `username`, `club_id`, `ok`, `message`
  - `as_dict()` - Convert to dictionary
- `ClubInfo` - Club information
- `TCPSession` - TCP session state

### core/constants.py
Configuration and constants:
- Server addresses (`CLUB_SERVER_HOST`, `CLUB_SERVER_PORT`)
- API endpoints (`LOGIN_PATH`, `LOGOUT_PATH`, etc.)
- Protocol message types (`MSG_USER_LOGIN_REQ`, etc.)
- Packet templates (`TEMPLATES`)
- Template values for patching
- Message headers
- Timeouts and intervals

## Usage Examples

### Basic TCP Club Join
```python
from core import XClubTCPClient

client = XClubTCPClient()
success = client.full_join_flow(
    uid=3557707,
    token="your_token_here",
    club_id=123
)
```

### HTTP Login + TCP Join
```python
from core import XPokerAPI

api = XPokerAPI(proxy="http://proxy:8080")
login_data = api.login(
    username="user",
    password="pass",
    password_is_md5=True,
    device_id="device123"
)

uid = api.get_uid_from_login_response(login_data)
if uid and api.token:
    success, msg = api.join_club_tcp(
        club_id=123,
        uid=uid,
        token=api.token
    )
```

### Working with Models
```python
from core import Account, JoinResult

# Create account
acc = Account(
    username="test_user",
    password="test_pass",
    proxy="http://proxy:8080"
)

# Track join result
result = JoinResult(
    ts=time.time(),
    username=acc.username,
    club_id="123",
    ok=True,
    message="Success"
)
```

## Protocol Details

### Varint Encoding
Uses Protocol Buffers LEB128 encoding for variable-length integers.

### TCP Framing
Messages are framed with 4-byte big-endian length prefix.

### Packet Structure
```
[msg_id: 6 bytes] [msg_type: string] [0x00 0x01] [protobuf payload] [0x00 0x01]
```

### Message Flow
1. TCP Connect
2. UserLoginREQ → UserLoginRSP
3. Start heartbeat (GetMoneyREQ every 25s)
4. GetClubDescREQ → GetClubDescRSP (optional)
5. ApplyClubREQ → ApplyClubRSP
6. Close connection

## Testing
Run `test_core_refactor.py` to verify the refactoring:
```bash
python test_core_refactor.py
```

## Migration from Old Code
- Replace `from api import XPokerAPI` with `from core import XPokerAPI`
- Replace `from models import Account` with `from core import Account`
- Replace `from club_tcp_client import XClubTCPClient` with `from core import XClubTCPClient`

Old files have been renamed with `_old_` prefix for reference.
