"""Protocol utilities for TCP framing, varint encoding, and packet manipulation."""

import struct
import socket
from typing import Tuple, Optional
import logging

log = logging.getLogger(__name__)


# Varint encoding/decoding (Protocol Buffers LEB128)

def varint_encode(n: int) -> bytes:
    """Encode integer as protobuf varint (LEB128).
    
    Args:
        n: Non-negative integer to encode
        
    Returns:
        Encoded varint bytes
        
    Raises:
        AssertionError: If n is negative
    """
    assert n >= 0, "varint_encode only supports non-negative integers"
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def varint_decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode protobuf varint from bytes.
    
    Args:
        data: Byte data containing varint
        offset: Starting offset in data
        
    Returns:
        Tuple of (decoded_value, next_offset)
        
    Raises:
        AssertionError: If varint is truncated or overflows
    """
    shift = 0
    result = 0
    i = offset
    while i < len(data):
        byte = data[i]
        result |= ((byte & 0x7F) << shift)
        i += 1
        if (byte & 0x80) == 0:
            return result, i
        shift += 7
        assert shift <= 63, "varint overflow"
    raise AssertionError("truncated varint")


# TCP framing utilities

def frame_pack(payload: bytes) -> bytes:
    """Pack payload with big-endian 32-bit length prefix.
    
    Args:
        payload: Data to frame
        
    Returns:
        Length-prefixed frame
    """
    return struct.pack(">I", len(payload)) + payload


def frame_read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket.
    
    Args:
        sock: Socket to read from
        n: Number of bytes to read
        
    Returns:
        Exactly n bytes
        
    Raises:
        OSError: If EOF is reached before n bytes are read
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("EOF while reading")
        buf += chunk
    return buf


def frame_recv(sock: socket.socket) -> bytes:
    """Receive one complete frame from socket.
    
    Args:
        sock: Socket to receive from
        
    Returns:
        Frame payload (without length prefix)
        
    Raises:
        ValueError: If frame size exceeds 1MB
        OSError: If socket is closed
    """
    hdr = frame_read_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length > 1024 * 1024:  # Sanity check: max 1MB
        raise ValueError(f"Frame too large: {length} bytes")
    return frame_read_exact(sock, length)


def frame_send(sock: socket.socket, payload: bytes) -> None:
    """Send frame with big-endian 32-bit length prefix.
    
    Args:
        sock: Socket to send on
        payload: Data to send
    """
    sock.sendall(frame_pack(payload))


# Packet patching utilities

def patch_varint(payload: bytes, old_value: int, new_value: int) -> bytes:
    """Replace varint value in payload.
    
    Args:
        payload: Original payload
        old_value: Varint value to find
        new_value: Replacement varint value
        
    Returns:
        Modified payload with varint replaced
    """
    old_v = varint_encode(old_value)
    new_v = varint_encode(new_value)
    
    data = bytearray(payload)
    idx = data.find(old_v)
    if idx >= 0:
        if len(old_v) != len(new_v):
            # Structural patch: rebuild the payload
            log.debug(f"Varint length changed: {len(old_v)} -> {len(new_v)}")
            data = data[:idx] + new_v + data[idx+len(old_v):]
        else:
            # Simple replacement when lengths match
            data[idx:idx+len(old_v)] = new_v
        return bytes(data)
    else:
        log.debug(f"Varint {old_value} (0x{old_v.hex()}) not found in payload")
        # Try to find it in a protobuf field context (field_num << 3 | wire_type)
        # For common fields, try field 1 with wire_type 0 (varint)
        field_tag = bytes([0x08])  # field 1, wire_type 0
        pattern = field_tag + old_v
        idx = data.find(pattern)
        if idx >= 0:
            log.debug(f"Found varint with field tag at offset {idx}")
            replacement = field_tag + new_v
            data = data[:idx] + replacement + data[idx+len(pattern):]
            return bytes(data)
        log.debug(f"Could not find varint in any context")
        return payload


def patch_string(payload: bytes, old_str: bytes, new_str: bytes) -> bytes:
    """Replace length-delimited string in payload.
    
    Args:
        payload: Original payload
        old_str: String to find (as bytes)
        new_str: Replacement string (as bytes)
        
    Returns:
        Modified payload with string replaced
    """
    # Find the old string with its length prefix
    old_len = varint_encode(len(old_str))
    new_len = varint_encode(len(new_str))
    
    pattern = old_len + old_str
    data = payload
    
    idx = data.find(pattern)
    if idx >= 0:
        # Replace with new length and string
        replacement = new_len + new_str
        data = data[:idx] + replacement + data[idx+len(pattern):]
        return data
    else:
        # Try finding just the string (sometimes length is elsewhere)
        idx = data.find(old_str)
        if idx >= 0 and len(old_str) == len(new_str):
            # Simple same-length replacement
            data = data[:idx] + new_str + data[idx+len(old_str):]
            return data
        else:
            log.warning(f"String {old_str[:20]}... not found in payload")
            return payload


# Packet building utilities

def build_packet_old(msg_id: bytes, msg_type: str, payload: bytes) -> bytes:
    """OLD Build a complete packet with application header (DEPRECATED).
    
    Args:
        msg_id: 6-byte message ID/header
        msg_type: Message type string (e.g., "pk.UserLoginREQ")
        payload: Protobuf payload
        
    Returns:
        Complete packet ready to send
    """
    msg_type_bytes = msg_type.encode('utf-8') if isinstance(msg_type, str) else msg_type
    separator = bytes([0x00, 0x01])
    return msg_id + msg_type_bytes + separator + payload + bytes([0x00, 0x01])


def build_packet_correct(msg_type: str, msg_type_id: int, payload: bytes, sequence: int = 1) -> bytes:
    """Build a correct X-Poker TCP packet based on real protocol analysis.
    
    Real packet structure from analysis:
    [length 4 bytes BE] [msg_type 2 bytes BE] [padding 4 bytes] [command] [separator] [protobuf] [sequence 2 bytes LE]
    
    Args:
        msg_type: Message type string (e.g., "pk.GetClubDescREQ")
        msg_type_id: Message type ID (e.g., 0x0011)
        payload: Protobuf payload
        sequence: Packet sequence number (default 1, should increment per request)
        
    Returns:
        Complete packet ready to send
    """
    msg_type_bytes = msg_type.encode('utf-8') if isinstance(msg_type, str) else msg_type
    
    # Encode sequence as 2-byte big-endian (matches dumps: ... 00 01 at end)
    sequence_bytes = sequence.to_bytes(2, 'big')
    
    # Calculate packet size (everything after first 4 bytes)
    # msg_type_id (2) + padding (4) + command + separator + payload + sequence (2)
    content_size = 2 + 4 + len(msg_type_bytes) + 2 + len(payload) + 2
    
    # Build packet: [packet_length 4 bytes BE] [msg_type 2 bytes BE] [padding 4 bytes] [command] [sep] [payload] [seq]
    packet = content_size.to_bytes(4, 'big')      # Total packet length (4 bytes big-endian)
    packet += msg_type_id.to_bytes(2, 'big')      # Message type (2 bytes big-endian)
    packet += bytes([0x00, 0x00, 0x00, 0x00])     # Reserved padding (4 bytes)
    packet += msg_type_bytes                      # Command string
    packet += bytes([0x00, 0x01])                 # Separator
    packet += payload                              # Protobuf payload
    packet += sequence_bytes                       # Packet sequence (2 bytes little-endian)
    
    return packet
