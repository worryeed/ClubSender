"""FishPoker protocol helpers.

FishPoker uses the same pb.* framing as PPPoker, but with a different 4-byte pad (00 00 00 00).
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple, Union

WT_VARINT = 0
WT_LEN = 2


def varint_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint expects non-negative")
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
    x = 0
    shift = 0
    i = offset
    while i < len(data):
        b = data[i]
        x |= (b & 0x7F) << shift
        i += 1
        if (b & 0x80) == 0:
            return x, i
        shift += 7
        if shift > 63:
            break
    raise ValueError("bad varint")


def build_frame(type_str: str, payload: bytes, *, pad4: bytes = b"\x00\x00\x00\x00") -> bytes:
    t = type_str.encode("ascii")
    if len(pad4) != 4:
        raise ValueError("pad4 must be 4 bytes")
    total = 2 + len(t) + 4 + len(payload)
    return struct.pack(">I", total) + struct.pack(">H", len(t)) + t + pad4 + payload


def parse_frame(frame: bytes) -> Optional[Tuple[str, bytes]]:
    try:
        (length,) = struct.unpack(">I", frame[:4])
        body = frame[4 : 4 + length]
        (tlen,) = struct.unpack(">H", body[:2])
        tstr = body[2 : 2 + tlen].decode("ascii", "replace")
        payload = body[2 + tlen + 4 :]
        return tstr, payload
    except Exception:
        return None


def parse_top_fields(payload: bytes) -> List[Dict[str, Union[int, str, bytes]]]:
    """Very small parser for top-level protobuf-like fields (wire 0 and 2)."""
    out: List[Dict[str, Union[int, str, bytes]]] = []
    i = 0
    while i < len(payload):
        try:
            key, i = varint_decode(payload, i)
        except Exception:
            break
        fno = key >> 3
        wt = key & 7
        if wt == WT_VARINT:
            try:
                v, i = varint_decode(payload, i)
            except Exception:
                break
            out.append({"f": fno, "wt": wt, "val": v})
        elif wt == WT_LEN:
            try:
                L, i = varint_decode(payload, i)
            except Exception:
                break
            if i + L > len(payload):
                break
            chunk = payload[i : i + L]
            i += L
            try:
                out.append({"f": fno, "wt": wt, "len": L, "str": chunk.decode("utf-8")})
            except Exception:
                out.append({"f": fno, "wt": wt, "len": L, "hex": chunk[:32].hex()})
        else:
            out.append({"f": fno, "wt": wt})
            break
    return out
