#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import time
import json
import argparse
import logging
from typing import List, Dict, Any, Optional, Union

# Local imports
from core.api import XPokerAPI, ApiError
from core.client import XClubTCPClient
from core.protobuf_decoder import ProtobufDecoder
from core.constants import XPOKER_CLIENT_VERSION, CLUB_SERVER_HOST, CLUB_SERVER_PORT

log = logging.getLogger("xpoker.test.apply")

DEFAULT_CLUBS = [
    # Явно несуществующие для проверки
    1,
    123123,
    # Заведомо существующие
    2375903,
    2447558,
    2372921,
    2408866,
    2384512,
    2395341,
    2400561,
    2436768,
    2350648,
    2403595,
]

def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=(logging.DEBUG if verbose else logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def env_or_default(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if (v is not None and str(v).strip() != "") else default


def extract_reason_from_fields(fields: Dict[int, List[Any]]) -> str:
    """Пытаемся извлечь человекочитаемую причину из строковых полей ответа."""
    if not isinstance(fields, dict):
        return ""
    best = ""
    try:
        for _f, vals in fields.items():
            for v in vals or []:
                if isinstance(v, str):
                    s = v.strip()
                    if not s:
                        continue
                    if s.lower().startswith("http"):
                        continue
                    if len(s) > len(best):
                        best = s
    except Exception:
        pass
    return best


def _norm_value(v: Any) -> Any:
    """Сделать значение JSON-безопасным (bytes->hex+len, рекурсивно по dict/list)."""
    try:
        if isinstance(v, bytes):
            return {"bytes_hex": v[:32].hex(), "len": len(v)}
        if isinstance(v, dict):
            return {str(k): _norm_value(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_norm_value(x) for x in v]
        return v
    except Exception:
        try:
            return str(v)
        except Exception:
            return "<unserializable>"


def normalize_fields(fields: Dict[int, List[Any]]) -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = {}
    try:
        for k, vals in (fields or {}).items():
            out[str(k)] = [_norm_value(x) for x in (vals or [])]
    except Exception:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser("XPoker apply tester")
    ap.add_argument("--username", dest="username", default=env_or_default("XPOKER_USER"))
    ap.add_argument("--password", dest="password", default=env_or_default("XPOKER_PASS"))
    ap.add_argument("--device-id", dest="device_id", default=env_or_default("XPOKER_DEVICE_ID"))
    ap.add_argument("--proxy", dest="proxy", default=env_or_default("XPOKER_PROXY"))
    ap.add_argument("--clubs", dest="clubs", help="Список клубов через запятую", default=None)
    ap.add_argument("--verbose", dest="verbose", action="store_true")
    args = ap.parse_args()

    setup_logging(args.verbose)

    if not args.username or not args.password:
        log.error("Укажите --username и --password (или XPOKER_USER/XPOKER_PASS)")
        return 2
    device_id = args.device_id or os.environ.get("COMPUTERNAME") or "device"

    clubs: List[int]
    if args.clubs:
        try:
            clubs = [int(x.strip()) for x in args.clubs.split(",") if x.strip()]
        except Exception:
            log.error("Некорректный формат --clubs (ожидаются числа, через запятую)")
            return 2
    else:
        clubs = DEFAULT_CLUBS

    log.info("Шаг 1: HTTP логин…")
    api = XPokerAPI(proxy=args.proxy)
    try:
        login_data = api.login(username=args.username, password=args.password, device_id=device_id)
    except ApiError as e:
        log.error(f"HTTP login ApiError: {e}")
        return 1
    except Exception as e:
        log.error(f"HTTP login error: {e}")
        return 1

    uid = api.get_uid_from_login_response(login_data)
    token = api.token
    if not uid or not token:
        log.error("Не удалось получить uid/token из ответа логина")
        return 1
    log.info(f"Логин ок: uid={uid}; токен получен; TCP entry: {getattr(api,'tcp_entries', [])}")

    # Подготовим TCP клиент (строгий режим, как в API)
    if getattr(api, "tcp_entries", None):
        host, port = api.tcp_entries[0]
    else:
        host, port = CLUB_SERVER_HOST, CLUB_SERVER_PORT
    log.info(f"Шаг 2: TCP соединение с {host}:{port}…")
    tcp = XClubTCPClient(host=host, port=int(port), timeout=3.0, proxy=args.proxy, disable_bootstrap=True, frida_strict=True)
    try:
        tcp.connect()
        rsp = tcp.tcp_login(int(uid), token, version=XPOKER_CLIENT_VERSION)
        if b"pk.UserLoginRSP" not in rsp:
            log.error("TCP логин неуспешен — прерывание")
            return 1
    except Exception as e:
        log.error(f"TCP connect/login error: {e}")
        return 1

    log.info("Шаг 3: Проверка клубов…")
    results: List[Dict[str, Any]] = []
    for idx, cid in enumerate(clubs, 1):
        try:
            time.sleep(0.1)
            log.info(f"[{idx}/{len(clubs)}] Клуб {cid}: GetClubDescREQ…")
            desc = b""
            desc_exists_rsp = False
            desc_exists_sem = False
            club_name = ""
            try:
                desc = tcp.get_club_desc(int(cid))
                desc_exists_rsp = bool(desc) and (b"pk.GetClubDescRSP" in desc)
                if desc_exists_rsp:
                    try:
                        parsed_desc = ProtobufDecoder.decode_club_desc_response(desc)
                        info = (parsed_desc or {}).get("club_info", {}) or {}
                        club_name = str(info.get("club_name") or "")
                        desc_exists_sem = bool(info.get("exists") or club_name)
                    except Exception:
                        desc_exists_sem = False
            except Exception:
                desc_exists_rsp = False
                desc_exists_sem = False
            log.info(f"[{cid}] exists_rsp={desc_exists_rsp} exists_sem={desc_exists_sem} club_name='{club_name}'")

            log.info(f"[{cid}] ApplyClubREQ…")
            apply_rsp = tcp.apply_club(int(cid), int(uid))
            if not apply_rsp:
                log.warning(f"[{cid}] ApplyClubRSP не получен")
                results.append({"club_id": cid, "exists": exists, "status": None, "message": "no response", "reason": ""})
                continue
            try:
                decoded = ProtobufDecoder.decode_apply_club_response(apply_rsp)
            except Exception as de:
                log.error(f"[{cid}] decode error: {de}")
                results.append({"club_id": cid, "exists": exists, "status": None, "message": f"decode error: {de}", "reason": "", "rsp_hex_full": apply_rsp.hex()})
                continue

            status = decoded.get("status")
            message = decoded.get("message") or ""
            raw_fields = decoded.get("raw_fields") or {}
            reason = extract_reason_from_fields(raw_fields)
            raw_hex = (decoded.get("raw_hex") or "")
            payload_len = len(raw_hex) // 2
            status_label = {0: "success", 1: "pending", 2: "already_member", 1002: "club_not_found", 1005: "daily_limit"}.get(status, "unknown")
            rsp_hex_full = apply_rsp.hex()

            # Сводка по клубу (расширенная)
            summary = {
                "club_id": cid,
                "exists_rsp": desc_exists_rsp,
                "exists_sem": desc_exists_sem,
                "club_name": club_name,
                "status": status,
                "status_label": status_label,
                "message": message,
                "reason": reason,
                "payload_len": payload_len,
                "raw_hex_head": raw_hex[:64],
                "raw_hex_tail": raw_hex[-64:],
                "raw_fields": normalize_fields(raw_fields),
                "rsp_hex_full": rsp_hex_full,
                "desc_hex_full": (desc.hex() if desc else ""),
            }
            results.append(summary)

            # Короткий лог
            base = f"[{cid}] status={status}({status_label}) msg='{message}'"
            if reason:
                base += f" reason='{reason}'"
            if status_label == "unknown":
                base += f" payload_len={payload_len} raw_hex_full={raw_hex}"
            log.info(base)
        except KeyboardInterrupt:
            log.warning("Прервано пользователем")
            break
        except Exception as e:
            log.error(f"[{cid}] ошибка: {e}")
            results.append({"club_id": cid, "exists": None, "status": None, "message": str(e), "reason": ""})

    # Итоговый JSON для копирования
    try:
        print("\n=== JSON results ===")
        print(json.dumps(results, ensure_ascii=False, indent=2))
    except Exception:
        pass

    try:
        tcp.close()
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
