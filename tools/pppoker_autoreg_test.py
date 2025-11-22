#!/usr/bin/env python3
from __future__ import annotations
import sys, os, json, argparse, uuid

# ensure repo root on sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pppoker.api import PPPokerAPI, ApiError


def main():
    p = argparse.ArgumentParser(description="PPPoker auto-registration test: register -> login")
    p.add_argument("--username", default="QWEASDQWEASD123123")
    p.add_argument("--password", default="qweqwe123123")
    p.add_argument("--proxy", default="http://QDC294:zLWrLH@161.115.231.152:9994", help="http(s)://user:pass@host:port")
    p.add_argument("--device-id", default="", help="optional device id seed (random if empty)")
    p.add_argument("--timeout", type=int, default=30)
    args = p.parse_args()

    if not args.device_id:
        args.device_id = str(uuid.uuid4())

    api = PPPokerAPI(proxy=args.proxy, timeout=args.timeout)

    # Prefetch root to set cookies (aliyungf_tc) as клиент делает
    try:
        api.session.get("https://www.pppoker.club/", proxies=api.proxies, timeout=10)
    except Exception:
        pass

    print("[INFO] Register...")
    try:
        rj = api.register(username=args.username, password=args.password, device_id=args.device_id)
    except Exception as e:
        print(f"[ERROR] Register error: {e}")
        sys.exit(2)

    try:
        reg_code = int(rj.get("code", -999)) if isinstance(rj, dict) else -999
    except Exception:
        reg_code = -999
    print("[REG]", json.dumps(rj, ensure_ascii=False))

    # После регистра сразу пробуем login (даже если -1: у них иногда -1 при занятом логине)
    print("[INFO] Login...")
    try:
        lj = api.login(username=args.username, password=args.password, device_id=args.device_id)
    except Exception as e:
        print(f"[ERROR] Login error: {e}")
        sys.exit(3)

    lcode = int(lj.get("code", -999)) if isinstance(lj, dict) else -999
    uid = api.get_uid_from_login_response(lj) if isinstance(lj, dict) else None
    print("[LOGIN]", json.dumps(lj, ensure_ascii=False))

    summary = {
        "register_code": reg_code,
        "login_code": lcode,
        "uid": uid,
        "token_len": len(api.token or ""),
        "tcp_host": api.tcp_host,
        "tcp_port": api.tcp_port,
        "client_version": api.client_version,
        "proxy": bool(api.proxies),
    }
    print("[SUMMARY]", json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
