#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys

# ensure repo root on sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ensure this directory (tools/fishpoker) on sys.path for importing common.py
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)

from core.credgen import CredGenerator
from common import FishPokerHTTP, gen_random_imei, md5_hex, double_md5, CLIENT_VER_HINT


def main() -> None:
    p = argparse.ArgumentParser(description="FishPoker HTTP probe: version -> register -> login")
    p.add_argument("--base-url", default="https://wwb.fishpoker.net")
    p.add_argument("--proxy", default=None, help="http(s)://user:pass@host:port or socks5h://... (auto-detect supported)")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.add_argument("--imei", default="", help="override MAC-like imei/openUid (e.g. 18-31-BF-E1-13-18)")
    p.add_argument("--country", default="CN")
    p.add_argument("--region", type=int, default=2)
    p.add_argument("--os", default="windows")
    p.add_argument("--retries", type=int, default=10, help="auto-reg retries if username is taken")
    args = p.parse_args()

    cg = CredGenerator()

    imei = (args.imei or "").strip() or gen_random_imei()

    api = FishPokerHTTP(base_url=args.base_url, proxy=args.proxy)

    print(f"[INFO] IMEI/openUid={imei}")

    print("[INFO] version.php ...")
    vj = api.fetch_version(imei=imei, ver_hint=CLIENT_VER_HINT, region=args.region, os_name=args.os)
    print("[VERSION]", json.dumps(vj, ensure_ascii=False))
    print(f"[INFO] server client_version={api.client_version} client_ip={api.client_ip or ''}")

    # credentials
    username = (args.username or "").strip()
    password = (args.password or "").strip()

    # register loop
    for attempt in range(1, max(1, int(args.retries)) + 1):
        if not username or not password:
            _nick, username, password = cg.generate_triplet()
            # FishPoker usernames seen as 6..20; keep safe
            username = username[:20]
            if len(username) < 6:
                username = (username + "123456")[:6]

        pwd_md5 = double_md5(password)

        print(f"[INFO] register.php (attempt {attempt}) username={username} pass_md5={pwd_md5}")
        rj = api.register(
            username=username,
            password_md5=pwd_md5,
            imei=imei,
            clientvar=api.client_version,
            country=args.country,
            region=args.region,
            os_name=args.os,
        )
        print("[REG]", json.dumps(rj, ensure_ascii=False))

        code = int(rj.get("code", -999)) if isinstance(rj, dict) else -999
        if code == 0:
            break

        # -1: username taken (per captures)
        if code == -1:
            username = ""
            password = ""
            continue

        # any other error: stop
        break

    print("[INFO] login.php ...")
    pwd_md5 = double_md5(password)
    lj = api.login(
        username=username,
        password_md5=pwd_md5,
        imei=imei,
        clientvar=api.client_version,
        country=args.country,
        region=args.region,
        os_name=args.os,
    )
    print("[LOGIN]", json.dumps(lj, ensure_ascii=False))

    lcode = int(lj.get("code", -999)) if isinstance(lj, dict) else -999
    summary = {
        "register_code": int(rj.get("code", -999)) if isinstance(rj, dict) else -999,
        "login_code": lcode,
        "username": username,
        "password": password,
        "password_md5": double_md5(password),
        "imei": imei,
        "client_version": api.client_version,
        "client_ip": api.client_ip,
        "uid": api.uid,
        "rdkey_len": len(api.rdkey or ""),
        "tcp_endpoints": api.tcp_endpoints,
        "proxy": bool(args.proxy),
    }
    print("[SUMMARY]", json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
