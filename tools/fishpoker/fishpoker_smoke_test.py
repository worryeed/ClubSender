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
from common import (
    FishPokerHTTP,
    FishPokerTCPClient,
    CLIENT_VER_HINT,
    gen_random_imei,
    md5_hex,
    double_md5,
)


def _sanitize_nick(s: str) -> str:
    s = "".join(ch for ch in (s or "") if ch.isalnum())
    if len(s) > 20:
        s = s[:20]
    while len(s) < 4:
        s += "0"
    if len(s) > 20:
        s = s[:20]
    return s

def main() -> None:
    p = argparse.ArgumentParser(description="FishPoker smoke test: HTTP reg/login + TCP login + nick/avatar + club check")
    p.add_argument("--base-url", default="https://wwb.fishpoker.net")
    p.add_argument("--proxy", default=None)
    p.add_argument("--imei", default="")

    p.add_argument("--username", default="", help="if empty -> auto-generate and register")
    p.add_argument("--password", default="", help="plain password (will MD5)")
    p.add_argument("--skip-register", action="store_true", help="do not call register.php (login only)")

    p.add_argument("--avatar", default="", help="path to image for icon_up.php (optional)")
    p.add_argument("--nick", default="", help="nickname to set via TCP (optional)")

    p.add_argument(
        "--club-id",
        type=int,
        action="append",
        default=[],
        help="club id to check via pb.ClubBriefInfoREQ (can be repeated)",
    )
    p.add_argument("--join", action="store_true", help="also send pb.JoinClubREQ if club exists")

    p.add_argument("--country", default="CN")
    p.add_argument("--region", type=int, default=2)
    p.add_argument("--os", default="windows")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--tcp-timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=10, help="auto-reg retries if username is taken")

    args = p.parse_args()

    cg = CredGenerator()

    imei = (args.imei or "").strip() or gen_random_imei()

    http = FishPokerHTTP(base_url=args.base_url, proxy=args.proxy, timeout=args.timeout)

    # Step 1: version
    print(f"[INFO] IMEI/openUid={imei}")
    print("[STEP] HTTP version.php")
    vj = http.fetch_version(imei=imei, ver_hint=CLIENT_VER_HINT, region=args.region, os_name=args.os)
    print(f"[OK] client_version={http.client_version} client_ip={http.client_ip or ''}")

    # Step 2: register (optional) + login
    username = (args.username or "").strip()
    password = (args.password or "").strip()

    reg_json = None
    if not args.skip_register:
        for attempt in range(1, max(1, int(args.retries)) + 1):
            if not username or not password:
                _nick, username, password = cg.generate_triplet()
                username = username[:20]
                if len(username) < 6:
                    username = (username + "123456")[:6]

            pwd_md5 = double_md5(password)
            print(f"[STEP] HTTP register.php attempt={attempt} username={username}")
            reg_json = http.register(
                username=username,
                password_md5=pwd_md5,
                imei=imei,
                clientvar=http.client_version,
                country=args.country,
                region=args.region,
                os_name=args.os,
            )
            code = int(reg_json.get("code", -999)) if isinstance(reg_json, dict) else -999
            print(f"[REG] code={code}")
            if code == 0:
                break
            if code == -1:
                # username taken
                username = ""
                password = ""
                continue
            break
    else:
        if not username or not password:
            raise SystemExit("--skip-register требует --username и --password")

    print("[STEP] HTTP login.php")
    pwd_md5 = double_md5(password)
    login_json = http.login(
        username=username,
        password_md5=pwd_md5,
        imei=imei,
        clientvar=http.client_version,
        country=args.country,
        region=args.region,
        os_name=args.os,
    )
    lcode = int(login_json.get("code", -999)) if isinstance(login_json, dict) else -999
    if lcode != 0 or not http.uid or not http.rdkey:
        print("[FAIL] HTTP login failed")
        print(json.dumps(login_json, ensure_ascii=False))
        raise SystemExit(2)
    uid = int(http.uid)
    rdkey = str(http.rdkey)
    print(f"[OK] HTTP login uid={uid} rdkey_len={len(rdkey)} tcp_eps={http.tcp_endpoints}")

    # Step 3: TCP login
    tcp_eps = http.tcp_endpoints
    if not tcp_eps:
        raise SystemExit("No TCP endpoints in HTTP login response")

    last_err = None
    tcp = None
    for host, port in tcp_eps:
        try:
            print(f"[STEP] TCP connect {host}:{port}")
            tcp = FishPokerTCPClient(host=host, port=port, timeout=args.tcp_timeout, proxy=args.proxy)
            tcp.clientver = http.client_version
            tcp.country = args.country
            tcp.connect()
            ok, msg = tcp.tcp_login(uid=uid, token=rdkey, clientip=http.client_ip or "", entry_host=host, entry_port=port)
            if not ok:
                raise OSError(f"tcp_login failed: {msg}")
            print("[OK] TCP login")
            break
        except Exception as e:
            last_err = e
            try:
                if tcp:
                    tcp.close()
            except Exception:
                pass
            tcp = None
            continue

    if not tcp:
        raise SystemExit(f"TCP connect/login failed: {last_err}")

    # Step 4: warmup burst (send-only)
    print("[STEP] TCP warmup bursts")
    try:
        tcp.send_post_login_bursts(uid=uid)
        print("[OK] warmup sent")
    except Exception as e:
        print(f"[WARN] warmup failed: {e}")

    # Optional heartbeat during the rest of steps
    try:
        tcp.start_heartbeat(interval=3.0)
    except Exception:
        pass

    # Step 5: rename cost + change nick
    print("[STEP] TCP rename cost")
    cost = None
    try:
        cost = tcp.rename_cost()
        print(f"[OK] rename_cost={cost}")
    except Exception as e:
        print(f"[WARN] rename_cost failed: {e}")

    if args.nick:
        new_nick = _sanitize_nick(args.nick)
    else:
        new_nick = _sanitize_nick(cg.derive_nick(username, min_len=6, max_len=20))

    print(f"[STEP] TCP change nickname -> {new_nick}")
    nick_ok = False
    nick_rsp = ""
    try:
        nick_ok, nick_rsp = tcp.change_username(nickname=new_nick)
        print(f"[{'OK' if nick_ok else 'FAIL'}] ChangeUserNameRSP: {nick_rsp}")
    except Exception as e:
        print(f"[FAIL] change_username error: {e}")

    # Step 6: upload avatar (HTTP)
    icon_url = None
    if args.avatar:
        if os.path.exists(args.avatar):
            print(f"[STEP] HTTP upload avatar: {args.avatar}")
            try:
                icon_url = http.upload_avatar(uid=uid, rdkey=rdkey, image_path=args.avatar)
                if icon_url:
                    print(f"[OK] avatar icon_url={icon_url}")
                else:
                    print("[FAIL] avatar upload returned no url")
            except Exception as e:
                print(f"[FAIL] avatar upload error: {e}")
        else:
            print("[WARN] avatar path does not exist; skip")

    # Step 7: club check (+ optional join)
    club_checks: list[dict] = []
    if args.club_id:
        for cid_raw in args.club_id:
            try:
                cid = int(cid_raw)
            except Exception:
                continue
            if cid <= 0:
                continue
            print(f"[STEP] TCP club check club_id={cid}")
            entry = {"club_id": cid, "exists": None, "join_ok": None, "join_msg": None}
            try:
                exists, _info = tcp.get_club_brief_info(club_id=cid)
                entry["exists"] = bool(exists)
                print(f"[OK] club_id={cid} exists={entry['exists']}")
                if args.join and entry["exists"]:
                    remark = f"Я fp{uid}"
                    print(f"[STEP] TCP join club_id={cid} remark='{remark}'")
                    okj, msgj = tcp.join_club(club_id=cid, remark=remark, apply_source=0)
                    entry["join_ok"] = bool(okj)
                    entry["join_msg"] = msgj
                    print(f"[{'OK' if okj else 'FAIL'}] join: {msgj}")
            except Exception as e:
                print(f"[FAIL] club check/join error club_id={cid}: {e}")
            club_checks.append(entry)

    # Close TCP
    try:
        tcp.close()
    except Exception:
        pass

    summary = {
        "username": username,
        "password": password,
        "password_md5": double_md5(password),
        "imei": imei,
        "client_version": http.client_version,
        "client_ip": http.client_ip,
        "uid": uid,
        "rdkey_len": len(rdkey),
        "tcp_endpoints": http.tcp_endpoints,
        "rename_cost": cost,
        "nick": new_nick,
        "nick_ok": nick_ok,
        "icon_url": icon_url,
        "club_ids": [int(x) for x in (args.club_id or []) if str(x).isdigit()],
        "club_checks": club_checks,
    }
    print("[SUMMARY]", json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
