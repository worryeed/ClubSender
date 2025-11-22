#!/usr/bin/env python3
from __future__ import annotations
import sys, os, json
import argparse
import mimetypes
import time
from typing import Optional

# ensure repo root on sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pppoker.api import PPPokerAPI, ApiError
from pppoker.client import PPPokerTCPClient


def upload_avatar(api: PPPokerAPI, uid: int, rdkey: str, image_path: str) -> Optional[str]:
    """Upload avatar via HTTP endpoint icon_up.php; returns icon URL on success.
    POST /poker/api/icon_up.php?rdkey=<rdkey>&uid=<uid>&type=user&clubid=0
    multipart/form-data: act=upload, submit=upload, icon=<file>
    """
    import requests
    url = f"https://www.pppoker.club/poker/api/icon_up.php"
    params = {
        "rdkey": rdkey,
        "uid": str(uid),
        "type": "user",
        "clubid": "0",
    }
    # Guess content-type from extension
    mt, _ = mimetypes.guess_type(image_path)
    if not mt:
        mt = "image/jpeg"
    fn = os.path.basename(image_path) or "icon.jpg"
    with open(image_path, "rb") as f:
        files = {
            "icon": (fn, f, mt),
        }
        data = {
            "act": "upload",
            "submit": "upload",
        }
        r = requests.post(url, params=params, data=data, files=files, timeout=30, proxies=api.proxies, verify=False)
    r.raise_for_status()
    try:
        j = r.json()
    except Exception:
        j = None
    if isinstance(j, dict) and int(j.get("code", -1)) == 0:
        return str(j.get("icon") or "")
    return None


def main():
    p = argparse.ArgumentParser(description="PPPoker: set avatar and nickname via HTTP+TCP")
    p.add_argument("--username", required=False, default="k1st0")
    p.add_argument("--password", required=False, default="qwe123qwe123")
    p.add_argument("--image", required=False, default=r"C:\\Users\\KISTO\\Desktop\\photo_2025-11-16_14-57-53.jpg")
    p.add_argument("--nick", required=False, default="NEWNIK")
    p.add_argument("--proxy", required=False, default=None)
    args = p.parse_args()

    api = PPPokerAPI(proxy=args.proxy)

    # Login (HTTP) to get uid/token and TCP entry
    print("[INFO] Login...")
    data = api.login(username=args.username, password=args.password)
    code = int(data.get("code", -1)) if isinstance(data, dict) else -1
    if code != 0 or not api.token:
        print(f"[ERROR] Login failed: code={code}")
        sys.exit(2)
    uid = api.get_uid_from_login_response(data)
    if not uid:
        print("[ERROR] No UID in login response")
        sys.exit(2)
    print(f"[OK] uid={uid} token=rdkey len={len(api.token or '')}")

    # Upload avatar once via HTTP
    icon_url = None
    img = args.image
    if img and os.path.exists(img):
        try:
            print(f"[INFO] Upload avatar: {img}")
            icon_url = upload_avatar(api, uid=int(uid), rdkey=api.token or "", image_path=img)
            if icon_url:
                print(f"[OK] Avatar uploaded: {icon_url}")
            else:
                print("[WARN] Avatar upload failed (no url in response)")
        except Exception as e:
            print(f"[WARN] Avatar upload error: {e}")
    else:
        print("[WARN] Image file not found; skip avatar upload")

    # TCP: login and change nickname
    host = api.tcp_host or "ali-entry.pppoker.club"
    port = int(api.tcp_port or 4000)
    tcp = PPPokerTCPClient(host=host, port=port, timeout=5.0, proxy=api.proxy_url)
    # set server-reported client version
    try:
        tcp.clientver = api.client_version
    except Exception:
        pass
    print(f"[INFO] TCP connect {host}:{port} clientver={getattr(tcp, 'clientver', '?')}")
    tcp.connect()
    ok, msg = tcp.tcp_login(uid=int(uid), token=api.token or "", clientip="", entry_host=host, entry_port=port)
    if not ok:
        print(f"[ERROR] TCP login failed: {msg}")
        sys.exit(3)
    print("[OK] TCP login")

    # Change nickname
    new_nick = args.nick
    # enforce 4..20 length like client
    if len(new_nick) < 4 or len(new_nick) > 20:
        print(f"[WARN] Nick '{new_nick}' length out of range; adjusting")
        new_nick = new_nick[:20].ljust(4, '_')
    print(f"[INFO] Change nick -> '{new_nick}'")
    okn, nick_rsp = tcp.change_username(nickname=new_nick)
    print(f"[{'OK' if okn else 'FAIL'}] ChangeUserNameRSP: {nick_rsp}")

    tcp.close()

    # Summary
    print(json.dumps({
        "uid": uid,
        "avatar_url": icon_url,
        "nick_ok": okn,
        "nick": new_nick,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
