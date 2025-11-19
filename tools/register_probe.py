#!/usr/bin/env python3
from __future__ import annotations
import argparse
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional

# Reuse project modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.api import XPokerAPI, ApiError, mask_proxy_for_log  # type: ignore
from core.credgen import CredGenerator  # type: ignore


def load_proxies(args) -> List[str]:
    proxies: List[str] = []
    if args.proxies_file:
        p = Path(args.proxies_file)
        if p.exists():
            proxies += [line.strip() for line in p.read_text(encoding='utf-8', errors='ignore').splitlines() if line.strip()]
    if args.proxy:
        for item in args.proxy:
            for seg in str(item).split(','):
                seg = seg.strip()
                if seg:
                    proxies.append(seg)
    # de-dup, keep order
    seen = set()
    out: List[str] = []
    for p in proxies:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe XPoker register endpoint via proxies")
    ap.add_argument('--count', type=int, default=10, help='Number of registrations to attempt (default: 10)')
    ap.add_argument('--proxies-file', type=str, default=None, help='Path to file with proxies (one per line)')
    ap.add_argument('--proxy', action='append', help='Proxy value(s). Can repeat flag or comma-separate.')
    ap.add_argument('--delay-ms', type=int, default=300, help='Sleep between attempts (ms)')
    args = ap.parse_args()

    proxies = load_proxies(args)
    gen = CredGenerator()

    # Prepare CSV
    logs_dir = Path('logs'); logs_dir.mkdir(parents=True, exist_ok=True)
    csv_path = logs_dir / 'registrations_probe.csv'
    need_header = not csv_path.exists() or csv_path.stat().st_size == 0
    import csv, datetime
    f = csv_path.open('a', encoding='utf-8', newline='')
    w = csv.writer(f)
    if need_header:
        w.writerow(['ts','proxy','username','password','nick','device_id','code','msg','uid'])

    def pick_proxy(i: int) -> Optional[str]:
        if not proxies:
            return None
        return proxies[i % len(proxies)]

    total = max(1, int(args.count))
    for i in range(total):
        username = gen.generate_login(min_len=6, max_len=30)
        nick = gen.derive_nick(username, min_len=6, max_len=20)
        password = gen.generate_password(min_len=6, max_len=16)
        device_id = str(uuid.uuid4())
        p = pick_proxy(i)
        api = XPokerAPI(proxy=p)
        masked = mask_proxy_for_log(p) if p else 'None'
        print(f"[{i+1}/{total}] REG via proxy={masked} user={username}")
        code = -1; msg = ''; uid = ''
        try:
            data = api.register(username=username, password=password, device_id=device_id)
            if isinstance(data, dict):
                code = int(data.get('code', -1))
                msg = str(data.get('msg',''))
                try:
                    uid = str(data.get('data',{}).get('auth',{}).get('uid','') or '')
                except Exception:
                    uid = ''
        except ApiError as e:
            msg = str(e)
        except Exception as e:
            msg = f"EXC: {e}"
        # Log to CSV
        try:
            w.writerow([datetime.datetime.now(datetime.UTC).isoformat(), masked, username, password, nick, device_id, code, msg, uid])
            f.flush()
        except Exception:
            pass
        # Print result
        if code == 0:
            print(f"  OK uid={uid}")
        else:
            print(f"  FAIL code={code} msg={msg}")
        time.sleep(max(0, int(args.delay_ms))/1000.0)

    try:
        f.close()
    except Exception:
        pass
    print(f"Done. CSV: {csv_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
