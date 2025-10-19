from __future__ import annotations
import os
import sys
import json
import hashlib
import tempfile
import subprocess
import time
import logging
from pathlib import Path
from typing import Optional, Callable, Dict, Any

import requests
import shutil

log = logging.getLogger(__name__)
DEFAULT_MANIFEST_URL = "https://worryeed.github.io/ClubSender/latest.json"


def _semver_tuple(v: str) -> tuple:
    parts = (v or "0").strip().split(".")
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except Exception:
            num = ''.join(ch for ch in p if ch.isdigit())
            out.append(int(num or 0))
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def _find_powershell() -> Optional[str]:
    try:
        sysroot = os.environ.get('SystemRoot') or os.environ.get('WINDIR')
        candidates: list[str] = []
        if sysroot:
            candidates.append(str(Path(sysroot) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'))
        for name in ('powershell', 'pwsh'):
            exe_path = shutil.which(name)
            if exe_path:
                candidates.append(exe_path)
        for c in candidates:
            if c and Path(c).exists():
                return c
    except Exception:
        pass
    return None

class UpdateManager:
    """Кастомный менеджер обновлений (манифест latest.json на gh-pages).

    Формат манифеста:
    {
      "version": "1.0.x",
      "notes": "...",
      "assets": { "windows": { "url": "https://.../ClubSender.exe", "sha256": "<hex>" } }
    }
    """

    def __init__(self, current_version: str, manifest_url: str = DEFAULT_MANIFEST_URL):
        self.current_version = str(current_version)
        self.manifest_url = manifest_url
        self._update_info: Optional[Dict[str, Any]] = None
        self._downloaded_path: Optional[Path] = None

    def _fetch_manifest(self) -> Optional[Dict[str, Any]]:
        try:
            log.info(f"[update] Fetch manifest: {self.manifest_url}")
            r = requests.get(self.manifest_url, timeout=10)
            r.raise_for_status()
            m = r.json()
            log.info(f"[update] Manifest received: keys={list(m.keys())}")
            return m
        except Exception as e:
            log.error(f"[update] Manifest fetch failed: {e}")
            return None

    def _select_asset(self, manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        version = manifest.get("version") or manifest.get("current")
        if not version:
            return None
        asset = (manifest.get("assets") or {}).get("windows")
        if asset is None and manifest.get("download_url"):
            asset = {"url": manifest.get("download_url"), "sha256": manifest.get("sha256")}
        if not asset or not asset.get("url"):
            return None
        return {"version": version, "url": asset["url"], "sha256": asset.get("sha256"), "notes": manifest.get("notes", "")}

    def check_for_update(self) -> Optional[Dict[str, Any]]:
        m = self._fetch_manifest()
        if not m:
            return None
        sel = self._select_asset(m)
        if not sel:
            log.warning("[update] No suitable asset in manifest")
            return None
        cur = _semver_tuple(self.current_version)
        lat = _semver_tuple(sel["version"])
        log.info(f"[update] Current={self.current_version} Latest={sel['version']} -> need_update={lat>cur}")
        if lat > cur:
            self._update_info = sel
            return sel
        return None

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def download(self, progress_cb: Optional[Callable[[int], None]] = None) -> bool:
        if not self._update_info:
            return False
        url = self._update_info["url"]
        try:
            log.info(f"[update] Download start: {url}")
            with requests.get(url, stream=True, timeout=30) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length", 0))
                fd, tmp = tempfile.mkstemp(prefix="clubsender_update_", suffix=".bin")
                os.close(fd)
                p = Path(tmp)
                downloaded = 0
                with open(p, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_cb and total > 0:
                            pct = max(0, min(100, int(downloaded * 100 / total)))
                            progress_cb(pct)
                expect = (self._update_info.get("sha256") or "").lower().strip()
                if expect:
                    actual = self._sha256(p)
                    log.info(f"[update] SHA256 actual={actual} expect={expect}")
                    if actual.lower() != expect:
                        try:
                            p.unlink(missing_ok=True)
                        except Exception:
                            pass
                        log.error("[update] Hash mismatch, abort")
                        return False
                self._downloaded_path = p
                log.info(f"[update] Download complete: {p}")
                return True
        except Exception as e:
            log.error(f"[update] Download failed: {e}")
            return False

    def install(self) -> bool:
        if not self._downloaded_path:
            return False
        if sys.platform.startswith("win"):
            return self._install_windows(self._downloaded_path)
        try:
            subprocess.Popen([str(self._downloaded_path)])
            return True
        except Exception as e:
            log.error(f"[update] Install (non-Windows) failed: {e}")
            return False

    def _install_windows(self, new_file: Path) -> bool:
        exe = Path(sys.executable)
        if getattr(sys, "frozen", False) and exe.suffix.lower() == ".exe":
            try:
                tmp_ps1 = Path(tempfile.gettempdir()) / f"clubsender_update_{int(time.time())}.ps1"
                ps_script = (
                    "param([string]$New,[string]$Target,[int]$ProcId,[string]$LogDir)\r\n"
                    "$ErrorActionPreference='SilentlyContinue'\r\n"
                    "if(!(Test-Path -LiteralPath $LogDir)){New-Item -ItemType Directory -Force -Path $LogDir | Out-Null}\r\n"
                    "$Log = Join-Path $LogDir 'updater.log'\r\n"
                    "function Log($m){ Add-Content -Path $Log -Value (\"[{0}] {1}\" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $m) }\r\n"
                    "Log (\"Start. NEW=\"\"{0}\"\" TARGET=\"\"{1}\"\" PID={2}\" -f $New,$Target,$ProcId)\r\n"
                    "if($ProcId -gt 0){ try{ Wait-Process -Id $ProcId -ErrorAction SilentlyContinue } catch{ Log (\"Wait-Process error: \" + $_) } }\r\n"
                    "Log 'Replacing target...'\r\n"
                    "$ok=$false; for($i=0;$i -lt 120 -and -not $ok;$i++){ try{ Copy-Item -Force -LiteralPath $New -Destination $Target; $ok=$true } catch{ Start-Sleep -Milliseconds 500 } }\r\n"
                    "if(-not $ok){ Log 'Copy failed after retries' }\r\n"
                    "$wd = Split-Path -Parent $Target\r\n"
                    "Log 'Starting new binary (primary)...'\r\n"
                    "$proc = $null\r\n"
                    "try{ $proc = Start-Process -FilePath $Target -WorkingDirectory $wd -WindowStyle Hidden -PassThru } catch { Log (\"Start-Process error: \" + $_) }\r\n"
                    "Start-Sleep -Milliseconds 400\r\n"
                    "$started = $false\r\n"
                    "if($proc -and $proc.Id){ try{ if(Get-Process -Id $proc.Id -ErrorAction SilentlyContinue){ $started = $true } } catch {} }\r\n"
                    "if(-not $started){\r\n"
                    "  Log 'Primary start not confirmed, trying fallback via cmd /c start'\r\n"
                    "  try{ Start-Process -FilePath cmd.exe -ArgumentList @('/c','start','\"\"',$Target) -WorkingDirectory $wd -WindowStyle Hidden | Out-Null; $started=$true } catch { Log (\"Fallback start error: \" + $_) }\r\n"
                    "}\r\n"
                    "Log ('Done. started={0}' -f $started)\r\n"
                    "try{ Remove-Item -LiteralPath $New -Force } catch{}\r\n"
                    "try{ Remove-Item -LiteralPath $PSCommandPath -Force } catch{}\r\n"
                )
                tmp_ps1.write_text(ps_script, encoding="utf-8")
                log.info(f"[update] Updater script: {tmp_ps1}")
                flags = 0
                for _f in ('CREATE_NO_WINDOW', 'DETACHED_PROCESS', 'CREATE_NEW_PROCESS_GROUP', 'CREATE_BREAKAWAY_FROM_JOB'):
                    flags |= getattr(subprocess, _f, 0)
                pid = os.getpid()
                log_dir = exe.parent / "logs"
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                ps = _find_powershell()
                if not ps:
                    log.error("[update] Cannot locate PowerShell executable")
                    return False
                cmd = [
                    ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmp_ps1),
                    "-New", str(new_file), "-Target", str(exe), "-ProcId", str(pid), "-LogDir", str(log_dir)
                ]
                log.info(f"[update] Launching updater: {' '.join(map(str, cmd))}")
                si = None
                try:
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 0)
                    si.wShowWindow = 0
                except Exception:
                    si = None
                try:
                    subprocess.Popen(cmd, creationflags=flags, cwd=str(exe.parent), startupinfo=si, close_fds=True)
                except Exception as e:
                    log.error(f"[update] Popen failed: {e}")
                    return False
                return True
            except Exception as e:
                log.error(f"[update] Install (Windows) failed: {e}")
                return False
        try:
            subprocess.Popen([str(new_file)])
            return True
        except Exception as e:
            log.error(f"[update] Install (non-frozen) failed: {e}")
            return False
