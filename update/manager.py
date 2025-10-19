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
            # strip non-digits like '1.0.0-beta'
            num = ''.join(ch for ch in p if ch.isdigit())
            out.append(int(num or 0))
    # normalize length
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def _find_powershell() -> Optional[str]:
    """Prefer 64-bit PowerShell via Sysnative to avoid WOW64 redirection."""
    try:
        windir = os.environ.get('WINDIR') or os.environ.get('SystemRoot')
        candidates: list[str] = []
        if windir:
            # Sysnative resolves to 64-bit System32 from 32-bit contexts
            candidates.append(str(Path(windir) / 'Sysnative' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'))
            candidates.append(str(Path(windir) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'))
        for name in ('powershell', 'pwsh'):
            exe_path = shutil.which(name)
            if exe_path:
                candidates.append(exe_path)
        for c in candidates:
            try:
                if c and Path(c).exists():
                    return c
            except Exception:
                continue
    except Exception:
        pass
    return None

class UpdateManager:
    """Простой менеджер обновлений без PyUpdater.

    Ожидаемый формат манифеста (gh-pages/latest.json):
    {
      "version": "1.0.1",
      "notes": "...",
      "assets": {
        "windows": {
          "url": "https://.../ClubSender-1.0.1.exe",
          "sha256": "<hex>"
        }
      }
    }
    Поля-совместимости: допускается {"current": "1.0.1"} или {"download_url": "..."}.
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
        # Version field: prefer 'version', fallback to 'current'
        version = manifest.get("version") or manifest.get("current")
        if not version:
            return None
        asset = None
        assets = manifest.get("assets") or {}
        if sys.platform.startswith("win"):
            asset = assets.get("windows") or assets.get("win32") or assets.get("win")
        # Fallbacks for simple manifests
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
                # verify sha256 if provided
                expect = (self._update_info.get("sha256") or "").lower().strip()
                if expect:
                    actual = self._sha256(p)
                    log.info(f"[update] SHA256 actual={actual} expect={expect}")
                    if actual.lower() != expect:
                        try:
                            p.unlink(missing_ok=True)  # type: ignore[arg-type]
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
        # Windows onefile update strategy
        if sys.platform.startswith("win"):
            return self._install_windows(self._downloaded_path)
        # For other platforms, attempt to launch downloaded file
        try:
            subprocess.Popen([str(self._downloaded_path)])
            return True
        except Exception:
            return False

    def _install_windows(self, new_file: Path) -> bool:
        exe = Path(sys.executable)
        # If running from PyInstaller onefile
        if getattr(sys, "frozen", False) and exe.suffix.lower() == ".exe":
            try:
                tmp_ps1 = Path(tempfile.gettempdir()) / f"clubsender_update_{int(time.time())}.ps1"
                ps_script = (
                    "param([string]$New,[string]$Target,[string]$LogDir)\r\n"
                    "$ErrorActionPreference='SilentlyContinue'\r\n"
                    "if(!(Test-Path -LiteralPath $LogDir)){New-Item -ItemType Directory -Force -Path $LogDir | Out-Null}\r\n"
                    "$Log = Join-Path $LogDir 'updater.log'\r\n"
                    "function Log($m){ Add-Content -Path $Log -Value (\"[{0}] {1}\" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $m) }\r\n"
                    "Log (\"Start. NEW=\"\"{0}\"\" TARGET=\"\"{1}\"\"\" -f $New,$Target)\r\n"
                    "Log 'Replacing target...'\r\n"
                    "$ok=$false; for($i=0;$i -lt 240 -and -not $ok;$i++){ try{ Copy-Item -Force -LiteralPath $New -Destination $Target; $ok=$true } catch{ Start-Sleep -Milliseconds 500 } }\r\n"
                    "if(-not $ok){ Log 'Copy failed after retries' }\r\n"
                    "$wd = Split-Path -Parent $Target\r\n"
                    "Log 'Starting new binary (primary)...'\r\n"
                    "$proc = $null\r\n"
                    "try{ $proc = Start-Process -FilePath $Target -WorkingDirectory $wd -WindowStyle Hidden -PassThru } catch { Log (\"Start-Process error: \" + $_) }\r\n"
                    "Start-Sleep -Milliseconds 500\r\n"
                    "Log ('Done. started_pid={0}' -f ($proc.Id))\r\n"
                    "try{ Remove-Item -LiteralPath $New -Force } catch{}\r\n"
                    "try{ Remove-Item -LiteralPath $PSCommandPath -Force } catch{}\r\n"
                )
                tmp_ps1.write_text(ps_script, encoding="utf-8")
                log.info(f"[update] Updater script: {tmp_ps1}")
                # Launch PowerShell updater hidden
                creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) | getattr(subprocess, 'DETACHED_PROCESS', 0)
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
                # Build PowerShell command (used as fallback)
                cmd = [
                    ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmp_ps1),
                    "-New", str(new_file), "-Target", str(exe), "-LogDir", str(log_dir)
                ]
                log.info(f"[update] Prepared updater cmd: {' '.join(map(str, cmd))}")
                # Prepare .bat updater (primary for scheduling)
                # Write updater .bat to temp to avoid clutter near exe
                bat_path = Path(tempfile.gettempdir()) / "clubsender_update.bat"
                bat_content = (
                    "@echo off\r\n"
                    "setlocal enableextensions\r\n"
                    "set NEW=%~1\r\n"
                    "set TARGET=%~2\r\n"
                    "set WD=%~dp2\r\n"
                    ":waitloop\r\n"
                    "timeout /t 1 /nobreak >nul\r\n"
                    "(del /f /q \"%TARGET%\") >nul 2>&1\r\n"
                    "if exist \"%TARGET%\" goto waitloop\r\n"
                    "move /y \"%NEW%\" \"%TARGET%\" >nul 2>&1\r\n"
                    "start \"\" /D \"%WD%\" \"%TARGET%\"\r\n"
                    "start \"\" cmd /c del /f /q \"%~f0\"\r\n"
                    "endlocal\r\n"
                    "exit\r\n"
                )
                try:
                    bat_path.write_text(bat_content, encoding="utf-8")
                except Exception:
                    bat_path = Path(tempfile.gettempdir()) / f"clubsender_update_{int(time.time())}.bat"
                    bat_path.write_text(bat_content, encoding="utf-8")
                # Primary: schedule .bat outside job (interactive)
                try:
                    import datetime, getpass
                    task_name = f"ClubSenderUpdate_{os.getpid()}"
                    run_time = (datetime.datetime.now() + datetime.timedelta(seconds=30)).strftime("%H:%M")
                    tr = f'"{bat_path}" "{new_file}" "{exe}"'
                    log.info(f"[update] Scheduling task {task_name} at {run_time} -> {tr}")
                    # Try interactive run for current user; on failure, fallback below
                    ru = os.environ.get('USERNAME') or getpass.getuser()
                    create_cmd = ['schtasks', '/Create', '/SC', 'ONCE', '/ST', run_time, '/TN', task_name, '/TR', tr, '/F', '/RL', 'HIGHEST', '/RU', ru, '/IT']
                    try:
                        subprocess.check_call(create_cmd)
                    except Exception as e_create:
                        log.error(f"[update] schtasks /Create (interactive) failed: {e_create}; retry without /IT and /RU")
                        subprocess.check_call(['schtasks', '/Create', '/SC', 'ONCE', '/ST', run_time, '/TN', task_name, '/TR', tr, '/F'])
                    subprocess.check_call(['schtasks', '/Run', '/TN', task_name])
                    return True
                except Exception as e_task:
                    log.error(f"[update] schtasks primary failed: {e_task}; trying PowerShell direct")
                # Fallback 1: direct PowerShell spawn
                try:
                    flags = 0
                    for _f in ('DETACHED_PROCESS', 'CREATE_NEW_PROCESS_GROUP', 'CREATE_BREAKAWAY_FROM_JOB'):
                        flags |= getattr(subprocess, _f, 0)
                    show_console = (os.environ.get('XP_UPDATER_DEBUG','').strip().lower() in ('1','true','yes'))
                    if not show_console:
                        flags |= getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                    else:
                        flags |= getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
                    si = None
                    try:
                        si = subprocess.STARTUPINFO()
                        if not show_console:
                            si.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 0)
                            si.wShowWindow = 0
                    except Exception:
                        si = None
                    env = os.environ.copy()
                    for k in ('PYTHONHOME','PYTHONPATH','PYTHONUSERBASE','PYTHONNOUSERSITE','PYTHONEXECUTABLE','_MEIPASS','_MEIPASS2'):
                        env.pop(k, None)
                    p = subprocess.Popen(cmd, creationflags=flags, cwd=str(exe.parent), startupinfo=si, close_fds=True, env=env)
                    log.info(f"[update] Direct PowerShell spawn OK (pid={getattr(p, 'pid', '?')})")
                    return True
                except Exception as e:
                    log.error(f"[update] PowerShell direct failed: {e}; trying cmd /c start .bat")
                # Fallback 2: cmd /c start .bat
                try:
                    start_cmd = [os.environ.get('COMSPEC','cmd'), '/c', 'start', '""', str(bat_path), str(new_file), str(exe)]
                    log.info(f"[update] .bat fallback launch: {' '.join(map(str, start_cmd))}")
                    subprocess.Popen(start_cmd, cwd=str(exe.parent))
                    return True
                except Exception as e_bat:
                    log.error(f"[update] .bat start failed: {e_bat}")
                    return False
            except Exception as e:
                log.error(f"[update] Install (Windows) failed: {e}")
                return False
        # Not frozen: just launch the downloaded binary/installer
        try:
            subprocess.Popen([str(new_file)])
            return True
        except Exception as e:
            log.error(f"[update] Install (non-frozen) failed: {e}")
            return False
