"""
Captcha solver for X-Poker registration captchas.

Uses ddddocr (free local OCR) — works well for simple alphanumeric captchas.
Install: pip install ddddocr==1.5.5
"""
from __future__ import annotations

import base64
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)


class CaptchaSolveError(Exception):
    """Raised when captcha solving fails."""
    pass


# Keep DLL directory handles alive (Windows / Python 3.8+)
_dll_dir_handles: list[object] = []


def _ensure_windows_dll_dirs():
    """Ensure bundled DLL directories are visible when running from PyInstaller.

    ddddocr -> onnxruntime loads native DLLs from onnxruntime/capi.
    In onefile builds, those DLLs live under sys._MEIPASS and may not be on DLL search path.
    """
    if sys.platform != "win32":
        return

    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return

    # Add onnxruntime/capi for native libs.
    cand_dirs = [
        os.path.join(meipass, "onnxruntime", "capi"),
    ]

    for d in cand_dirs:
        try:
            if os.path.isdir(d):
                # 1) Preferred: add directory to DLL search path
                try:
                    h = os.add_dll_directory(d)
                    _dll_dir_handles.append(h)
                    log.debug(f"[captcha] add_dll_directory: {d}")
                except Exception as e:
                    log.debug(f"[captcha] add_dll_directory failed for {d}: {e}")
                # 2) Fallback: extend PATH (helps some LoadLibrary paths)
                try:
                    cur = os.environ.get("PATH", "")
                    if d not in cur.split(";"):
                        os.environ["PATH"] = d + ";" + cur
                        log.debug(f"[captcha] PATH prepended: {d}")
                except Exception as e:
                    log.debug(f"[captcha] PATH update failed: {e}")
        except Exception as e:
            log.debug(f"[captcha] DLL dir setup error for {d}: {e}")
            continue


# Singleton OCR instance (heavy to create, reuse across calls)
_ocr_instance = None


def _get_ocr():
    """Get or create the ddddocr OCR instance (singleton)."""
    global _ocr_instance
    if _ocr_instance is not None:
        return _ocr_instance

    # PyInstaller(onefile) on Windows: ensure onnxruntime native DLLs can be found.
    _ensure_windows_dll_dirs()

    try:
        import ddddocr
    except Exception as e:
        raise CaptchaSolveError(
            f"ddddocr не удалось импортировать: {type(e).__name__}: {e}"
        )
    try:
        _ocr_instance = ddddocr.DdddOcr(show_ad=False)
    except Exception as e:
        raise CaptchaSolveError(f"Ошибка инициализации ddddocr: {e}")
    return _ocr_instance


def solve_captcha_b64(image_b64: str, *, save_debug: bool = False) -> str:
    """Solve a captcha from base64-encoded JPEG string.

    Args:
        image_b64: Base64-encoded image as returned by X-Poker /api/common/captcha/regCode.
        save_debug: If True, save the image to logs/last_captcha.jpg for debugging.

    Returns:
        Recognized captcha text (lowercase).

    Raises:
        CaptchaSolveError: If decoding or recognition fails.
    """
    # Decode base64 -> raw bytes
    try:
        image_bytes = base64.b64decode(image_b64)
    except Exception as e:
        raise CaptchaSolveError(f"Ошибка декодирования base64: {e}")

    log.debug(f"Captcha image: {len(image_bytes)} bytes")

    # Optionally save for debugging
    if save_debug:
        try:
            debug_path = Path("logs") / "last_captcha.jpg"
            debug_path.parent.mkdir(parents=True, exist_ok=True)
            debug_path.write_bytes(image_bytes)
            log.debug(f"Captcha image saved: {debug_path}")
        except Exception:
            pass

    # Recognize
    ocr = _get_ocr()
    try:
        result = ocr.classification(image_bytes)
    except Exception as e:
        raise CaptchaSolveError(f"ddddocr ошибка распознавания: {e}")

    if not result or not result.strip():
        raise CaptchaSolveError("ddddocr вернул пустой результат")

    text = result.strip()
    log.info(f"Captcha solved: '{text}' ({len(text)} chars)")
    return text
