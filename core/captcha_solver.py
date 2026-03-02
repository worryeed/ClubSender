"""
Captcha solver for X-Poker registration captchas.

Uses ddddocr (free local OCR) — works well for simple alphanumeric captchas.
Install: pip install ddddocr==1.5.5
"""
from __future__ import annotations

import base64
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class CaptchaSolveError(Exception):
    """Raised when captcha solving fails."""
    pass


# Singleton OCR instance (heavy to create, reuse across calls)
_ocr_instance = None


def _get_ocr():
    """Get or create the ddddocr OCR instance (singleton)."""
    global _ocr_instance
    if _ocr_instance is not None:
        return _ocr_instance
    try:
        import ddddocr
    except ImportError:
        raise CaptchaSolveError(
            "ddddocr не установлен. Выполните: pip install ddddocr==1.5.5"
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
