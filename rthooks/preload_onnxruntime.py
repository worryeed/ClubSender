# PyInstaller runtime hook: preload onnxruntime early.
#
# Motivation:
# When PyQt6 is bundled, PyInstaller's runtime hook for Qt adds Qt6\bin (and other dirs)
# to DLL search paths. On Windows, this can cause onnxruntime's native extension to fail
# with:
#   ImportError: DLL load failed while importing onnxruntime_pybind11_state
#
# Preloading onnxruntime BEFORE the Qt runtime hook runs ensures onnxruntime and its
# dependencies are loaded first, avoiding the conflict.

import os
import sys


def _try_add_dll_dir() -> None:
    if sys.platform != "win32":
        return
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return
    capi = os.path.join(meipass, "onnxruntime", "capi")
    try:
        if os.path.isdir(capi):
            os.add_dll_directory(capi)
    except Exception:
        pass


_try_add_dll_dir()

try:
    import onnxruntime  # noqa: F401
except Exception:
    # Keep silent; application code will surface errors if OCR/captcha is used.
    pass
