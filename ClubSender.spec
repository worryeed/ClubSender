# -*- mode: python ; coding: utf-8 -*-
import os
import importlib

# ---- ddddocr: bundle ONNX model files ----
_ddddocr_datas = []
try:
    import ddddocr as _ddd
    _ddd_dir = os.path.dirname(_ddd.__file__)
    for f in os.listdir(_ddd_dir):
        if f.endswith('.onnx'):
            _ddddocr_datas.append((os.path.join(_ddd_dir, f), 'ddddocr'))
except Exception:
    pass

# ---- onnxruntime: bundle native DLLs/PYDs as binaries ----
_ort_binaries = []
try:
    import onnxruntime as _ort
    _ort_dir = os.path.dirname(_ort.__file__)
    _capi = os.path.join(_ort_dir, 'capi')
    if os.path.isdir(_capi):
        for f in os.listdir(_capi):
            fp = os.path.join(_capi, f)
            if os.path.isfile(fp) and (f.endswith('.dll') or f.endswith('.pyd')):
                _ort_binaries.append((fp, 'onnxruntime/capi'))
except Exception:
    pass

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=_ort_binaries,
    datas=_ddddocr_datas,
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'ddddocr',
        'onnxruntime',
        'onnxruntime.capi',
        'onnxruntime.capi._pybind_state',
        'numpy',
        'PIL',
        'PIL.Image',
        'cv2',
        # FishPoker integration (dynamic imports in main.py)
        'fishpoker',
        'fishpoker.api',
        'fishpoker.client',
        'fishpoker.protocol',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[os.path.abspath(os.path.join('rthooks', 'preload_onnxruntime.py'))],
    # PyInstaller cannot freeze multiple Qt binding packages in one app.
    # Ensure only PyQt6 is collected.
    excludes=['PyQt5', 'PySide2', 'PySide6'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ClubSender',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
