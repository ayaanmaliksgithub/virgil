# PyInstaller spec for the `virgil` CLI.
#
# Produces a single-file binary that bundles the Python runtime + every
# dependency, so end users can run `virgil` without installing Python or pipx.
# Built by `python build_binary.py` locally and by `.github/workflows/cli-binaries.yml`
# in CI for each supported platform.
#
# Hidden imports: PyInstaller's static analysis catches direct `import` statements,
# but several deps reach for modules at runtime — Rich loads renderers lazily, and
# requests pulls in `certifi` via urllib3. Listing them here makes the build
# reproducible across machines that may or may not have the modules already
# resolvable.
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hidden_imports = []
hidden_imports += collect_submodules("rich")
hidden_imports += collect_submodules("click")
hidden_imports += ["certifi"]

datas = []
# certifi ships its CA bundle as a data file; bundle it so HTTPS works in
# the frozen binary even on hosts whose system trust store PyInstaller
# can't reach.
datas += collect_data_files("certifi")


a = Analysis(
    ["cli/main.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # We never want to drag a GUI toolkit into the bundle.
        "tkinter",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="virgil",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
