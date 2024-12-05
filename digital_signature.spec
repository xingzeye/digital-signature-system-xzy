# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

# 确保路径正确
current_dir = os.path.dirname(os.path.abspath(SPEC))
resources_dir = os.path.join(current_dir, 'resources')
bg_image = os.path.join(current_dir, '1.jpg')

a = Analysis(
    ['数字签名系统.py'],
    pathex=[current_dir],
    binaries=[],
    datas=[
        (resources_dir, 'resources'),  # 使用完整路径
        (bg_image, '.'),              # 使用完整路径
        ('create_icon.py', '.')
    ],
    hiddenimports=[
        'PIL._tkinter_finder',
        'gmpy2',
        'gmssl',
        'Crypto.Hash',
        'Crypto.Cipher',
        'tkinter',
        'tkinter.ttk',
        'tkinter.font',
        'tkinter.scrolledtext'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='数字签名系统',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 改为False，这样就不会显示控制台窗口
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(resources_dir, 'signature.ico')
) 