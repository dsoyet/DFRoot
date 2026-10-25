#!/usr/bin/env python3
"""Fetch only pinned upstream release payloads. No device data is uploaded."""
import hashlib
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[1]
dest = root / 'app/src/main/assets/violin'
dest.mkdir(parents=True, exist_ok=True)
files = {
    'kernelsu310.ko': ('android15-6.6_kernelsu.ko', '48afa2e0c7ce6b310bd2885c99e0a3276672f3c7fa2f597a011610fd9c989fb3'),
    'ksud310': ('ksud-aarch64-linux-android', '3c4da894bf2f0a09b5e666d1bb52ab346225e804260713f9fa635c4b52867b46'),
}
for local, (upstream, expected) in files.items():
    data = urllib.request.urlopen('https://github.com/tiann/KernelSU/releases/download/v3.1.0/' + upstream, timeout=120).read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit(f'SHA256 mismatch for {upstream}: {actual}')
    (dest / local).write_bytes(data)
    print(local, actual)
