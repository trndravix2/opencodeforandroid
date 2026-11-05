#!/usr/bin/env python3
"""
Encrypt the Dravix Android runtime assets with AES-256-CTR.

The APK ships only *.enc blobs. The decryption key is never stored in the APK:
the panel returns it wrapped with RSA-OAEP to the device's hardware Keystore
key, inside a 5 minute signed lease.

Container: b"DRVX2" + 16-byte IV + AES-CTR ciphertext

Usage:
  python tools/encrypt_assets.py [--key-file tools/asset_key.txt] [--force]

Key resolution order:
  1. --key-file
  2. env DRAVIX_ASSET_KEY (base64)
  3. tools/asset_key.txt
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "app" / "src" / "main" / "assets"
MAGIC = b"DRVX2"
CHUNK = 8 * 1024 * 1024
TARGETS = [
    "opencode-aarch64",
    "opencode-x86_64",
    "rootfs-aarch64.bin",
    "rootfs-x86_64.bin",
]


def load_key(args) -> bytes:
    raw = ""
    if args.key_file:
        raw = Path(args.key_file).read_text(encoding="ascii").strip()
    if not raw:
        raw = os.environ.get("DRAVIX_ASSET_KEY", "").strip()
    if not raw:
        fallback = ROOT / "tools" / "asset_key.txt"
        if fallback.exists():
            raw = fallback.read_text(encoding="ascii").strip()
    if not raw:
        sys.exit("No asset key. Pass --key-file or set DRAVIX_ASSET_KEY.")
    key = base64.b64decode(raw, validate=True)
    if len(key) != 32:
        sys.exit("Asset key must be 32 bytes (base64 encoded).")
    return key


def encrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    plain_hash = hashlib.sha256()
    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(MAGIC)
        fout.write(iv)
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            plain_hash.update(chunk)
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
    enc_hash = hashlib.sha256()
    with dst.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            enc_hash.update(chunk)
    return {
        "source": src.name,
        "encrypted": dst.name,
        "plain_size": src.stat().st_size,
        "enc_size": dst.stat().st_size,
        "plain_sha256": plain_hash.hexdigest(),
        "enc_sha256": enc_hash.hexdigest(),
    }


def verify_file(enc: Path, key: bytes, expected_sha: str) -> None:
    size = enc.stat().st_size
    with enc.open("rb") as f:
        header = f.read(5 + 16)
        if header[:5] != MAGIC:
            sys.exit(f"{enc.name}: bad magic")
        iv = header[5:]
        ciphertext_len = size - len(header)
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        digest = hashlib.sha256()
        remaining = ciphertext_len
        while remaining > 0:
            chunk = f.read(min(CHUNK, remaining))
            if not chunk:
                sys.exit(f"{enc.name}: truncated ciphertext")
            remaining -= len(chunk)
            digest.update(decryptor.update(chunk))
        decryptor.finalize()
        if digest.hexdigest() != expected_sha:
            sys.exit(f"{enc.name}: plaintext hash mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    key = load_key(args)

    manifest = []
    for name in TARGETS:
        src = ASSETS / name
        dst = ASSETS / (name + ".enc")
        if not src.exists():
            print(f"skip (missing): {name}")
            continue
        if dst.exists() and not args.force:
            print(f"skip (exists): {dst.name}")
            continue
        print(f"encrypting {name} ...")
        info = encrypt_file(src, dst, key)
        verify_file(dst, key, info["plain_sha256"])
        print(f"  ok  {info['plain_size']} -> {info['enc_size']} bytes")
        manifest.append(info)

    manifest_path = ROOT / "tools" / "asset_manifest.json"
    if manifest:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"manifest: {manifest_path}")


if __name__ == "__main__":
    main()
