#!/usr/bin/env python3
"""Local mock panel used only for end-to-end smoke tests on an emulator."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

ROOT = Path(__file__).resolve().parent
ASSET_KEY = base64.b64decode((ROOT / "asset_key.txt").read_text().strip())
DEVICES = {}
NONCES = set()
JWT_SECRET = b"local-mock-secret"
USER = {"id": 1, "username": "tester"}


def pem_to_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def b64_der_to_pem(b64: str) -> str:
    der = base64.b64decode(b64)
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + base64.encodebytes(der).decode().strip()
        + "\n-----END PUBLIC KEY-----\n"
    )


def make_token() -> str:
    header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(
        json.dumps({"uid": 1, "user": "tester", "exp": int(time.time()) + 86400}).encode()
    ).decode()
    sig = hmac.new(JWT_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{sig}"


def access_payload():
    return {
        "can_enter": True,
        "access_type": "paid",
        "plan": "pro",
        "paid_active": True,
        "user": USER,
        "token_expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400)),
    }


def issue_lease(wrap_pub_pem: str):
    expires = int(time.time()) + 300
    wrapped = pem_to_public(wrap_pub_pem).encrypt(
        ASSET_KEY,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    return {
        "can_enter": True,
        "lease": base64.b64encode(secrets.token_bytes(48)).decode(),
        "lease_expires_at": expires,
        "lease_ttl": 300,
        "asset_key": base64.b64encode(wrapped).decode(),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[mock] {fmt % args}", flush=True)

    def send_json(self, data, code=200):
        body = json.dumps({"status": "success", "message": "ok", "data": data}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode() or "{}")
        except Exception:
            body = {}
        print(f"[mock] {self.path} device={self.headers.get('X-Dravix-Device','-')}", flush=True)

        if self.path == "/gate/config":
            self.send_json({"maintenance_mode": False, "min_version_code": 0, "latest_version_code": 0})
            return

        if self.path in ("/gate/login", "/gate/register"):
            data = access_payload()
            data["token"] = make_token()
            data["needs_shortener"] = False
            self.send_json(data)
            return

        if self.path == "/gate/device":
            sign_pub = b64_der_to_pem(body["sign_pub"])
            wrap_pub = b64_der_to_pem(body["wrap_pub"])
            device_id = secrets.token_hex(16)
            DEVICES[device_id] = {"sign_pub": sign_pub, "wrap_pub": wrap_pub}
            data = access_payload()
            data["device_id"] = device_id
            data.update(issue_lease(wrap_pub))
            self.send_json(data)
            return

        if self.path == "/gate/lease":
            device_id = body.get("device_id", "")
            device = DEVICES.get(device_id)
            if not device:
                self.send_json({"state": "device_unknown"}, 403)
                return

            nonce = self.headers.get("X-Dravix-Nonce", "")
            ts = self.headers.get("X-Dravix-Timestamp", "")
            sig = self.headers.get("X-Dravix-Signature", "")
            dev_header = self.headers.get("X-Dravix-Device", "")
            if not (nonce and ts and sig and dev_header == device_id and nonce not in NONCES):
                self.send_json({"state": "bad_signature"}, 403)
                return
            canonical = (
                "/gate/lease\n"
                + hashlib.sha256(raw).hexdigest()
                + "\n"
                + nonce
                + "\n"
                + ts
                + "\n"
                + device_id
            )
            try:
                pem_to_public(device["sign_pub"]).verify(
                    base64.b64decode(sig),
                    canonical.encode(),
                    ec.ECDSA(hashes.SHA256()),
                )
            except Exception as exc:
                print("[mock] signature verify failed:", exc, flush=True)
                self.send_json({"state": "bad_signature"}, 403)
                return
            NONCES.add(nonce)

            data = access_payload()
            data["device_id"] = device_id
            data.update(issue_lease(device["wrap_pub"]))
            self.send_json(data)
            return

        self.send_json({"state": "not_found"}, 404)


if __name__ == "__main__":
    print("[mock] listening on 127.0.0.1:18099", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 18099), Handler).serve_forever()
