#!/usr/bin/env python3
"""Deny-all mock panel for the fail-closed lease test."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.path == "/gate/lease":
            data = {
                "can_enter": False,
                "lease": None,
                "lease_expires_at": 0,
                "lease_ttl": 0,
                "asset_key": None,
                "access_type": "free",
                "plan": "free",
                "paid_active": False,
                "user": {"id": 1, "username": "tester"},
            }
        elif self.path in ("/gate/login", "/gate/register"):
            data = {
                "can_enter": False,
                "needs_shortener": True,
                "access_type": "free",
                "plan": "free",
                "paid_active": False,
                "user": {"id": 1, "username": "tester"},
                "token": "deny.token.value",
            }
        else:
            data = {"maintenance_mode": False, "min_version_code": 0, "latest_version_code": 0}
        body = json.dumps({"status": "success", "message": "ok", "data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[deny] " + (fmt % args), flush=True)


if __name__ == "__main__":
    print("[deny] listening on 127.0.0.1:18099", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 18099), Handler).serve_forever()
