import base64, hashlib, json, os, time, urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

BASE="http://127.0.0.1:18099"
def post(path, obj, headers=None):
    raw=json.dumps(obj).encode()
    req=urllib.request.Request(BASE+path, data=raw, headers={"Content-Type":"application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

print("config:", post("/gate/config", {})["status"])
login=post("/gate/login", {"username":"tester","password":"x","package_name":"com.dravix.ai","app_version":"2.2.0-lease"})
print("login token:", bool(login["data"].get("token")))

ec_key=ec.generate_private_key(ec.SECP256R1())
rsa_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
def spki(k): return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

dev=post("/gate/device", {"token":login["data"]["token"],"hwid":"a"*64,"install_id":"test","sign_pub":spki(ec_key),"wrap_pub":spki(rsa_key),"apk_cert":"","package_name":"com.dravix.ai","app_version":"2.2.0-lease"})
d=dev["data"]; print("device_id:", d["device_id"], "ttl:", d["lease_ttl"])
asset=rsa_key.decrypt(base64.b64decode(d["asset_key"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
expected=base64.b64decode(open("asset_key.txt").read().strip())
print("asset key match:", asset==expected)

body={"token":login["data"]["token"],"device_id":d["device_id"],"hwid":"a"*64,"install_id":"test","package_name":"com.dravix.ai","app_version":"2.2.0-lease"}
raw=json.dumps(body).encode()
nonce=os.urandom(16).hex(); ts=str(int(time.time()))
canon=f"/gate/lease\n{hashlib.sha256(raw).hexdigest()}\n{nonce}\n{ts}\n{d['device_id']}".encode()
sig=base64.b64encode(ec_key.sign(canon, ec.ECDSA(hashes.SHA256()))).decode()
lease=post("/gate/lease", body, {"X-Dravix-Device":d["device_id"],"X-Dravix-Nonce":nonce,"X-Dravix-Timestamp":ts,"X-Dravix-Signature":sig})
print("lease can_enter:", lease["data"]["can_enter"], "ttl:", lease["data"]["lease_ttl"])

