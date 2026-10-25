import base64, hashlib, json, subprocess
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

ec_key = ec.generate_private_key(ec.SECP256R1())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def spki(k):
    return base64.b64encode(k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
body = b'{"device_id":"abc"}'
nonce, ts, dev = "a"*32, "1700000000", "b"*32
canonical = f"/gate/lease\n{hashlib.sha256(body).hexdigest()}\n{nonce}\n{ts}\n{dev}".encode()
sig = ec_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
req = {"ec_spki": spki(ec_key.public_key()), "rsa_spki": spki(rsa_key.public_key()),
       "canonical": canonical.decode(), "sig": base64.b64encode(sig).decode()}
p = subprocess.run(["php", "interop.php"], input=json.dumps(req), capture_output=True, text=True)
print("PHP stderr:", p.stderr.strip())
res = json.loads(p.stdout)
print({k:v for k,v in res.items() if k not in ("asset","wrapped")})
asset = rsa_key.decrypt(base64.b64decode(res["wrapped"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
print("unwrap_match:", base64.b64encode(asset).decode() == res["asset"])
