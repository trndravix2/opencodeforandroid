# Dravix OpenCode — 2.2.0-lease hardening

APK: `com.dravix.ai`, versionCode 6, versionName `2.2.0-lease`
Release APK: `C:\Users\pc\Dravix-OpenCode-v2.2.0-lease-release.apk`
APK SHA-256: `F87851E778A431F1FA09074C2614213B27C5F03F4F599AADDC56CA1D62AF3C5A`

> The SHA-256 changes every time the APK is rebuilt. Recompute it after any
> build (`Get-FileHash ... -Algorithm SHA256`).

Signing certificate SHA-256 (stable as long as the same keystore is used):

```
6884c593e499083e703cd2c088fb02183c958db81b428b9af94169883d7f1ca4
```

---

## 1. What changed

### Server is now the only authority

- The old client-side `can_enter` / cached entitlement and the 24h/7d offline
  grace are gone.
- The engine can start only with a **5 minute server lease**.
- A lease is renewed every ~60 seconds by `MainActivity` and by
  `DravixService`. If renewal fails, the stored lease expires (max 5 minutes),
  the UI locks, and the foreground service stops the engine.
- Lease validity is measured with `SystemClock.elapsedRealtime()`, so moving the
  device clock backwards cannot extend access. A reboot forces a new lease.

### Hardware-bound device identity

On first successful login the app creates two keys inside the Android Keystore:

- EC P-256 signing key (`dravix_device_sign_v1`)
- RSA-2048 OAEP key (`dravix_wrap_v1`)

Private keys never leave the Keystore. The server stores only the public keys
in `ai_devices`.

Every `/gate/lease` request is signed:

```
ECDSA-SHA256(
  path + "\n" +
  sha256hex(raw_body) + "\n" +
  nonce + "\n" +
  timestamp + "\n" +
  device_id
)
```

Headers: `X-Dravix-Device`, `X-Dravix-Nonce`, `X-Dravix-Timestamp`,
`X-Dravix-Signature`. The server checks the signature, the timestamp window,
and a one-time nonce table (`ai_lease_nonces`), so captured requests cannot be
replayed.

### Encrypted runtime, key only inside the lease

- `opencode-aarch64`, `opencode-x86_64`, `rootfs-aarch64.bin`,
  `rootfs-x86_64.bin` are shipped only as `*.enc`.
- Container: `"DRVX2" | 16-byte IV | AES-256-CTR ciphertext`.
- The AES key is **not** in the APK. The panel returns it as
  `RSA-OAEP(SHA-1)(asset_key)` to the device's Keystore RSA key, together with
  the lease.
- CTR is used instead of GCM because Android's `CipherInputStream` buffers AEAD
  plaintext in memory; a 213 MB binary caused GC thrashing and a startup stall.
  CTR streams in constant memory. The APK v2 signature protects the encrypted
  asset at rest, and a wrong key produces an unusable image.
- The plaintext assets are excluded from the APK by
  `androidResources.ignoreAssetsPattern` (verified after build).

### Other client hardening

- `SecurePrefs`: token, device id and lease are stored with Keystore-backed
  AES-256-GCM, not plaintext SharedPreferences.
- The runtime AES key is **memory-only**. It is never written to disk; after a
  process death or reboot the app must obtain a fresh server lease before it can
  decrypt the runtime. The old persisted asset key is deleted on first launch.
- If a lease refresh fails transiently (network/server down), the gate shows a
  **Retry secure license** button instead of forcing a full logout.
- The runtime gate URL is compiled in (`BuildConfig.GATE_API_BASE`). The old
  footer/long-press "Gate server" dialog and `setApiBase` were removed.
- TLS SPKI pinning is enforced **before the request body is written**.
- `DEBUG_STRACE` is off.
- R8 + resource shrinking enabled; `proguard-rules.pro` keeps only the WebView
  JS bridge.
- Old plaintext `dravix_gate_v1` preferences are scrubbed on first launch.
- Old extracted runtimes are re-extracted (`ROOTFS_MARKER` v3 + `.dravix-watermark`
  presence), so upgrading from a pre-encryption build does not keep plaintext
  files.
- Per-user watermark is written to `files/rootfs/etc/dravix-watermark` and
  `files/bin/.dravix-watermark`. The OpenCode/Bun binary itself is not modified
  (Bun standalone executables keep a trailer at EOF).
- `targetSdk` intentionally stays **28**: Android 10+ blocks `execve()` of files
  in the app data directory for apps targeting 29+, which would break the bundled
  PRoot/Alpine/OpenCode runtime. The app is sideloaded, not distributed via Play.

---

## 2. Server deployment (required)

Files to deploy:

```
application/controllers/Gate.php
application/config/dravix_secrets.php
```

`Gate.php` adds three endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/gate/device` | POST | Register/refresh this phone's public keys; returns device id + first lease |
| `/gate/lease` | POST | Signed lease refresh; returns lease + RSA-OAEP wrapped asset key |
| `/gate/revoke` | POST | Admin kill switch (device / user / HWID) |

Tables are created automatically on first use:

- `ai_devices` (device id, user, HWID, signing/wrap public keys, APK cert, status)
- `ai_lease_nonces` (replay protection)
- `ai_leases` (issued lease ids, expiry, status)

### Required environment variables

```bash
# Existing, must stay the same as before
DRAVIX_JWT_SECRET=...

# NEW: must exactly match the key used at APK build time.
# Current key (also present as a fallback in dravix_secrets.php):
DRAVIX_ASSET_KEY=YoIX4vhGyodgjH+1xCxwwoas1Rf+cExfcsrlLqzl0Es=

# Optional; defaults to SHA-256(jwt_secret + '|dravix-lease-v1')
DRAVIX_LEASE_SECRET=...

# Optional; if unset, admin auth = HMAC-SHA256('dravix-lease-revoke', jwt_secret)
DRAVIX_ADMIN_TOKEN=...

# Optional but recommended: reject APKs not signed by this release key.
DRAVIX_APK_CERT_SHA256=6884c593e499083e703cd2c088fb02183c958db81b428b9af94169883d7f1ca4
```

If `DRAVIX_ASSET_KEY` is not set, the panel falls back to `asset_key` in
`application/config/dravix_secrets.php`. That fallback must be the same 32-byte
base64 value. If neither source contains a valid 32-byte key, `/gate/lease`
fails with HTTP 500 `server_misconfigured` and logs `ASSET_KEY_MISSING`; there
is no derived fallback. A key mismatch means the app gets a wrapped key it
cannot use, and the engine fails closed (the failure is explicit server-side).

### Revoke a device / user

```bash
ADMIN=$(php -r "echo getenv('DRAVIX_ADMIN_TOKEN') ?: hash_hmac('sha256','dravix-lease-revoke',getenv('DRAVIX_JWT_SECRET'));")

# Revoke one device
curl -sS https://tool.lightkuro.site/gate/revoke \
  -H "Content-Type: application/json" \
  -H "X-Dravix-Admin: $ADMIN" \
  -d '{"device_id":"0123456789abcdef0123456789abcdef"}'

# Revoke every device of an account and invalidate its JWTs
curl -sS https://tool.lightkuro.site/gate/revoke \
  -H "Content-Type: application/json" \
  -H "X-Dravix-Admin: $ADMIN" \
  -d '{"username":"someuser"}'

# Revoke by HWID
curl -sS https://tool.lightkuro.site/gate/revoke \
  -H "Content-Type: application/json" \
  -H "X-Dravix-Admin: $ADMIN" \
  -d '{"hwid":"..."}'
```

Revocation flips `ai_devices.status = revoked`, marks leases revoked, and bumps
`users.token_epoch`. The next lease refresh (within ~60s) locks the app and
stops the engine.

Optional setting: `ai_require_key_rotation_approval = 1` blocks automatic
Keystore key rotation (e.g. after a reinstall with a new key) and requires an
admin HWID/device reset. Default is `0` so legitimate reinstalls self-recover.

---

## 3. Building / rotating keys

### Rebuild the APK

```powershell
cd C:\Users\pc\.gemini\antigravity\scratch\dravix_apk
python tools\encrypt_assets.py --force   # only needed if assets/key changed
.\gradlew.bat :app:assembleRelease
```

Output: `app\build\outputs\apk\release\app-release.apk`.

Signing is configured through `keystore.properties` (release keystore
`dravix-release.jks`). Keep that keystore and its password safe: losing it means
existing users cannot update.

### Rotate the asset key

The asset key is shared by the APK build and the panel. To rotate:

1. Generate a new 32-byte base64 key.
2. Write it to `tools/asset_key.txt`.
3. `python tools\encrypt_assets.py --force`
4. Rebuild and ship a new APK.
5. Set `DRAVIX_ASSET_KEY` on the panel to the same value (or update
   `dravix_secrets.php`).

Old APKs stop working immediately after step 5.

### TLS certificate pin rotation

Current SPKI pins (base64 SHA-256):

```
leaf  : cmJ/GpwT+B0p8CXGHyUZQzYnjkcCjxPF9nvKB0SyEMs=
WE1   : kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=
GTS R4: mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=
```

Any pin in the presented chain is accepted, so leaf rotation is fine while the
GTS root stays trusted. If the panel moves to another CA, capture the new
chain and rebuild:

```powershell
.\gradlew.bat :app:assembleRelease -Pdravix.gatePin="newPin1,newPin2"
```

or update the default in `app/build.gradle.kts`.

---

## 4. Verification performed

- `php -l` on `Gate.php` and `dravix_secrets.php`: clean.
- Missing/invalid asset key: `/gate/lease` returns HTTP 500
  `server_misconfigured` and logs `ASSET_KEY_MISSING`; there is no derived-key
  fallback (code review + lint).
- Client ↔ PHP crypto interop:
  - EC P-256 curve `prime256v1` accepted.
  - DER ECDSA signature verified by `openssl_verify`.
  - RSA-2048 SPKI accepted; RSA-OAEP wrapped 32-byte key unwrapped by the client
    equivalent.
- Android 35 emulator, clean install:
  - login → `/gate/device` → hardware keys → `/gate/lease`
  - encrypted rootfs + 203 MB OpenCode binary decrypted
  - `opencode v2.1.1` verified, server reached `ONLINE` on `127.0.0.1:4096`
  - lease refreshed every ~60s (mock panel logs)
  - deny panel → app locked and engine stopped within one refresh cycle
  - process death + server unreachable (stored lease still unexpired) →
    GateActivity only, no engine, no port 4096, Retry button shown. This proves
    the AES key is not recoverable from disk.
  - Retry button tapped while offline: no crash, remains locked; the successful
    path uses the same `attemptSavedSession()` code verified at cold start.
  - release APK clean install: login screen renders, no R8/runtime crash.
  - release APK installed over the debug build only after uninstalling it
    (different signing key).
- Release APK checks:
  - signed with the release certificate above
  - `versionCode 6`, `targetSdk 28`
  - no plaintext runtime assets in `assets/`
  - no asset key string in any DEX
  - `.enc` entries stored uncompressed

Not tested on a physical device or against the production panel database. Run a
staged rollout/login test after uploading the two server files and setting
`DRAVIX_ASSET_KEY`.

---

## 5. Residual risks (honest list)

- A rooted device with a valid lease can dump the decrypted runtime from
  `files/`. No client-side scheme can prevent that; the watermark and revocation
  exist for leak tracing.
- `targetSdk 28` is required for the PRoot runtime and is a deliberate
  compatibility trade-off.
- The APK signing-certificate claim sent by the client can be lied about by a
  patched client. The real controls are the hardware device key, the 5 minute
  lease, and the server-held asset key.
- R8/obfuscation and pinning raise the cost of patching but are not a native
  integrity attestation (Play Integrity / hardware attestation was not added).
- If the panel's TLS chain changes to a CA outside the pin set, existing app
  versions will fail closed until updated. Keep a backup release channel ready.
- The asset key in `dravix_secrets.php` is a fallback for development; prefer the
  environment variable on production and restrict file permissions.
