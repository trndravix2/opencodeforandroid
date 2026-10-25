package com.dravix.ai

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

/**
 * Local, encrypted gate session.
 *
 * SECURITY MODEL
 * --------------
 * There is no client-side "can enter" boolean anymore. The app can only start
 * the engine while it holds a short-lived (5 minute) server lease. The lease is
 * bound to a hardware-backed device key, and the AES key needed to decrypt the
 * bundled runtime is only returned wrapped to that device key. Copying the
 * APK, the preferences, or the token to another device yields no usable key.
 */
object GateStore {

    private const val KEY_TOKEN = "token"
    private const val KEY_TOKEN_EXP = "token_exp"
    private const val KEY_ACCESS_TYPE = "access_type"
    private const val KEY_PLAN = "plan"
    private const val KEY_PAID_ACTIVE = "paid_active"
    private const val KEY_USERNAME = "username"
    private const val KEY_USER_JSON = "user_json"
    private const val KEY_INSTALL_ID = "install_id"
    private const val KEY_DEVICE_ID = "device_id"
    private const val KEY_LEASE = "lease"
    private const val KEY_LEASE_EXP = "lease_exp"
    private const val KEY_LEASE_RECEIVED_ELAPSED = "lease_received_elapsed"
    private const val KEY_LEASE_TTL = "lease_ttl"
    private const val KEY_ASSET_KEY = "asset_key"

    /**
     * The AES key lives only in this process's memory. It is deliberately not
     * written to disk: after a process death or reboot the app must obtain a
     * fresh server lease before it can decrypt the runtime.
     */
    @Volatile
    private var memoryAssetKey: ByteArray? = null

    /** The gate base URL is compiled in. It cannot be changed at runtime. */
    fun apiBase(@Suppress("UNUSED_PARAMETER") context: Context): String =
        normalizeBase(BuildConfig.GATE_API_BASE)

    fun normalizeBase(value: String): String {
        var v = value.trim()
        if (v.isEmpty()) return BuildConfig.GATE_API_BASE
        if (!v.startsWith("http://") && !v.startsWith("https://")) v = "https://$v"
        while (v.endsWith("/")) v = v.dropLast(1)
        return v
    }

    /** Per-install value. Used only to make HWID fallbacks unique. */
    fun installId(context: Context): String {
        val existing = SecurePrefs.getString(context, KEY_INSTALL_ID, "")
        if (existing.isNotBlank()) return existing
        val id = UUID.randomUUID().toString().replace("-", "")
        SecurePrefs.putString(context, KEY_INSTALL_ID, id)
        return id
    }

    /**
     * Stable device binding. ANDROID_ID is scoped to the app signing key on
     * modern Android and survives reinstall/updates; only a factory reset or
     * a new signing key changes it.
     */
    fun hwid(context: Context): String {
        val androidId = try {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ).orEmpty().trim()
        } catch (_: Throwable) {
            ""
        }
        val raw = if (androidId.isNotEmpty() && androidId != "9774d56d682e549c") {
            "dravix-hwid-v2|${context.packageName}|$androidId"
        } else {
            "dravix-hwid-v2|${context.packageName}|${Build.BRAND}|${Build.DEVICE}|${Build.MODEL}|${installId(context)}"
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { String.format(Locale.US, "%02x", it.toInt() and 0xff) }
    }

    fun username(context: Context): String = SecurePrefs.getString(context, KEY_USERNAME, "")

    fun token(context: Context): String = SecurePrefs.getString(context, KEY_TOKEN, "")

    fun tokenExpiresAt(context: Context): Long = SecurePrefs.getLong(context, KEY_TOKEN_EXP, 0L)

    fun hasFreshToken(context: Context): Boolean {
        val token = token(context)
        return token.isNotBlank() && tokenExpiresAt(context) > System.currentTimeMillis() + 30_000L
    }

    fun deviceId(context: Context): String = SecurePrefs.getString(context, KEY_DEVICE_ID, "")

    fun saveDeviceId(context: Context, deviceId: String) =
        SecurePrefs.putString(context, KEY_DEVICE_ID, deviceId)

    /** Drops the local device binding so a rotated Keystore key can re-register. */
    @Synchronized
    fun clearDeviceRegistration(context: Context) {
        clearLeaseMaterial(context)
        SecurePrefs.remove(context, KEY_DEVICE_ID)
    }

    fun lease(context: Context): String = SecurePrefs.getString(context, KEY_LEASE, "")

    /** For display/diagnostics only; local validity uses the monotonic clock. */
    fun leaseExpiresAt(context: Context): Long = SecurePrefs.getLong(context, KEY_LEASE_EXP, 0L)

    /**
     * True only while a server lease (max 5 minutes) is unexpired AND the
     * hardware-wrapped asset key has been received. No offline grace period.
     *
     * Validity is measured with SystemClock.elapsedRealtime(), not the wall
     * clock, so moving the device clock backwards cannot extend access and a
     * reboot always forces a fresh server decision.
     */
    @Synchronized
    fun hasValidLease(context: Context): Boolean {
        if (deviceId(context).isBlank()) return false
        val receivedAt = SecurePrefs.getLong(context, KEY_LEASE_RECEIVED_ELAPSED, 0L)
        val ttlSeconds = SecurePrefs.getLong(context, KEY_LEASE_TTL, 0L)
        if (receivedAt <= 0L || ttlSeconds <= 0L) {
            clearLeaseMaterial(context)
            return false
        }
        val now = SystemClock.elapsedRealtime()
        if (now < receivedAt) {
            clearLeaseMaterial(context)
            return false
        }
        val remaining = (receivedAt + ttlSeconds * 1000L) - now
        if (remaining <= 5_000L) {
            clearLeaseMaterial(context)
            return false
        }
        return memoryAssetKey != null
    }

    /** AES-256 key used to decrypt the bundled runtime, or null. */
    fun assetKey(@Suppress("UNUSED_PARAMETER") context: Context): ByteArray? = memoryAssetKey

    /** Removes lease material (and any legacy persisted asset key). */
    @Synchronized
    private fun clearLeaseMaterial(context: Context) {
        memoryAssetKey = null
        SecurePrefs.remove(
            context,
            KEY_LEASE,
            KEY_LEASE_EXP,
            KEY_LEASE_RECEIVED_ELAPSED,
            KEY_LEASE_TTL,
            KEY_ASSET_KEY
        )
    }

    /** One-time cleanup for builds that persisted the asset key. */
    fun purgeLegacyAssetKey(context: Context) {
        SecurePrefs.remove(context, KEY_ASSET_KEY)
    }

    /**
     * Stores a lease response. Returns true when the device may enter.
     * The asset key is RSA-OAEP wrapped and can only be opened by this
     * device's Keystore private key.
     */
    @Synchronized
    fun saveLease(context: Context, data: JSONObject): Boolean {
        val canEnter = data.optBoolean("can_enter", false)
        val expiresAt = data.optLong("lease_expires_at", 0L)
        val wrapped = data.optString("asset_key", "").trim()
        if (!canEnter || expiresAt <= 0L || wrapped.isBlank()) {
            clearLeaseMaterial(context)
            return false
        }
        val secret = try {
            GateCrypto.unwrapSecret(Base64.decode(wrapped, Base64.NO_WRAP))
        } catch (_: Throwable) {
            clearLeaseMaterial(context)
            return false
        }
        if (secret.size != 32) {
            clearLeaseMaterial(context)
            return false
        }
        var ttlSeconds = data.optLong("lease_ttl", 0L)
        if (ttlSeconds <= 0L) {
            ttlSeconds = (expiresAt - System.currentTimeMillis() / 1000L).coerceIn(30L, 900L)
        }
        SecurePrefs.putString(context, KEY_LEASE, data.optString("lease", ""))
        SecurePrefs.putLong(context, KEY_LEASE_EXP, expiresAt * 1000L)
        SecurePrefs.putLong(context, KEY_LEASE_RECEIVED_ELAPSED, SystemClock.elapsedRealtime())
        SecurePrefs.putLong(context, KEY_LEASE_TTL, ttlSeconds)
        memoryAssetKey = secret
        return true
    }

    /** The engine may start only with a fresh token AND an unexpired lease. */
    fun isAllowedToEnter(context: Context): Boolean =
        hasFreshToken(context) && hasValidLease(context)

    fun saveSession(context: Context, data: JSONObject) {
        val token = data.optString("token", "")
        if (token.isBlank()) return
        val exp = jwtExpiry(token).takeIf { it > 0 }
            ?: parseIsoTime(data.optString("token_expires_at", ""))
        val user = data.optJSONObject("user")

        SecurePrefs.putString(context, KEY_TOKEN, token)
        SecurePrefs.putLong(context, KEY_TOKEN_EXP, exp)
        SecurePrefs.putString(context, KEY_ACCESS_TYPE, data.optString("access_type", "free"))
        SecurePrefs.putString(context, KEY_PLAN, data.optString("plan", "free"))
        SecurePrefs.putBoolean(context, KEY_PAID_ACTIVE, data.optBoolean("paid_active", false))
        SecurePrefs.putString(context, KEY_USER_JSON, user?.toString() ?: "{}")
        val name = user?.optString("username", "").orEmpty()
        if (name.isNotBlank()) SecurePrefs.putString(context, KEY_USERNAME, name)
    }

    fun saveToken(context: Context, data: JSONObject) = saveSession(context, data)

    /** Clears credentials, lease and the usable asset key. */
    @Synchronized
    fun clearSession(context: Context) {
        clearLeaseMaterial(context)
        SecurePrefs.remove(
            context,
            KEY_TOKEN,
            KEY_TOKEN_EXP,
            KEY_ACCESS_TYPE,
            KEY_PLAN,
            KEY_PAID_ACTIVE,
            KEY_USER_JSON,
            KEY_DEVICE_ID
        )
    }

    fun clearAll(context: Context) {
        clearSession(context)
        SecurePrefs.remove(context, KEY_INSTALL_ID)
    }

    private fun jwtExpiry(token: String): Long {
        return try {
            val parts = token.split('.')
            if (parts.size != 3) return 0L
            val raw = try {
                Base64.decode(parts[1], Base64.DEFAULT)
            } catch (_: Throwable) {
                Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            }
            val json = JSONObject(String(raw, Charsets.UTF_8))
            val exp = json.optLong("exp", 0L)
            if (exp > 0) exp * 1000L else json.optLong("exp_time", 0L) * 1000L
        } catch (_: Throwable) {
            0L
        }
    }

    private fun parseIsoTime(value: String): Long {
        if (value.isBlank()) return 0L
        val patterns = arrayOf(
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
            "yyyy-MM-dd HH:mm:ss"
        )
        for (pattern in patterns) {
            try {
                val parser = java.text.SimpleDateFormat(pattern, java.util.Locale.US)
                parser.timeZone = java.util.TimeZone.getTimeZone("UTC")
                return parser.parse(value)?.time ?: 0L
            } catch (_: Throwable) {
            }
        }
        return 0L
    }
}
