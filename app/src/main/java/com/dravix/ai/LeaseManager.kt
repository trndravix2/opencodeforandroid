package com.dravix.ai

import android.content.Context
import android.os.Build
import org.json.JSONObject

/**
 * Server-authoritative license manager.
 *
 * A device is registered once with two hardware-backed public keys. Every
 * access decision afterwards comes from `/gate/lease`, which returns a
 * 5 minute signed lease plus the asset key wrapped to this device's RSA key.
 * There is no cached "allowed" flag anywhere.
 */
object LeaseManager {

    const val LEASE_PATH = "/gate/lease"
    const val DEVICE_PATH = "/gate/device"

    @Synchronized
    fun registerDevice(context: Context): Boolean {
        if (GateStore.deviceId(context).isNotBlank()) return true

        val body = JSONObject()
            .put("token", GateStore.token(context))
            .put("hwid", GateStore.hwid(context))
            .put("install_id", GateStore.installId(context))
            .put("device_model", deviceName())
            .put("sign_pub", GateCrypto.signingPublicKeyBase64())
            .put("wrap_pub", GateCrypto.wrapPublicKeyBase64())
            .put("apk_cert", GateCrypto.apkCertSha256(context))

        val data = GateApi.post(context, DEVICE_PATH, body)
        val deviceId = data.optString("device_id", "").trim()
        if (deviceId.isBlank()) {
            throw GateApiException(
                0,
                "device_register_failed",
                "Server did not issue a device identity.",
                null
            )
        }
        GateStore.saveDeviceId(context, deviceId)
        return GateStore.saveLease(context, data)
    }

    /**
     * Requests a fresh lease. Returns true only if the server granted access
     * and the asset key was successfully unwrapped by the Keystore.
     */
    @Synchronized
    fun refresh(context: Context): Boolean {
        if (GateStore.token(context).isBlank()) return false
        if (GateStore.deviceId(context).isBlank()) {
            registerDevice(context)
            if (GateStore.hasValidLease(context)) return true
        }

        val body = JSONObject()
            .put("token", GateStore.token(context))
            .put("device_id", GateStore.deviceId(context))
            .put("hwid", GateStore.hwid(context))
            .put("install_id", GateStore.installId(context))

        val data = GateApi.postSigned(context, LEASE_PATH, body)
        val granted = data.optBoolean("can_enter", false)
        val ok = GateStore.saveLease(context, data)
        if (ok) return true
        if (granted) {
            // The server granted access but the wrapped key could not be
            // opened. This happens when the Keystore key was rotated or the
            // app was restored to a device with a different key. Re-register
            // once with the current hardware keys.
            GateStore.clearDeviceRegistration(context)
            return registerDevice(context)
        }
        return false
    }

    /**
     * Ensures the device has a usable lease, registering or refreshing as
     * needed. Throws GateApiException for fatal states (banned, revoked...).
     */
    fun ensureLease(context: Context): Boolean {
        if (GateStore.hasValidLease(context)) return true
        if (GateStore.deviceId(context).isBlank()) {
            registerDevice(context)
            if (GateStore.hasValidLease(context)) return true
        }
        return refresh(context)
    }

    fun hasValidLease(context: Context): Boolean = GateStore.hasValidLease(context)

    fun assetKey(context: Context): ByteArray? = GateStore.assetKey(context)

    fun isFatalState(state: String?): Boolean = state in setOf(
        "token_expired",
        "token_missing",
        "banned",
        "session_revoked",
        "hwid_mismatch",
        "account_inactive",
        "user_not_found",
        "wrong_app",
        "device_revoked",
        "device_unknown",
        "apk_mismatch"
    )

    private fun deviceName(): String {
        val name = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        return name.ifBlank { "Android device" }.take(120)
    }
}
