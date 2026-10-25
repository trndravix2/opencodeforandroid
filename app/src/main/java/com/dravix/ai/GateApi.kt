package com.dravix.ai

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom

class GateApiException(
    val httpCode: Int,
    val state: String?,
    message: String,
    val data: JSONObject? = null
) : Exception(message)

/**
 * Minimal JSON client for the panel gate API.
 *
 * Every HTTPS response is verified against the compiled-in SPKI pins before
 * the request body is written. Lease calls additionally carry an ECDSA
 * signature made by the hardware-backed device key, so a replayed or copied
 * request cannot be produced without the physical device.
 */
object GateApi {

    fun post(context: Context, path: String, body: JSONObject): JSONObject =
        postInternal(context, path, body, null)

    /** POST with an ECDSA device signature (used by the lease endpoint). */
    fun postSigned(context: Context, path: String, body: JSONObject): JSONObject {
        val deviceId = GateStore.deviceId(context)
        if (deviceId.isBlank()) {
            throw GateApiException(0, "device_missing", "Device is not registered.", null)
        }
        return postInternal(context, path, body, deviceId)
    }

    private fun postInternal(
        context: Context,
        path: String,
        body: JSONObject,
        deviceId: String?
    ): JSONObject {
        val base = GateStore.apiBase(context)
        val url = URL(base + path)
        val payload = JSONObject(body.toString())
        payload.put("package_name", context.packageName)
        payload.put("app_version", BuildConfig.VERSION_NAME)
        val bytes = payload.toString().toByteArray(Charsets.UTF_8)

        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15_000
            readTimeout = 35_000
            doOutput = true
            useCaches = false
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "DravixGate/${BuildConfig.VERSION_NAME}")
            setFixedLengthStreamingMode(bytes.size)
        }

        try {
            if (deviceId != null) {
                val nonce = randomNonce()
                val timestamp = System.currentTimeMillis() / 1000L
                val canonical = canonicalString(path, bytes, nonce, timestamp, deviceId)
                val signature = GateCrypto.signBase64(canonical.toByteArray(Charsets.UTF_8))
                conn.setRequestProperty("X-Dravix-Device", deviceId)
                conn.setRequestProperty("X-Dravix-Nonce", nonce)
                conn.setRequestProperty("X-Dravix-Timestamp", timestamp.toString())
                conn.setRequestProperty("X-Dravix-Signature", signature)
            }

            // Force the TLS handshake, then validate the SPKI pins before any
            // request body leaves the device.
            if (conn is javax.net.ssl.HttpsURLConnection) {
                conn.connect()
                verifyPins(conn)
            }

            conn.outputStream.use { it.write(bytes) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.use { input ->
                BufferedReader(InputStreamReader(input, Charsets.UTF_8)).readText()
            }.orEmpty()

            val json = try {
                if (text.isBlank()) JSONObject() else JSONObject(text)
            } catch (_: Throwable) {
                throw GateApiException(code, "bad_response", "Server returned an invalid response.", null)
            }

            val status = json.optString("status", "")
            if (code !in 200..299 || status != "success") {
                val data = json.optJSONObject("data")
                val state = data?.optString("state", "")?.takeIf { it.isNotBlank() }
                val message = json.optString("message", "").ifBlank {
                    when (code) {
                        401 -> "Session expired. Please log in again."
                        403 -> "Access denied by the server."
                        404 -> "Server endpoint not found."
                        429 -> "Too many requests. Please wait a minute."
                        else -> "Server error (HTTP $code)."
                    }
                }
                throw GateApiException(code, state, message, data)
            }
            return json.optJSONObject("data") ?: JSONObject()
        } catch (e: GateApiException) {
            throw e
        } catch (e: Exception) {
            throw GateApiException(0, "network", "Could not reach the server. Check your internet connection.", null)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Certificate pin verification. BuildConfig.GATE_PIN_SHA256 may contain a
     * comma separated list of base64 SHA-256 SPKI pins (leaf + backup/CA).
     * Any match in the presented chain is accepted.
     */
    private fun verifyPins(conn: javax.net.ssl.HttpsURLConnection) {
        val pins = BuildConfig.GATE_PIN_SHA256
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (pins.isEmpty()) return

        val chain = conn.serverCertificates ?: throw GateApiException(
            0, "pin_mismatch", "Secure connection could not be verified.", null
        )
        val digest = MessageDigest.getInstance("SHA-256")
        for (cert in chain) {
            val pin = Base64.encodeToString(
                digest.digest(cert.publicKey.encoded),
                Base64.NO_WRAP
            )
            if (pins.contains(pin)) return
        }
        throw GateApiException(
            0,
            "pin_mismatch",
            "Secure connection could not be verified. Update the app.",
            null
        )
    }

    private fun randomNonce(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun canonicalString(
        path: String,
        body: ByteArray,
        nonce: String,
        timestamp: Long,
        deviceId: String
    ): String {
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body)
            .joinToString("") { "%02x".format(it) }
        return "$path\n$bodyHash\n$nonce\n$timestamp\n$deviceId"
    }
}
