package com.dravix.ai

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.InputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted runtime assets.
 *
 * The 200 MB+ OpenCode binaries and Alpine rootfs are stored in the APK as
 * AES-256-CTR blobs. The key exists only inside a short-lived server lease,
 * wrapped to the device's hardware Keystore RSA key. Without a live license the
 * APK contains nothing that can be executed.
 *
 * CTR is used instead of GCM because Android's CipherInputStream buffers AEAD
 * plaintext in memory; with a 213 MB binary that causes GC thrashing and stalls
 * the engine. CTR streams at constant memory. The APK's v2 signature already
 * protects asset integrity, and a wrong key simply produces an unusable image.
 *
 * File format: "DRVX2" | 16-byte IV | AES-CTR ciphertext
 */
object AssetVault {

    private const val MAGIC = "DRVX2"
    private const val HEADER_SIZE = 5 + 16

    /** Opens a decrypted stream for the named asset. Fails closed. */
    fun open(context: Context, assetName: String): InputStream {
        val key = GateStore.assetKey(context)
            ?: throw IllegalStateException("No active license. Please sign in again.")

        val encryptedName = "$assetName.enc"
        val raw = try {
            context.assets.open(encryptedName)
        } catch (_: FileNotFoundException) {
            if (BuildConfig.ALLOW_PLAIN_ASSETS && BuildConfig.DEBUG) {
                // Development-only fallback. Never enabled in release builds.
                return context.assets.open(assetName)
            }
            throw IllegalStateException("Encrypted asset is missing from this build.")
        }
        return decryptStream(raw, key)
    }

    private fun decryptStream(input: InputStream, key: ByteArray): InputStream {
        val header = ByteArray(HEADER_SIZE)
        var read = 0
        while (read < header.size) {
            val n = input.read(header, read, header.size - read)
            if (n <= 0) throw IllegalStateException("Corrupt encrypted asset header.")
            read += n
        }
        val magic = String(header, 0, 5, Charsets.US_ASCII)
        if (magic != MAGIC) {
            input.close()
            throw IllegalStateException("Unsupported asset container.")
        }
        val iv = header.copyOfRange(5, HEADER_SIZE)

        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return CipherInputStream(input, cipher)
    }

    /**
     * Writes a per-user forensic watermark to a sidecar file. The runtime
     * binaries themselves are never modified: Bun standalone executables keep
     * a trailer at EOF, so appending bytes would corrupt them.
     */
    fun writeWatermark(context: Context, target: File) {
        val username = GateStore.username(context).ifBlank { "unknown" }
        val device = GateStore.deviceId(context).ifBlank { "unregistered" }
        val marker = "DRAVIX-WM|$username|$device|${System.currentTimeMillis()}\n"
        try {
            target.parentFile?.mkdirs()
            target.writeText(marker)
        } catch (_: Throwable) {
            // Watermarking is best effort; never block startup over it.
        }
    }

    /** Verifies that a file was fully decrypted (used for large binaries). */
    fun isComplete(file: File, minimumBytes: Long): Boolean =
        file.exists() && file.length() >= minimumBytes

    @Suppress("unused")
    fun copiedLength(file: File): Long = if (file.exists()) file.length() else 0L

    @Suppress("unused")
    fun openFile(file: File): InputStream = FileInputStream(file)
}
