package com.dravix.ai

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted preference store backed by an AES-256-GCM key that lives in the
 * Android Keystore (hardware backed where available). Nothing sensitive is
 * ever written to disk in plaintext.
 */
object SecurePrefs {

    private const val FILE = "dravix_secure_v2"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "dravix_prefs_aes_v1"
    private const val GCM_TAG_BITS = 128

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun secretKey(): SecretKey {
        val ks = keyStore()
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = cipher.iv
        val body = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val packed = ByteArray(iv.size + body.size)
        System.arraycopy(iv, 0, packed, 0, iv.size)
        System.arraycopy(body, 0, packed, iv.size, body.size)
        return Base64.encodeToString(packed, Base64.NO_WRAP)
    }

    private fun decrypt(value: String): String? {
        return try {
            val packed = Base64.decode(value, Base64.NO_WRAP)
            if (packed.size <= 12) return null
            val iv = packed.copyOfRange(0, 12)
            val body = packed.copyOfRange(12, packed.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(body), Charsets.UTF_8)
        } catch (_: Throwable) {
            null
        }
    }

    fun getString(context: Context, key: String, fallback: String = ""): String {
        val raw = prefs(context).getString(key, null) ?: return fallback
        return decrypt(raw) ?: fallback
    }

    fun putString(context: Context, key: String, value: String?) {
        val editor = prefs(context).edit()
        if (value == null) {
            editor.remove(key)
        } else {
            editor.putString(key, encrypt(value))
        }
        editor.apply()
    }

    fun putLong(context: Context, key: String, value: Long) =
        prefs(context).edit().putLong(key, value).apply()

    fun getLong(context: Context, key: String, fallback: Long = 0L): Long =
        prefs(context).getLong(key, fallback)

    fun putBoolean(context: Context, key: String, value: Boolean) =
        prefs(context).edit().putBoolean(key, value).apply()

    fun getBoolean(context: Context, key: String, fallback: Boolean = false): Boolean =
        prefs(context).getBoolean(key, fallback)

    fun remove(context: Context, vararg keys: String) {
        val editor = prefs(context).edit()
        keys.forEach { editor.remove(it) }
        editor.apply()
    }

    fun clear(context: Context) = prefs(context).edit().clear().apply()
}
