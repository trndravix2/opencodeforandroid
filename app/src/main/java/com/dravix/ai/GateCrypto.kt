package com.dravix.ai

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher

/**
 * Hardware backed device identity.
 *
 * - EC P-256 signing key: proves the request came from this physical device.
 * - RSA-2048 wrapping key: unwraps the per-lease AES asset key.
 *
 * Private keys never leave the TEE/StrongBox. A copied APK on another device
 * cannot produce valid request signatures and cannot unwrap the asset key.
 */
object GateCrypto {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val SIGN_ALIAS = "dravix_sign_v1"
    private const val WRAP_ALIAS = "dravix_wrap_v1"

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun publicKey(alias: String): PublicKey {
        val entry = keyStore().getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return entry.certificate.publicKey
    }

    private fun privateKey(alias: String): PrivateKey {
        val entry = keyStore().getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey
    }

    @Synchronized
    private fun ensureSigningKey(): KeyStore.PrivateKeyEntry {
        val ks = keyStore()
        (ks.getEntry(SIGN_ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let { return it }
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(
                SIGN_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
        )
        generator.generateKeyPair()
        return ks.getEntry(SIGN_ALIAS, null) as KeyStore.PrivateKeyEntry
    }

    @Synchronized
    private fun ensureWrapKey(): KeyStore.PrivateKeyEntry {
        val ks = keyStore()
        (ks.getEntry(WRAP_ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let { return it }
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(WRAP_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(false)
                .build()
        )
        generator.generateKeyPair()
        return ks.getEntry(WRAP_ALIAS, null) as KeyStore.PrivateKeyEntry
    }

    /** X.509 SubjectPublicKeyInfo, base64 (no wrap). Sent once at registration. */
    fun signingPublicKeyBase64(): String {
        ensureSigningKey()
        return Base64.encodeToString(publicKey(SIGN_ALIAS).encoded, Base64.NO_WRAP)
    }

    fun wrapPublicKeyBase64(): String {
        ensureWrapKey()
        return Base64.encodeToString(publicKey(WRAP_ALIAS).encoded, Base64.NO_WRAP)
    }

    /** DER encoded ECDSA-SHA256 signature, base64 (no wrap). */
    fun signBase64(payload: ByteArray): String {
        ensureSigningKey()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey(SIGN_ALIAS))
        signature.update(payload)
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    /** RSA-OAEP(SHA-1) unwrap of the server wrapped AES-256 asset key. */
    fun unwrapSecret(wrapped: ByteArray): ByteArray {
        ensureWrapKey()
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey(WRAP_ALIAS))
        return cipher.doFinal(wrapped)
    }

    fun sha256Hex(value: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** SHA-256 of the APK signing certificate. Server pins this value. */
    @Suppress("DEPRECATION")
    fun apkCertSha256(context: Context): String {
        val pm = context.packageManager
        val cert = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                info.signingInfo?.apkContentsSigners?.firstOrNull()
            } else {
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                    .signatures?.firstOrNull()
            }
        } catch (_: Throwable) {
            null
        } ?: return ""
        return sha256Hex(cert.toByteArray())
    }
}
