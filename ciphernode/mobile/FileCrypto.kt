package ciphernode.mobile

import android.graphics.BitmapFactory
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Local-only file processor that strips metadata and encrypts with AES-256-GCM.
 */
object FileCrypto {
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12
    private const val TAG_LENGTH = 128

    data class EncryptedPayload(
        val cipherText: ByteArray,
        val iv: ByteArray,
        val rawKey: ByteArray,
    )

    fun encryptFile(rawBytes: ByteArray, mimeType: String): EncryptedPayload {
        val sanitized = stripMetadata(rawBytes, mimeType)
        val key = generateKey()
        val iv = ByteArray(IV_LENGTH).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH, iv))
        val cipherText = cipher.doFinal(sanitized)
        return EncryptedPayload(cipherText, iv, key.encoded)
    }

    fun decryptFile(payload: EncryptedPayload): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        val key = javax.crypto.spec.SecretKeySpec(payload.rawKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH, payload.iv))
        return cipher.doFinal(payload.cipherText)
    }

    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom())
        return generator.generateKey()
    }

    private fun stripMetadata(bytes: ByteArray, mimeType: String): ByteArray {
        return when {
            mimeType.startsWith("image/") -> stripImageMetadata(bytes)
            mimeType == "text/plain" || mimeType == "application/json" -> bytes
            else -> throw IllegalArgumentException("Unsupported document type. Add a sanitizer before upload.")
        }
    }

    private fun stripImageMetadata(bytes: ByteArray): ByteArray {
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: throw IllegalArgumentException("Invalid image payload")
        val output = ByteArrayOutputStream()
        bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, output)
        return output.toByteArray()
    }

    fun encodeKeyForSharing(rawKey: ByteArray): String {
        return Base64.encodeToString(rawKey, Base64.NO_WRAP)
    }
}
