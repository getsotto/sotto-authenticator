package dev.getsotto.authenticator

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

internal enum class VaultKeyMode(
    val alias: String,
    val authenticationWindowSeconds: Int,
    val authenticators: Int,
) {
    BIOMETRIC_PER_OPERATION(
        alias = "sotto_vault_spike_biometric",
        authenticationWindowSeconds = 0,
        authenticators = KeyProperties.AUTH_BIOMETRIC_STRONG,
    ),
    BIOMETRIC_OR_CREDENTIAL(
        alias = "sotto_vault_spike_fallback",
        authenticationWindowSeconds = 5,
        authenticators = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
    ),
}

internal class VaultKeyExperiment {
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private var envelope: ByteArray? = null

    fun hasKey(mode: VaultKeyMode): Boolean = keyStore.containsAlias(mode.alias)

    fun hasAnyKey(): Boolean = VaultKeyMode.entries.any { hasKey(it) }

    fun createKey(mode: VaultKeyMode): String {
        check(mode != VaultKeyMode.BIOMETRIC_OR_CREDENTIAL || Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "Device-credential fallback requires Android 11 (API 30) or later."
        }
        val store = keyStore
        if (store.containsAlias(mode.alias)) store.deleteEntry(mode.alias)
        envelope = null

        val spec = KeyGenParameterSpec.Builder(
            mode.alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(mode.authenticationWindowSeconds, mode.authenticators)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply {
            init(spec)
            generateKey()
        }
        return "Synthetic AES key created; reported backing: ${keySecurityLevel(mode)}."
    }

    fun deleteKeys(): Boolean {
        val store = keyStore
        val hadKeys = VaultKeyMode.entries.any { store.containsAlias(it.alias) }
        VaultKeyMode.entries.forEach { mode ->
            if (store.containsAlias(mode.alias)) store.deleteEntry(mode.alias)
        }
        envelope = null
        return hadKeys
    }

    fun beginEncrypt(mode: VaultKeyMode): Cipher = newCipher(mode, Cipher.ENCRYPT_MODE)

    fun probeEncryptWithoutPrompt(mode: VaultKeyMode): String {
        val discardedCiphertext = beginEncrypt(mode).doFinal(SYNTHETIC_FIXTURE)
        return "Keystore permitted encryption without a new prompt; discarded ${discardedCiphertext.size} bytes."
    }

    fun beginDecrypt(mode: VaultKeyMode): Cipher {
        val savedEnvelope = checkNotNull(envelope) { "Encrypt the synthetic fixture first." }
        check(savedEnvelope.size > HEADER_SIZE + GCM_IV_SIZE) { "Synthetic envelope is incomplete." }
        check(savedEnvelope.copyOfRange(0, HEADER_SIZE).contentEquals(HEADER)) {
            "Synthetic envelope header is invalid."
        }
        val iv = savedEnvelope.copyOfRange(HEADER_SIZE, HEADER_SIZE + GCM_IV_SIZE)
        return newCipher(mode, Cipher.DECRYPT_MODE, iv)
    }

    fun saveEncryptedFixture(cipher: Cipher): String {
        val encrypted = cipher.doFinal(SYNTHETIC_FIXTURE)
        envelope = HEADER + cipher.iv + encrypted
        return "Synthetic fixture encrypted; envelope remains in memory only."
    }

    fun decryptFixture(cipher: Cipher, tampered: Boolean = false): String {
        val savedEnvelope = checkNotNull(envelope) { "Encrypt the synthetic fixture first." }
        val ciphertext = savedEnvelope.copyOfRange(HEADER_SIZE + GCM_IV_SIZE, savedEnvelope.size)
        if (tampered) ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()
        val plaintext = cipher.doFinal(ciphertext)
        check(plaintext.contentEquals(SYNTHETIC_FIXTURE)) { "Decrypted fixture did not match." }
        return if (tampered) {
            "Unexpectedly accepted the modified synthetic envelope."
        } else {
            "Protected decrypt succeeded; synthetic fixture matched."
        }
    }

    private fun newCipher(mode: VaultKeyMode, operation: Int, iv: ByteArray? = null): Cipher {
        val key = keyStore.getKey(mode.alias, null) ?: error("Synthetic AES key is missing.")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            if (operation == Cipher.ENCRYPT_MODE) {
                init(operation, key)
            } else {
                init(operation, key, GCMParameterSpec(GCM_TAG_BITS, checkNotNull(iv)))
            }
        }
    }

    private fun keySecurityLevel(mode: VaultKeyMode): String {
        val key = keyStore.getKey(mode.alias, null) as? javax.crypto.SecretKey ?: return "unknown"
        val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Trusted Environment"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "unknown"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure hardware (level unavailable)" else "software"
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val HEADER_SIZE = 4
        private const val GCM_IV_SIZE = 12
        private const val GCM_TAG_BITS = 128
        private val HEADER = byteArrayOf('S'.code.toByte(), 'V'.code.toByte(), 'K'.code.toByte(), '1'.code.toByte())
        private val SYNTHETIC_FIXTURE = "synthetic local vault fixture v1".toByteArray(Charsets.UTF_8)
    }
}

internal fun authenticateVaultOperation(
    activity: androidx.fragment.app.FragmentActivity,
    mode: VaultKeyMode,
    cipher: Cipher?,
    onAuthorized: (Cipher?) -> Unit,
    onFailure: () -> Unit,
) {
    val useCryptoObject = mode == VaultKeyMode.BIOMETRIC_PER_OPERATION
    val authenticators = if (useCryptoObject) {
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
    val prompt = BiometricPrompt(
        activity,
        androidx.core.content.ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onAuthorized(if (useCryptoObject) result.cryptoObject?.cipher else null)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onFailure()
            }
        },
    )
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Unlock synthetic vault key")
        .setSubtitle("Authenticate to protect a synthetic test fixture")
        .setAllowedAuthenticators(authenticators)
        .apply { if (useCryptoObject) setNegativeButtonText("Cancel") }
        .build()
    try {
        if (useCryptoObject) {
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(checkNotNull(cipher)))
        } else {
            prompt.authenticate(promptInfo)
        }
    } catch (_: Exception) {
        onFailure()
    }
}
