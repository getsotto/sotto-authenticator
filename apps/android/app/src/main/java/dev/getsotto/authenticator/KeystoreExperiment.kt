package dev.getsotto.authenticator

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal enum class KeyAccessMode(
    val alias: String,
    val authWindowSeconds: Int,
) {
    BIOMETRIC_PER_OPERATION("sotto_spike_biometric_per_use", 0),
    BIOMETRIC_OR_CREDENTIAL("sotto_spike_fallback_window", 5);
}

internal class KeystoreExperiment {
    private val keyStore: KeyStore
        get() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun createKey(mode: KeyAccessMode): String {
        check(mode != KeyAccessMode.BIOMETRIC_OR_CREDENTIAL || Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "Credential fallback requires Android 11 (API 30) or later."
        }

        val store = keyStore
        if (store.containsAlias(mode.alias)) store.deleteEntry(mode.alias)

        val authTypes = when (mode) {
            KeyAccessMode.BIOMETRIC_PER_OPERATION -> KeyProperties.AUTH_BIOMETRIC_STRONG
            KeyAccessMode.BIOMETRIC_OR_CREDENTIAL ->
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        }
        val spec = KeyGenParameterSpec.Builder(
            mode.alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(mode.authWindowSeconds, authTypes)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(
                        if (mode.authWindowSeconds == 0) -1 else mode.authWindowSeconds,
                    )
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
        return keySecurityLevel(mode)
    }

    fun hasKey(mode: KeyAccessMode): Boolean = keyStore.containsAlias(mode.alias)

    fun newSignature(mode: KeyAccessMode): Signature {
        val privateKey = keyStore.getKey(mode.alias, null)
            ?: error("Synthetic key is missing.")
        return Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey as java.security.PrivateKey)
        }
    }

    fun signSyntheticChallenge(signature: Signature): Int {
        signature.update(SYNTHETIC_CHALLENGE)
        return signature.sign().size
    }

    fun deleteKeys(): Boolean {
        val store = keyStore
        val hadKeys = KeyAccessMode.entries.any { mode -> store.containsAlias(mode.alias) }
        KeyAccessMode.entries.forEach { mode ->
            if (store.containsAlias(mode.alias)) store.deleteEntry(mode.alias)
        }
        return hadKeys
    }

    private fun keySecurityLevel(mode: KeyAccessMode): String {
        val privateKey = keyStore.getKey(mode.alias, null) as java.security.PrivateKey
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        val backing = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
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
        return "${mode.name}: key created; reported backing: $backing."
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        val SYNTHETIC_CHALLENGE = "sotto-authenticator-android-spike-v1".toByteArray(Charsets.UTF_8)
    }
}
