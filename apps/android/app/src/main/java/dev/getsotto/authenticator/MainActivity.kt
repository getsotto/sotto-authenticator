package dev.getsotto.authenticator

import android.os.Bundle
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import java.security.Signature
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val parameters = TotpParameters(
            digits = 8u.toUByte(),
            periodSeconds = 30u,
            algorithm = TotpAlgorithm.SHA1,
        )
        val code = try {
            generateTotpCode(
                secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // gitleaks:allow -- public RFC 6238 Appendix B test vector, not a credential
                unixTimeSeconds = 59L,
                parameters = parameters,
            )
        } catch (_: TotpException) {
            "Could not generate the synthetic code."
        }
        val invalidInputOutcome = try {
            generateTotpCode(
                secretBase32 = "NOT*BASE32",
                unixTimeSeconds = 59L,
                parameters = parameters,
            )
            "Invalid synthetic input was unexpectedly accepted."
        } catch (_: TotpException) {
            "Invalid synthetic input was safely rejected."
        }
        intent.getStringExtra(EXTRA_SYNTHETIC_ENVELOPE)?.let { suppliedEnvelope ->
            snapshotEnvelope = suppliedEnvelope
            decryptSnapshotEnvelope()
        }
        if (intent.getBooleanExtra(EXTRA_ENCRYPT_SYNTHETIC_SNAPSHOT, false)) {
            encryptSnapshotFixture()
        }
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.Top,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text("Sotto Authenticator native spike")
                        if (snapshotStatus != "No snapshot operation has run.") {
                            Text(snapshotStatus)
                        }
                        Text("Synthetic RFC 6238 Appendix B vector")
                        Text("Unix timestamp 59 · 30-second period · 8 digits")
                        Text(code)
                        Text(invalidInputOutcome)
                        Text("Android Keystore authentication experiment")
                        Button(onClick = {
                            status = createKey(KeyAccessMode.BIOMETRIC_PER_OPERATION)
                        }) {
                            Text("Create biometric-only key")
                        }
                        Button(onClick = {
                            status = createKey(KeyAccessMode.BIOMETRIC_OR_CREDENTIAL)
                        }) {
                            Text("Create biometric + device credential key")
                        }
                        Button(onClick = {
                            status = authenticateAndSign(KeyAccessMode.BIOMETRIC_PER_OPERATION)
                        }) {
                            Text("Authenticate and sign (per-operation biometric)")
                        }
                        Button(onClick = {
                            status = authenticateAndSign(KeyAccessMode.BIOMETRIC_OR_CREDENTIAL)
                        }) {
                            Text("Authenticate and sign (5-second fallback window)")
                        }
                        Button(onClick = {
                            status = trySignWithoutPrompt(KeyAccessMode.BIOMETRIC_PER_OPERATION)
                        }) {
                            Text("Probe biometric key without authentication")
                        }
                        Button(onClick = {
                            status = trySignWithoutPrompt(KeyAccessMode.BIOMETRIC_OR_CREDENTIAL)
                        }) {
                            Text("Probe fallback key without authentication")
                        }
                        Button(onClick = {
                            status = if (experiment.deleteKeys()) {
                                "Synthetic keys deleted."
                            } else {
                                "No synthetic keys were present."
                            }
                        }) {
                            Text("Delete synthetic keys")
                        }
                        Text(status)

                        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                        Text("Temporary encrypted snapshot interoperability")
                        Text(
                            "Uses a public synthetic test key. This does not use or wrap the Android Keystore key and is not a backup format.",
                        )
                        OutlinedTextField(
                            value = snapshotEnvelope,
                            onValueChange = { snapshotEnvelope = it },
                            label = { Text("Base64 envelope to paste or transfer") },
                            modifier = Modifier.fillMaxWidth(),
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                autoCorrectEnabled = false,
                            ),
                        )
                        Button(onClick = { encryptSnapshotFixture() }) {
                            Text("Encrypt synthetic snapshot")
                        }
                        Button(onClick = { decryptSnapshotEnvelope() }) {
                            Text("Decrypt pasted envelope")
                        }
                        Text(snapshotStatus, modifier = Modifier.padding(top = 8.dp))

                        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                        Text("Temporary native vault-key experiment")
                        Text(
                            "Uses one synthetic AES key and fixture. The encrypted fixture stays in memory and is discarded on process restart.",
                        )
                        Text(vaultStatus, modifier = Modifier.padding(top = 8.dp))
                        Button(
                            onClick = { useVaultMode(VaultKeyMode.BIOMETRIC_PER_OPERATION) },
                            enabled = !vaultAuthenticationPending,
                        ) {
                            Text("Use per-operation biometric policy")
                        }
                        Button(
                            onClick = { useVaultMode(VaultKeyMode.BIOMETRIC_OR_CREDENTIAL) },
                            enabled = !vaultAuthenticationPending,
                        ) {
                            Text("Use biometric or device-credential policy")
                        }
                        Text("Selected policy: ${vaultMode.name}")
                        Button(onClick = { createVaultKey() }, enabled = !vaultAuthenticationPending) {
                            Text("Create synthetic AES key")
                        }
                        Button(onClick = { encryptVaultFixture() }, enabled = vaultHasKey && !vaultAuthenticationPending) {
                            Text("Authenticate and encrypt fixture")
                        }
                        Button(onClick = { probeVaultEncryptionWithoutPrompt() }, enabled = vaultHasKey && !vaultAuthenticationPending) {
                            Text("Probe encryption without a prompt")
                        }
                        Button(
                            onClick = { authenticateThenProbeVaultWindow() },
                            enabled = vaultHasKey && vaultMode == VaultKeyMode.BIOMETRIC_OR_CREDENTIAL && !vaultAuthenticationPending,
                        ) {
                            Text("Authenticate, then probe the five-second window")
                        }
                        Button(onClick = { decryptVaultFixture() }, enabled = vaultHasKey && vaultEnvelopePresent && !vaultAuthenticationPending) {
                            Text("Authenticate and decrypt fixture")
                        }
                        Button(onClick = { decryptVaultFixture(tampered = true) }, enabled = vaultHasKey && vaultEnvelopePresent && !vaultAuthenticationPending) {
                            Text("Authenticate and reject modified fixture")
                        }
                        Button(onClick = { deleteVaultKey() }, enabled = vaultHasAnyKey && !vaultAuthenticationPending) {
                            Text("Delete synthetic AES key")
                        }
                    }
                }
            }
        }
    }

    private val experiment = KeystoreExperiment()
    private var status by mutableStateOf("No synthetic key has been created.")
    private var snapshotStatus by mutableStateOf("No snapshot operation has run.")
    private var snapshotEnvelope by mutableStateOf("")
    private val vaultExperiment = VaultKeyExperiment()
    private var vaultMode by mutableStateOf(VaultKeyMode.BIOMETRIC_PER_OPERATION)
    private var vaultHasKey by mutableStateOf(vaultExperiment.hasKey(VaultKeyMode.BIOMETRIC_PER_OPERATION))
    private var vaultHasAnyKey by mutableStateOf(vaultExperiment.hasAnyKey())
    private var vaultEnvelopePresent by mutableStateOf(false)
    private var vaultAuthenticationPending by mutableStateOf(false)
    private var vaultStatus by mutableStateOf("No synthetic vault operation has run.")
    private val snapshotTestKey = ByteArray(32) { 0x11 } // gitleaks:allow -- public synthetic interoperability fixture only
    private val snapshotTestNonce = ByteArray(12) { 0x22 } // gitleaks:allow -- public synthetic interoperability fixture only
    private val snapshotFixture = """{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"""

    private fun encryptSnapshotFixture() {
        snapshotStatus = try {
            val envelope = encryptTestSnapshot(snapshotTestKey, snapshotTestNonce, snapshotFixture)
            snapshotEnvelope = Base64.encodeToString(envelope, Base64.NO_WRAP)
            "Synthetic snapshot encrypted. Copy this envelope to iOS and decrypt it there."
        } catch (_: Exception) {
            "Synthetic snapshot encryption failed."
        }
    }

    private fun decryptSnapshotEnvelope() {
        snapshotStatus = try {
            val envelope = Base64.decode(snapshotEnvelope, Base64.DEFAULT)
            val plaintext = decryptTestSnapshot(snapshotTestKey, envelope)
            if (plaintext == snapshotFixture) {
                "Cross-platform synthetic snapshot decrypted and matched."
            } else {
                "Decrypted snapshot did not match the expected synthetic fixture."
            }
        } catch (_: Exception) {
            "Synthetic snapshot was rejected."
        }
    }

    private fun useVaultMode(mode: VaultKeyMode) {
        vaultMode = mode
        vaultHasKey = vaultExperiment.hasKey(mode)
        vaultEnvelopePresent = false
        vaultStatus = "Selected ${mode.name}; create its synthetic key to begin."
    }

    private fun createVaultKey() {
        vaultStatus = try {
            vaultExperiment.createKey(vaultMode).also {
                vaultHasKey = true
                vaultHasAnyKey = vaultExperiment.hasAnyKey()
                vaultEnvelopePresent = false
            }
        } catch (_: Exception) {
            vaultHasKey = false
            vaultHasAnyKey = vaultExperiment.hasAnyKey()
            vaultEnvelopePresent = false
            "Synthetic AES key creation failed. Set a secure device lock and required biometric enrollment."
        }
    }

    private fun encryptVaultFixture() {
        val requestedMode = vaultMode
        if (!vaultHasKey) {
            vaultStatus = "Create the synthetic AES key first."
            return
        }
        val cipher = if (requestedMode == VaultKeyMode.BIOMETRIC_PER_OPERATION) {
            try {
                vaultExperiment.beginEncrypt(requestedMode)
            } catch (_: Exception) {
                vaultStatus = "Synthetic AES key is unavailable or invalidated."
                return
            }
        } else {
            null
        }
        vaultStatus = "Waiting for system authentication."
        authenticateVaultOperationSafely(
            mode = requestedMode,
            cipher = cipher,
            onAuthorized = { authorizedCipher ->
                vaultStatus = try {
                    val operationCipher = authorizedCipher ?: vaultExperiment.beginEncrypt(requestedMode)
                    vaultExperiment.saveEncryptedFixture(operationCipher).also { vaultEnvelopePresent = true }
                } catch (_: Exception) {
                    "Synthetic encryption failed or authentication was unavailable."
                }
            },
            onFailure = { vaultStatus = "System authentication did not authorize encryption." },
        )
    }

    private fun decryptVaultFixture(tampered: Boolean = false) {
        val requestedMode = vaultMode
        if (!vaultHasKey || !vaultEnvelopePresent) {
            vaultStatus = "Create a key and encrypt the synthetic fixture first."
            return
        }
        val cipher = if (requestedMode == VaultKeyMode.BIOMETRIC_PER_OPERATION) {
            try {
                vaultExperiment.beginDecrypt(requestedMode)
            } catch (_: Exception) {
                vaultStatus = "Synthetic encrypted fixture is unavailable."
                return
            }
        } else {
            null
        }
        vaultStatus = "Waiting for system authentication."
        authenticateVaultOperationSafely(
            mode = requestedMode,
            cipher = cipher,
            onAuthorized = { authorizedCipher ->
                vaultStatus = try {
                    val operationCipher = authorizedCipher ?: vaultExperiment.beginDecrypt(requestedMode)
                    vaultExperiment.decryptFixture(operationCipher, tampered)
                } catch (_: AEADBadTagException) {
                    if (tampered) "Modified synthetic fixture rejected by AES-GCM authentication."
                    else "Synthetic decryption failed or authentication was unavailable."
                } catch (_: Exception) {
                    "Synthetic decryption failed or authentication was unavailable."
                }
            },
            onFailure = { vaultStatus = "System authentication did not authorize decryption." },
        )
    }

    private fun probeVaultEncryptionWithoutPrompt() {
        vaultStatus = try {
            vaultExperiment.probeEncryptWithoutPrompt(vaultMode)
        } catch (_: android.security.keystore.UserNotAuthenticatedException) {
            "Android Keystore denied encryption without recent system authentication."
        } catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) {
            "Synthetic key was invalidated. Delete and recreate it."
        } catch (_: Exception) {
            "No-prompt encryption probe was denied or unavailable."
        }
    }

    private fun authenticateThenProbeVaultWindow() {
        val requestedMode = vaultMode
        if (requestedMode != VaultKeyMode.BIOMETRIC_OR_CREDENTIAL || !vaultHasKey) {
            vaultStatus = "Select the fallback policy and create its synthetic key first."
            return
        }
        vaultStatus = "Waiting for system authentication."
        authenticateVaultOperationSafely(
            mode = requestedMode,
            cipher = null,
            onAuthorized = {
                vaultStatus = try {
                    vaultExperiment.probeEncryptWithoutPrompt(requestedMode)
                } catch (_: android.security.keystore.UserNotAuthenticatedException) {
                    "Android Keystore denied no-prompt encryption after authentication."
                } catch (_: Exception) {
                    "Post-authentication no-prompt probe failed."
                }
            },
            onFailure = { vaultStatus = "System authentication did not authorize the probe." },
        )
    }

    private fun authenticateVaultOperationSafely(
        mode: VaultKeyMode,
        cipher: Cipher?,
        onAuthorized: (Cipher?) -> Unit,
        onFailure: () -> Unit,
    ) {
        vaultAuthenticationPending = true
        authenticateVaultOperation(
            activity = this,
            mode = mode,
            cipher = cipher,
            onAuthorized = { authorizedCipher ->
                vaultAuthenticationPending = false
                onAuthorized(authorizedCipher)
            },
            onFailure = {
                vaultAuthenticationPending = false
                onFailure()
            },
        )
    }

    private fun deleteVaultKey() {
        vaultStatus = if (vaultExperiment.deleteKeys()) {
            vaultHasKey = false
            vaultEnvelopePresent = false
            "Synthetic AES keys deleted; in-memory fixture discarded."
        } else {
            "No synthetic AES keys were present."
        }
    }

    private companion object {
        const val EXTRA_SYNTHETIC_ENVELOPE = "dev.getsotto.authenticator.extra.SYNTHETIC_ENVELOPE"
        const val EXTRA_ENCRYPT_SYNTHETIC_SNAPSHOT = "dev.getsotto.authenticator.extra.ENCRYPT_SYNTHETIC_SNAPSHOT"
    }

    private fun createKey(mode: KeyAccessMode): String {
        if (mode == KeyAccessMode.BIOMETRIC_OR_CREDENTIAL &&
            android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R
        ) {
            return "Biometric plus device credential fallback requires Android 11 (API 30) or later."
        }
        return try {
            experiment.createKey(mode)
        } catch (_: Exception) {
            "Could not create synthetic key. Set a secure device lock and, for the biometric-only key, enroll a strong biometric."
        }
    }

    private fun trySignWithoutPrompt(mode: KeyAccessMode): String {
        if (!experiment.hasKey(mode)) return "Create this synthetic key first."
        return try {
            val signature = experiment.newSignature(mode)
            val discardedBytes = experiment.signSyntheticChallenge(signature)
            "Unexpectedly signed without an authentication prompt; discarded $discardedBytes bytes."
        } catch (_: android.security.keystore.UserNotAuthenticatedException) {
            "Android Keystore denied signing without recent system authentication."
        } catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) {
            "Synthetic key was invalidated. Delete and recreate it."
        } catch (_: Exception) {
            "The no-prompt signing probe failed."
        }
    }

    private fun authenticateAndSign(mode: KeyAccessMode): String {
        if (!experiment.hasKey(mode)) return "Create this synthetic key first."
        if (mode == KeyAccessMode.BIOMETRIC_OR_CREDENTIAL &&
            android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R
        ) {
            return "Biometric plus device credential fallback requires Android 11 (API 30) or later."
        }

        val fallbackMode = mode == KeyAccessMode.BIOMETRIC_OR_CREDENTIAL
        val signature = if (fallbackMode) {
            null
        } else {
            try {
                experiment.newSignature(mode)
            } catch (_: Exception) {
                return "Synthetic key is unavailable or invalidated. Delete and recreate it."
            }
        }
        val allowedAuthenticators = if (fallbackMode) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    status = try {
                        val authorizedSignature = if (fallbackMode) {
                            experiment.newSignature(mode)
                        } else {
                            result.cryptoObject?.signature
                        }
                        val bytes = experiment.signSyntheticChallenge(
                            checkNotNull(authorizedSignature) {
                                "Authenticated signing operation was unavailable."
                            },
                        )
                        "Protected signing succeeded; discarded $bytes signature bytes."
                    } catch (_: Exception) {
                        "The protected signing operation failed."
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    status = "Authentication canceled or unavailable."
                }
            },
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign a synthetic test challenge")
            .setSubtitle(if (fallbackMode) {
                "Use a strong biometric or this device’s PIN, pattern, or password"
            } else {
                "Use a strong biometric for this signing operation"
            })
            .setAllowedAuthenticators(allowedAuthenticators)
            .apply {
                if (!fallbackMode) setNegativeButtonText("Cancel")
            }
            .build()

        return try {
            if (fallbackMode) {
                // CryptoObject does not support the device-credential fallback combination.
                // Android Keystore's five-second authorization window still gates signing.
                prompt.authenticate(promptInfo)
            } else {
                prompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(checkNotNull(signature)),
                )
            }
            "Waiting for system authentication."
        } catch (_: Exception) {
            "This device does not support the selected authentication flow."
        }
    }
}
