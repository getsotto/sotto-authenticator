package dev.getsotto.authenticator

import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import java.security.Signature

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
                    }
                }
            }
        }
    }

    private val experiment = KeystoreExperiment()
    private var status by mutableStateOf("No synthetic key has been created.")

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
