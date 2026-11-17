package dev.getsotto.authenticator

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
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
                            .padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text("Sotto Authenticator native spike")
                        Text("Synthetic RFC 6238 Appendix B vector")
                        Text("Unix timestamp 59 · 30-second period · 8 digits")
                        Text(code)
                        Text(invalidInputOutcome)
                    }
                }
            }
        }
    }
}
