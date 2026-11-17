import SwiftUI
import authenticator_bridgeFFI

struct ContentView: View {
    private let code: String
    private let invalidInputOutcome: String

    init() {
        let parameters = TotpParameters(
            digits: 8,
            periodSeconds: 30,
            algorithm: .sha1
        )

        do {
            code = try generateTotpCode(
                secretBase32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // gitleaks:allow -- public RFC 6238 Appendix B test vector, not a credential
                unixTimeSeconds: 59,
                parameters: parameters
            )
        } catch {
            code = "Could not generate the synthetic code."
        }

        do {
            _ = try generateTotpCode(
                secretBase32: "NOT*BASE32",
                unixTimeSeconds: 59,
                parameters: parameters
            )
            invalidInputOutcome = "Invalid synthetic input was unexpectedly accepted."
        } catch {
            invalidInputOutcome = "Invalid synthetic input was safely rejected."
        }
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Sotto Authenticator native spike")
                .font(.headline)
            Text("Synthetic RFC 6238 Appendix B vector")
            Text("Unix timestamp 59 · 30-second period · 8 digits")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(code)
                .font(.system(.largeTitle, design: .monospaced))
                .accessibilityIdentifier("totp-code")
            Text(invalidInputOutcome)
                .font(.caption)
                .accessibilityIdentifier("totp-safe-error")
        }
        .padding(24)
    }
}
