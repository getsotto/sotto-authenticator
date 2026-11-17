import SwiftUI
import authenticator_bridgeFFI

struct ContentView: View {
    @StateObject private var experiment = ProtectedKeyExperiment()

    var body: some View {
        VStack(spacing: 20) {
            Text("iOS protected key experiment")
                .font(.headline)
            Text("Synthetic Secure Enclave P-256 signing key. No account data or key material is displayed.")
                .multilineTextAlignment(.center)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(experiment.status)
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("protected-key-status")
            Button("Create synthetic key") {
                experiment.createTestKey()
            }
            .disabled(experiment.hasTestKey)
            Button("Authenticate and sign test challenge") {
                experiment.signTestChallenge()
            }
            .disabled(!experiment.hasTestKey)
            Button("Delete synthetic key", role: .destructive) {
                experiment.deleteTestKey()
            }
            .disabled(!experiment.hasTestKey)
        }
        .padding(24)
    }
}
