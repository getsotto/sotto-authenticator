import SwiftUI
import authenticator_bridgeFFI

struct ContentView: View {
    @StateObject private var experiment = ProtectedKeyExperiment()
    @StateObject private var snapshotExperiment = SnapshotInteropExperiment()

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

            Divider()

            Text("Temporary encrypted snapshot interoperability")
                .font(.headline)
            Text("Uses a public synthetic test key. This does not use or wrap the Secure Enclave key and is not a backup format.")
                .multilineTextAlignment(.center)
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("Paste Base64 envelope from Android", text: $snapshotExperiment.envelopeBase64, axis: .vertical)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(2...5)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("snapshot-envelope")
            Button("Encrypt synthetic snapshot") {
                snapshotExperiment.encryptFixture()
            }
            Button("Decrypt pasted envelope") {
                snapshotExperiment.decryptPastedEnvelope()
            }
            Text(snapshotExperiment.status)
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("snapshot-status")
        }
        .padding(24)
    }
}
