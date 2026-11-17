import SwiftUI
import authenticator_bridgeFFI

struct ContentView: View {
    private let rustMessage = platformMessage()

    var body: some View {
        VStack(spacing: 16) {
            Text("Sotto Authenticator native spike")
                .font(.headline)
            Text(rustMessage)
                .accessibilityIdentifier("rust-bridge-message")
        }
        .padding(24)
    }
}
