uniffi::setup_scaffolding!();

/// Returns a fixed message so native clients can prove they called this Rust library.
#[uniffi::export]
pub fn platform_message() -> String {
    "Hello from the shared Rust authenticator core".to_owned()
}

#[cfg(test)]
mod tests {
    use super::platform_message;

    #[test]
    fn returns_the_native_bridge_proof_message() {
        assert_eq!(
            platform_message(),
            "Hello from the shared Rust authenticator core"
        );
    }
}
