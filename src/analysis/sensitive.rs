//! Recognition of files that must never be proposed for deletion.
//!
//! Bloatrail's cleanup classification is based on *recreatability*, not size.
//! These names identify things that are either irreplaceable (private keys,
//! wallets, databases) or dangerous to lose quietly (credential files). The
//! cleanup executor treats a match as a hard stop, independent of whatever the
//! detectors concluded about the surrounding directory.

use crate::analysis::context::extension_of;

/// Why a path is considered sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// A private key or certificate.
    PrivateKey,
    /// A credential or secrets file.
    Credentials,
    /// A cryptocurrency wallet.
    Wallet,
    /// A local database file.
    Database,
    /// A keychain / password store.
    KeyStore,
}

impl Sensitivity {
    /// Human-readable explanation used in reports.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Sensitivity::PrivateKey => "looks like a private key or certificate",
            Sensitivity::Credentials => "looks like a credentials or secrets file",
            Sensitivity::Wallet => "looks like a cryptocurrency wallet",
            Sensitivity::Database => "looks like a database file",
            Sensitivity::KeyStore => "looks like a keystore or password database",
        }
    }
}

/// Classify a file name, returning `Some` when it must be protected.
///
/// Matching is on the file name only — this function performs no I/O and never
/// reads file contents.
#[must_use]
pub fn classify(name: &str) -> Option<Sensitivity> {
    let lower = name.to_ascii_lowercase();

    // Exact names.
    match lower.as_str() {
        ".env"
        | ".envrc"
        | ".netrc"
        | "_netrc"
        | ".npmrc"
        | ".pypirc"
        | ".dockercfg"
        | "credentials"
        | "secrets.json"
        | "secrets.yaml"
        | "secrets.yml"
        | ".htpasswd"
        | "service-account.json" => return Some(Sensitivity::Credentials),
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "identity" | "server.key" => {
            return Some(Sensitivity::PrivateKey)
        }
        "wallet.dat" | "keystore.json" => return Some(Sensitivity::Wallet),
        "known_hosts" | "authorized_keys" => return Some(Sensitivity::Credentials),
        _ => {}
    }

    // `.env.production`, `.env.local`, …
    if lower.starts_with(".env.") {
        return Some(Sensitivity::Credentials);
    }

    match extension_of(&lower) {
        Some("pem" | "key" | "p12" | "pfx" | "crt" | "cer" | "der" | "asc" | "gpg" | "ppk") => {
            Some(Sensitivity::PrivateKey)
        }
        Some("kdbx" | "keychain" | "jks" | "keystore" | "agilekeychain" | "opvault") => {
            Some(Sensitivity::KeyStore)
        }
        Some("sqlite" | "sqlite3" | "db" | "mdb" | "accdb" | "realm" | "mdf" | "ldf") => {
            Some(Sensitivity::Database)
        }
        Some("wallet") => Some(Sensitivity::Wallet),
        _ => None,
    }
}

/// Whether a *directory* name is one whose contents are always protected.
#[must_use]
pub fn is_protected_directory(name: &str) -> bool {
    matches!(
        name,
        ".ssh" | ".gnupg" | ".gpg" | ".aws" | ".kube" | ".azure" | ".docker" | ".password-store"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files_are_credentials() {
        assert_eq!(classify(".env"), Some(Sensitivity::Credentials));
        assert_eq!(classify(".env.production"), Some(Sensitivity::Credentials));
        assert_eq!(classify(".ENV"), Some(Sensitivity::Credentials));
    }

    #[test]
    fn private_keys_are_detected_by_name_and_extension() {
        assert_eq!(classify("id_rsa"), Some(Sensitivity::PrivateKey));
        assert_eq!(classify("id_ed25519"), Some(Sensitivity::PrivateKey));
        assert_eq!(classify("server.pem"), Some(Sensitivity::PrivateKey));
        assert_eq!(classify("cert.PFX"), Some(Sensitivity::PrivateKey));
    }

    #[test]
    fn databases_and_wallets_are_protected() {
        assert_eq!(classify("app.sqlite3"), Some(Sensitivity::Database));
        assert_eq!(classify("wallet.dat"), Some(Sensitivity::Wallet));
        assert_eq!(classify("vault.kdbx"), Some(Sensitivity::KeyStore));
    }

    #[test]
    fn ordinary_files_are_not_sensitive() {
        for name in [
            "main.rs",
            "video.mp4",
            "notes.md",
            "package.json",
            "keyboard.png",
        ] {
            assert_eq!(classify(name), None, "{name} should not be sensitive");
        }
    }

    #[test]
    fn credential_directories_are_recognised() {
        assert!(is_protected_directory(".ssh"));
        assert!(is_protected_directory(".gnupg"));
        assert!(!is_protected_directory("src"));
    }
}
