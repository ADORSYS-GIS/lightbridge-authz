use sha2::{Digest, Sha256};

/// Hashes an API key secret using SHA-256 and returns a hex-encoded digest.
pub fn hash_api_key(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}
