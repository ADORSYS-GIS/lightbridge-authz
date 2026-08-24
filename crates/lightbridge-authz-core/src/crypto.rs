//! AES-256-GCM sealing for at-rest secrets that must be recoverable, plus the one-way
//! `hash_api_key` digest for secrets that never need to be (contrast the two: `seal`/`open`
//! round-trip a plaintext; `hash_api_key` deliberately cannot).
//!
//! ## The `open()` failure contract every production caller MUST follow
//!
//! No production call site opens a sealed envelope yet -- `federated_identities.token_envelope`
//! (ADR-0024) is written by `KeycloakRelyingParty::persist_federated_identity` today, but nothing
//! reads it back; that lands with ADR-0024's own follow-up 4. This paragraph is the contract
//! the future caller MUST implement, written down now so it isn't rediscovered under pressure
//! later:
//!
//! - Treat any `open()` failure as **"no stored credential"**, never as a request-failing error.
//!   A bad/rotated key, a tampered row, or a stale format must all degrade to "this identity has
//!   no usable stored token" -- exactly like a `None` from a lookup that found nothing.
//! - Log the failure at `warn!` with **at most the AAD components** (`issuer`, `subject`) --
//!   never the ciphertext, never the key, never the underlying decrypt error detail. Those are
//!   exactly the fields [`open`]'s own doc comment already says are safe to have on hand at the
//!   call site (they're required inputs to the call), and nothing else from this module's failure
//!   path is safe to put in a log line.
//!
//! The first real consumer of `open()` owns implementing this contract; `seal`/`open` themselves
//! only guarantee the cryptographic property (wrong key/AAD/ciphertext all fail the same generic
//! way) -- they do not and cannot enforce how a caller reacts to that failure.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Hashes an API key secret using SHA-256 and returns a hex-encoded digest.
pub fn hash_api_key(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Random-nonce length AES-256-GCM uses (96 bits, the size every implementation -- this one
/// included -- treats as mandatory; anything else needs a different construction entirely).
const NONCE_LEN: usize = 12;

/// The one envelope format [`seal`] ever produces and [`open`] ever accepts. A version prefix
/// (not a version *number* encoded some other way) so a future format change can add a `"v2."`
/// case to `open` without breaking `"v1."` rows already at rest -- see that function's own doc
/// comment for why an unrecognized/unopenable envelope must never be treated as "delete this
/// row," only "treat this credential as absent."
const ENVELOPE_PREFIX: &str = "v1.";

/// Seals `plaintext` under `key`, binding it to `aad` so a ciphertext sealed for one `(issuer,
/// subject)` pair can never be swapped onto a different row's envelope column even by someone
/// who already holds `key` -- AES-GCM's associated data is authenticated but not encrypted, and
/// a mismatched `aad` at [`open`] time fails the same way a wrong key does (generic decrypt
/// failure, no further detail). Every caller in this codebase passes
/// `format!("{issuer}\u{1f}{subject}")` as `aad` -- NOT the row id, which can be regenerated
/// without invalidating anything sealed against the stable `(issuer, subject)` identity.
///
/// Output shape: [`ENVELOPE_PREFIX`] followed by the unpadded URL-safe base64 encoding of
/// `nonce (12 bytes) || ciphertext || tag (16 bytes, appended by the AES-GCM implementation
/// itself, not appended separately here)`. A fresh random nonce is drawn from the OS CSPRNG on
/// every call -- callers must never reuse a nonce for the same key, and this function is the only
/// place in the codebase that is allowed to choose one.
pub fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Server("failed to initialize AES-256-GCM cipher".to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::Server("failed to seal payload".to_string()))?;
    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!(
        "{ENVELOPE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope)
    ))
}

/// Opens an envelope [`seal`] produced, verifying it was sealed under the same `key` and `aad`.
///
/// Every failure mode here -- an unrecognized version prefix, invalid base64, a truncated
/// envelope, a wrong `key`, a wrong `aad`, or a tampered ciphertext/tag -- collapses to the same
/// generic [`Error::Server`]. Callers must treat "cannot open" as "no stored credential", never
/// as "corrupt row to be deleted": a rotated [`crate::config::OidcRelyingParty::token_encryption_key`]
/// makes every previously-sealed envelope permanently unopenable by design (there is no key
/// history, ADR-0024's documented rotation posture), and the row is expected to sit inert until
/// the next successful login re-seals it -- open() must never be the thing that decides to erase
/// it.
pub fn open(key: &[u8; 32], aad: &str, sealed: &str) -> Result<Vec<u8>> {
    let encoded = sealed
        .strip_prefix(ENVELOPE_PREFIX)
        .ok_or_else(|| Error::Server("unrecognized envelope version".to_string()))?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Server("envelope is not valid base64url".to_string()))?;
    if envelope.len() < NONCE_LEN {
        return Err(Error::Server(
            "envelope is too short to contain a nonce".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Server("failed to initialize AES-256-GCM cipher".to_string()))?;
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::Server("failed to open sealed payload".to_string()))
}
