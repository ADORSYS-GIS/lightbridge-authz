//! Coverage for `lightbridge_authz_core::crypto::{seal, open}` (ADR-0024): the AES-256-GCM
//! envelope that protects the Keycloak token set at rest on
//! `federated_identities.token_envelope`. No database needed -- these are pure unit tests of the
//! seal/open contract itself.

use lightbridge_authz_core::crypto::{open, seal};

const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];

#[test]
fn seal_open_round_trips_and_rejects_a_wrong_aad() {
    let plaintext = b"super-secret-refresh-value";
    let sealed = seal(&KEY_A, "issuer-a\u{1f}subject-a", plaintext)
        .expect("sealing with a valid 32-byte key must succeed");

    assert!(
        sealed.starts_with("v1."),
        "the envelope must carry the v1. version prefix: got {sealed}"
    );

    let opened = open(&KEY_A, "issuer-a\u{1f}subject-a", &sealed)
        .expect("opening under the same key and AAD must succeed");
    assert_eq!(
        opened, plaintext,
        "opening under the same key and AAD must return the original plaintext"
    );

    let wrong_aad = open(&KEY_A, "issuer-a\u{1f}subject-b", &sealed);
    assert!(
        wrong_aad.is_err(),
        "opening under a different AAD (a different (issuer, subject) pair) must fail, not \
         silently return the plaintext"
    );
}

#[test]
fn open_rejects_a_ciphertext_sealed_under_a_different_key() {
    let plaintext = b"super-secret-refresh-value";
    let aad = "issuer-a\u{1f}subject-a";
    let sealed = seal(&KEY_A, aad, plaintext).expect("sealing under KEY_A must succeed");

    let opened_under_wrong_key = open(&KEY_B, aad, &sealed);
    assert!(
        opened_under_wrong_key.is_err(),
        "a ciphertext sealed under KEY_A must not open under KEY_B -- this is the mechanism a \
         token_encryption_key rotation relies on: an un-openable envelope must fail closed as \
         'no stored token', never panic or silently return garbage"
    );
}
