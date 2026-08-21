//! Lenient CBOR codec: wraps `cratestack_codec_cbor::CborCodec` to normalize wire-level
//! `undefined` to `null` on decode.
//!
//! **Decode: wire-level `undefined` (simple value 23, `0xf7`) normalized to `null`.**
//! `cborg`, the TS client's CBOR encoder (`converse-frontends/packages/authz-rpc/src/codec.ts`),
//! encodes a JS `undefined` property value as CBOR `undefined` rather than omitting the key --
//! unlike `JSON.stringify`, which drops `undefined`-valued keys entirely. `minicbor-serde` treats
//! `undefined` as a distinct CBOR type from `null` and has no mapping for it into `Option<T>`, so
//! an RPC input with an `undefined`-valued optional field (originally reproduced on
//! `CreateProjectInput.allowedModels` when the caller supplied `{ allowedModels: undefined, ... }`
//! -- since #415/ADR-0018 that field moved to `SetProjectAllowedModelsInput.allowedModels`, same
//! shape, see `codec_undefined_regression_tests.rs`) fails to decode with the generic
//! `invalid_argument` / "invalid request payload" error. This reproduces on the CBOR path only --
//! `authz-api`'s production default -- never on the JSON path used in dev/CI, which is why it
//! surfaced only in prod.
//!
//! Rewrites the frame at the token level (`minicbor::decode::Tokenizer` / `minicbor::data::Token`)
//! rather than a byte-level find/replace, so a `0xf7` byte occurring inside a text/byte string's
//! payload is never mistaken for the `undefined` type marker.
//!
//! **Encode: no longer overridden here.** Until cratestack 0.8.6 this module also worked around a
//! second, independent gap: `serde_json::Value::Null` mis-encoded as CBOR's empty array (`0x80`),
//! not `null` (`0xf6`), because `cratestack_codec_cbor::CborCodec::encode` built its
//! `minicbor_serde::Serializer` without `serialize_unit_as_null(true)`. Upstream fixed this
//! directly in `CborCodec::encode` itself (cratestack commit
//! [`2c0f4676`](https://github.com/cratestack/cratestack/commit/2c0f4676), PR
//! [cratestack/cratestack#675](https://github.com/cratestack/cratestack/pull/675), closing
//! cratestack/cratestack#657) -- confirmed by reading the released 0.8.6 source, not just the
//! changelog: it now constructs the exact same `minicbor_serde::Serializer` with
//! `serialize_unit_as_null(true)` this module used to build by hand. `LenientCborCodec::encode`
//! therefore just delegates to the wrapped codec now; see
//! `serde_json_null_encodes_as_cbor_null_not_empty_array` below for the byte-level (`0xf6`, not
//! `0x80`) proof that the delegated behavior is still correct.

use cratestack_core::{CratestackCodec, CratestackError};
use minicbor::data::Token;
use minicbor::encode::Encode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct LenientCborCodec(cratestack_codec_cbor::CborCodec);

impl CratestackCodec for LenientCborCodec {
    const CONTENT_TYPE: &'static str =
        <cratestack_codec_cbor::CborCodec as CratestackCodec>::CONTENT_TYPE;

    fn encode<T: Serialize + ?Sized>(&self, value: &T) -> Result<Vec<u8>, CratestackError> {
        self.0.encode(value)
    }

    fn decode<T: for<'de> Deserialize<'de>>(&self, bytes: &[u8]) -> Result<T, CratestackError> {
        self.0.decode(&normalize_undefined_to_null(bytes)?)
    }
}

/// Re-encodes `bytes` with every `undefined` token replaced by `null`. Cheap no-op (returns the
/// input unchanged, no tokenize/re-encode pass) when no `0xf7` byte is present at all.
fn normalize_undefined_to_null(bytes: &[u8]) -> Result<Vec<u8>, CratestackError> {
    if !bytes.contains(&0xf7) {
        return Ok(bytes.to_vec());
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut encoder = minicbor::Encoder::new(&mut out);
    for token in minicbor::decode::Tokenizer::new(bytes) {
        let token = token.map_err(|error| {
            CratestackError::Codec(format!("failed to decode CBOR body: {error}"))
        })?;
        let token = if matches!(token, Token::Undefined) {
            Token::Null
        } else {
            token
        };
        token.encode(&mut encoder, &mut ()).map_err(|error| {
            CratestackError::Codec(format!("failed to re-encode CBOR body: {error}"))
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "camelCase")]
    struct Input {
        name: String,
        allowed_models: Option<Vec<String>>,
    }

    fn frame_with(
        allowed_models_token: impl FnOnce(&mut minicbor::Encoder<&mut Vec<u8>>),
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = minicbor::Encoder::new(&mut out);
        e.map(2).unwrap();
        e.str("name").unwrap();
        e.str("demo").unwrap();
        e.str("allowedModels").unwrap();
        allowed_models_token(&mut e);
        out
    }

    #[test]
    fn undefined_field_decodes_as_none() {
        let bytes = frame_with(|e| {
            e.undefined().unwrap();
        });
        let codec = LenientCborCodec::default();
        let decoded: Input = codec
            .decode(&bytes)
            .expect("undefined should normalize to null");
        assert_eq!(
            decoded,
            Input {
                name: "demo".to_owned(),
                allowed_models: None,
            }
        );
    }

    #[test]
    fn null_field_still_decodes_as_none() {
        let bytes = frame_with(|e| {
            e.null().unwrap();
        });
        let codec = LenientCborCodec::default();
        let decoded: Input = codec.decode(&bytes).expect("null should still decode");
        assert_eq!(
            decoded,
            Input {
                name: "demo".to_owned(),
                allowed_models: None,
            }
        );
    }

    #[test]
    fn present_field_still_decodes() {
        let bytes = frame_with(|e| {
            e.array(1).unwrap();
            e.str("gpt-4").unwrap();
        });
        let codec = LenientCborCodec::default();
        let decoded: Input = codec.decode(&bytes).expect("present array should decode");
        assert_eq!(
            decoded,
            Input {
                name: "demo".to_owned(),
                allowed_models: Some(vec!["gpt-4".to_owned()]),
            }
        );
    }

    #[test]
    fn byte_0xf7_inside_a_byte_string_is_not_mistaken_for_undefined() {
        // 0xf7 is not valid inside a UTF-8 text string, but it can appear as data inside a byte
        // string payload. Exercises `normalize_undefined_to_null` directly (rather than round-
        // tripping through `serde`, which has its own bytes-vs-array mapping quirks unrelated to
        // this codec) to confirm the tokenizer-based rewrite leaves payload bytes untouched --
        // a byte-level find/replace of 0xf7 would have corrupted this frame.
        let mut original = Vec::new();
        let mut e = minicbor::Encoder::new(&mut original);
        e.map(1).unwrap();
        e.str("data").unwrap();
        e.bytes(&[0x01, 0xf7, 0x02]).unwrap();

        let normalized = normalize_undefined_to_null(&original).expect("normalize should succeed");
        assert_eq!(
            normalized, original,
            "byte string payload must round-trip byte-for-byte"
        );
    }

    /// Historical note: a *direct* decode of an explicit `null` `expiresAt` for `createApiKey` was
    /// never actually broken by the `undefined`/empty-array bug this module fixes -- that bug was
    /// on *encode*, one hop further downstream, and only reachable through `POST /rpc/batch` (see
    /// this module's doc comment and
    /// `rpc_it_tests.rs::batch_create_api_key_rejects_real_cborg_null_expires_at_bytes` for the
    /// full mechanism). This test used to prove exactly that: a direct decode of `expiresAt: null`
    /// succeeded, landing as `None`.
    ///
    /// Since lightbridge-authz#395 made `expiresAt` a *required* (non-nullable) field on
    /// `CreateApiKeyInput` -- every API key must carry an expiry now, no more "no expiry" -- the
    /// correct outcome for the identical bytes flipped: `Option<T>: Deserialize` no longer applies
    /// (the field is a plain `chrono::DateTime<Utc>`, not `Option<..>`), so a `null` value must now
    /// fail to decode. Kept as a permanent regression test with the assertion flipped, for the same
    /// "a future change quietly reopening the hole" reason `rpc_it_tests.rs`'s companion tests were
    /// flipped rather than deleted.
    #[test]
    fn explicit_null_expires_at_fails_to_decode_for_create_api_key_input() {
        use lightbridge_authz_api::schema::types::CreateApiKeyInput;

        let mut bytes = Vec::new();
        let mut e = minicbor::Encoder::new(&mut bytes);
        e.map(4).unwrap();
        e.str("name").unwrap();
        e.str("Miaou").unwrap();
        e.str("expiresAt").unwrap();
        e.null().unwrap();
        e.str("projectId").unwrap();
        e.str("zezxvt21irmoi0kzm22el7gu").unwrap();
        e.str("billingPlan").unwrap();
        e.str("free").unwrap();

        let codec = LenientCborCodec::default();
        let result: Result<CreateApiKeyInput, _> = codec.decode(&bytes);
        assert!(
            result.is_err(),
            "a null expiresAt must fail to decode now that the field is required \
             (lightbridge-authz#395), got: {result:?}"
        );
    }

    /// The actual root cause, in isolation: `serde_json::Value::Null` must encode as CBOR `null`
    /// (`0xf6`), not CBOR's empty array (`0x80`). `RpcRequest.input` (`cratestack_core::rpc`) is
    /// typed `serde_json::Value` -- an intentionally opaque carrier for `/rpc/batch`'s per-frame
    /// re-encode step (`cratestack-axum`'s `rpc_batch_dispatch`/`encode_rpc_value`) -- so any
    /// `null` inside a batched call's input (e.g. `createApiKey`'s `expiresAt: null`) passes
    /// through exactly this encode path before being redispatched and decoded a second time.
    #[test]
    fn serde_json_null_encodes_as_cbor_null_not_empty_array() {
        let codec = LenientCborCodec::default();
        let bytes = codec
            .encode(&serde_json::Value::Null)
            .expect("encode should succeed");
        assert_eq!(
            bytes,
            vec![0xf6],
            "must be CBOR null, not empty array (0x80)"
        );
    }

    /// Regression guard for the fix moving upstream. Until cratestack 0.8.6,
    /// `cratestack_codec_cbor::CborCodec::encode` had exactly the `0x80`-not-`0xf6` bug the test
    /// above used to prove `LenientCborCodec::encode`'s now-removed override fixed. Cratestack
    /// commit [`2c0f4676`](https://github.com/cratestack/cratestack/commit/2c0f4676)
    /// (`cratestack/cratestack#675`, closing `#657`) fixed it directly in the raw codec, which is
    /// why `LenientCborCodec::encode` now just delegates (see this module's doc comment). If this
    /// ever starts asserting `0x80` again, the raw codec has regressed and
    /// `LenientCborCodec::encode` needs its `serialize_unit_as_null(true)` override back.
    #[test]
    fn raw_cratestack_cbor_codec_now_correctly_encodes_serde_json_null_as_cbor_null() {
        let bytes = cratestack_codec_cbor::CborCodec
            .encode(&serde_json::Value::Null)
            .expect("encode should succeed");
        assert_eq!(
            bytes,
            vec![0xf6],
            "cratestack_codec_cbor::CborCodec (>=0.8.6) must encode serde_json::Value::Null as \
             CBOR null (0xf6), not the empty array (0x80) it used to mis-encode before the \
             upstream fix -- LenientCborCodec::encode relies on this by delegating directly"
        );
    }
}
