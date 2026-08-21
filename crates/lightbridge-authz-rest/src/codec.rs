//! Lenient CBOR codec: wraps `cratestack_codec_cbor::CborCodec`, fixing two independent
//! `null`-representation gaps the raw codec has -- one on decode, one on encode.
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
//! **Encode: `serde_json::Value::Null` mis-encoded as CBOR's empty array (`0x80`), not `null`
//! (`0xf6`), unless `minicbor_serde::Serializer::serialize_unit_as_null` is explicitly enabled.**
//! `serde_json::Value`'s `Serialize` impl routes `Value::Null` through `serializer.serialize_unit()`
//! (not `serialize_none()`), and `minicbor-serde`'s own `serialize_unit()` encodes Rust's `()`
//! (an empty tuple) as CBOR's empty-array marker by default -- confirmed directly against
//! `cratestack-codec-cbor`'s own source and test comments (`optional_none_round_trips_as_cbor_null`
//! there documents the same pitfall, but only for the model-projection decode path it guards; the
//! flag itself is never turned on for `cratestack_codec_cbor::CborCodec` overall).
//!
//! This bit `authz-api`'s `POST /rpc/batch` handling specifically: `cratestack-axum`'s
//! `rpc_batch_dispatch` decodes each frame's `input` into `cratestack_core::rpc::RpcRequest.input:
//! serde_json::Value` (an intentionally opaque carrier -- it doesn't know the target procedure's
//! concrete input type yet), then re-encodes *that* `serde_json::Value` back to bytes
//! (`encode_rpc_value`) before redispatching through the normal per-op decode path. A `null`
//! anywhere inside that value -- e.g. (historically -- see lightbridge-authz#395, which made
//! `expiresAt` required and closed off "no expiry" entirely) `CreateApiKeyInput.expiresAt: null`
//! for "no expiry" -- comes out the other side of that round trip as CBOR's empty array, which
//! then fails to decode into the target field, producing the same generic `invalid_argument` /
//! "invalid request payload" error a `null` gets rejected with today, just for a different reason
//! (required-field enforcement, not this codec bug). This reproduces only through `/rpc/batch`
//! (`converse-frontends` wires `createBatchLink()` into every unary authz RPC call --
//! `apps/self-service/src/app/_layout.tsx` -- so every `createApiKey` call actually takes this
//! path in production) and never through a direct `/rpc/procedure.createApiKey` call, which is why
//! testing the unary endpoint alone did not reproduce the production report that prompted this fix.
//!
//! Fixed by constructing our own `minicbor_serde::Serializer` with `serialize_unit_as_null(true)`
//! rather than delegating to `cratestack_codec_cbor::CborCodec::encode`'s hardcoded
//! `minicbor_serde::to_vec` (which leaves that flag at its default `false`). Safe to flip globally
//! for this codec: nothing else in this codebase's wire types ever serializes a real Rust `()` --
//! `cratestack_core::Value::Null` and `ProjectedValue::Null` both already call `serialize_none()`
//! directly (per `cratestack-codec-cbor`'s own doc comment) and are unaffected by this flag either
//! way.

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
        let mut bytes = Vec::new();
        let mut serializer = minicbor_serde::Serializer::new(&mut bytes);
        serializer.serialize_unit_as_null(true);
        value.serialize(&mut serializer).map_err(|error| {
            CratestackError::Codec(format!("failed to encode CBOR body: {error}"))
        })?;
        Ok(bytes)
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

    /// Documents why `LenientCborCodec::encode` can't delegate to
    /// `cratestack_codec_cbor::CborCodec::encode` (unlike `decode`, which delegates after its own
    /// `undefined`-normalization pass): the raw codec has exactly the bug the test above proves
    /// fixed. If this starts asserting `0xf6`, `cratestack_codec_cbor::CborCodec` has started
    /// enabling `serialize_unit_as_null` itself and `LenientCborCodec::encode`'s custom
    /// `Serializer` construction is no longer needed.
    #[test]
    fn raw_cratestack_cbor_codec_still_mis_encodes_serde_json_null_documenting_why_the_override_exists()
     {
        let bytes = cratestack_codec_cbor::CborCodec
            .encode(&serde_json::Value::Null)
            .expect("encode should succeed");
        assert_eq!(
            bytes,
            vec![0x80],
            "if this starts encoding 0xf6, cratestack_codec_cbor::CborCodec itself now handles \
             serde_json::Value::Null correctly and LenientCborCodec's encode override is no \
             longer needed"
        );
    }
}
