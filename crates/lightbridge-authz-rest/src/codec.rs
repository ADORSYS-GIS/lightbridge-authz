//! Lenient CBOR codec: wraps `cratestack_codec_cbor::CborCodec`, normalizing wire-level CBOR
//! `undefined` (simple value 23, `0xf7`) to `null` before handing the frame to the real decoder.
//!
//! `cborg`, the TS client's CBOR encoder (`converse-frontends/packages/authz-rpc/src/codec.ts`),
//! encodes a JS `undefined` property value as CBOR `undefined` rather than omitting the key --
//! unlike `JSON.stringify`, which drops `undefined`-valued keys entirely. `minicbor-serde` treats
//! `undefined` as a distinct CBOR type from `null` and has no mapping for it into `Option<T>`, so
//! an RPC input with an `undefined`-valued optional field (e.g. `CreateProjectInput.allowedModels`
//! when the caller supplies `{ allowedModels: undefined, ... }`) fails to decode with the generic
//! `invalid_argument` / "invalid request payload" error. This reproduces on the CBOR path only --
//! `authz-api`'s production default -- never on the JSON path used in dev/CI, which is why it
//! surfaced only in prod.
//!
//! Rewrites the frame at the token level (`minicbor::decode::Tokenizer` / `minicbor::data::Token`)
//! rather than a byte-level find/replace, so a `0xf7` byte occurring inside a text/byte string's
//! payload is never mistaken for the `undefined` type marker.

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
}
