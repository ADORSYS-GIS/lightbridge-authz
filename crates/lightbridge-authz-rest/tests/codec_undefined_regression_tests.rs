// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Regression test for the CBOR `undefined`-vs-`null` bug that broke project creation in
//! production (see `lightbridge_authz_rest::codec`). The TS client's cborg-based CBOR encoder
//! (`converse-frontends/packages/authz-rpc/src/codec.ts`) encodes a JS `undefined` property
//! value as the CBOR `undefined` simple value rather than omitting the key -- the create-project
//! screen never collects `allowedModels`, so every `createProject` RPC call on the CBOR path
//! (`authz-api`'s production default) sent `{ ..., allowedModels: undefined, ... }` and 400'd with
//! the generic `invalid_argument` / "invalid request payload" error. JSON dev/CI traffic never
//! hit this because `JSON.stringify` drops `undefined`-valued keys entirely, which is why the bug
//! only reproduced in prod.

use cratestack_core::CoolCodec;
use lightbridge_authz_api::schema::inputs::CreateProjectInput;
use lightbridge_authz_rest::codec::LenientCborCodec;

/// Builds the exact wire frame `cborg` produces for a `createProject` call whose
/// `allowedModels` field is `undefined` -- i.e. what the real frontend sends today
/// (`packages/hooks/src/projects.ts::buildCreateProjectInput`/`tagProjectJsonFields`).
fn frontend_frame_with_undefined_allowed_models() -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = minicbor::Encoder::new(&mut out);
    // Seven fields, not six: ADR-0006 moved `billingIdentity` from `Account` onto `Project` and it
    // is non-optional there, so the real frontend now sends it on every create (added in
    // `buildCreateProjectInput` alongside the optional `projectQuota`, which stays omitted here —
    // it is nullable, so its absence is not what this regression is about).
    e.map(7).unwrap();
    e.str("id").unwrap();
    e.str("abc123def456").unwrap();
    e.str("accountId").unwrap();
    e.str("go17t93z1vbd99yl5toj7eu5").unwrap();
    e.str("name").unwrap();
    e.str("demo").unwrap();
    e.str("allowedModels").unwrap();
    e.undefined().unwrap();
    e.str("defaultLimits").unwrap();
    e.map(1).unwrap();
    e.str("Map").unwrap();
    e.map(0).unwrap();
    e.str("billingPlan").unwrap();
    e.str("free").unwrap();
    e.str("billingIdentity").unwrap();
    e.str("acme-corp").unwrap();
    out
}

#[test]
fn lenient_cbor_codec_accepts_undefined_allowed_models() {
    let codec = LenientCborCodec::default();
    let bytes = frontend_frame_with_undefined_allowed_models();

    let decoded: CreateProjectInput = codec
        .decode(&bytes)
        .expect("LenientCborCodec must accept the real frontend wire frame");

    assert_eq!(decoded.name, "demo");
    assert!(decoded.allowedModels.is_none());
}

#[test]
fn raw_cratestack_cbor_codec_still_rejects_undefined_documenting_why_the_wrapper_exists() {
    let codec = cratestack_codec_cbor::CborCodec;
    let bytes = frontend_frame_with_undefined_allowed_models();

    let decoded: Result<CreateProjectInput, _> = codec.decode(&bytes);

    assert!(
        decoded.is_err(),
        "if this starts passing, cratestack-codec-cbor itself now handles `undefined` and \
         LenientCborCodec's normalization pass is no longer needed"
    );
}
