// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Regression test for the CBOR `undefined`-vs-`null` bug that broke project creation in
//! production (see `lightbridge_authz_rest::codec`). The TS client's cborg-based CBOR encoder
//! (`converse-frontends/packages/authz-rpc/src/codec.ts`) encodes a JS `undefined` property
//! value as the CBOR `undefined` simple value rather than omitting the key -- the original
//! production incident was the create-project screen never collecting `allowedModels`, so every
//! `createProject` RPC call on the CBOR path (`authz-api`'s production default) sent
//! `{ ..., allowedModels: undefined, ... }` and 400'd with the generic `invalid_argument` /
//! "invalid request payload" error. JSON dev/CI traffic never hit this because
//! `JSON.stringify` drops `undefined`-valued keys entirely, which is why the bug only reproduced
//! in prod.
//!
//! **Retargeted by #415 (ADR-0018 Decision 5):** `Project.allowedModels` is now `@readonly` on
//! `model.Project.create`/`.update` (no runtime-catalogue-check hook on the generic verbs, same
//! reason `Project.projectQuota` already was since #379/#397), so `CreateProjectInput` no longer
//! carries the field at all -- the original reproduction is structurally closed. Its only write
//! path is now `procedure.setProjectAllowedModels`, whose `allowedModels` argument is exactly the
//! same shape (`Json?`) a model-picker clearing its selection could still send as `undefined`, so
//! this test moved there rather than being deleted -- the underlying `LenientCborCodec` behavior
//! it proves is still load-bearing for that new endpoint.

use cratestack_core::CratestackCodec;
use lightbridge_authz_api::schema::procedures::set_project_allowed_models;
use lightbridge_authz_rest::codec::LenientCborCodec;

/// Builds the wire frame a `cborg`-encoding client sends for `setProjectAllowedModels` when
/// `allowedModels` is `undefined` (e.g. a picker with nothing selected) -- the same shape
/// `frontend_frame_with_undefined_allowed_models` used to build for `createProject` before #415.
fn frame_with_undefined_allowed_models() -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = minicbor::Encoder::new(&mut out);
    e.map(1).unwrap();
    e.str("args").unwrap();
    e.map(2).unwrap();
    e.str("projectId").unwrap();
    e.str("abc123def456").unwrap();
    e.str("allowedModels").unwrap();
    e.undefined().unwrap();
    out
}

#[test]
fn lenient_cbor_codec_accepts_undefined_allowed_models() {
    let codec = LenientCborCodec::default();
    let bytes = frame_with_undefined_allowed_models();

    let decoded: set_project_allowed_models::Args = codec
        .decode(&bytes)
        .expect("LenientCborCodec must accept the real frontend wire frame");

    assert_eq!(decoded.args.projectId, "abc123def456");
    assert!(decoded.args.allowedModels.is_none());
}

#[test]
fn raw_cratestack_cbor_codec_still_rejects_undefined_documenting_why_the_wrapper_exists() {
    let codec = cratestack_codec_cbor::CborCodec;
    let bytes = frame_with_undefined_allowed_models();

    let decoded: Result<set_project_allowed_models::Args, _> = codec.decode(&bytes);

    assert!(
        decoded.is_err(),
        "if this starts passing, cratestack-codec-cbor itself now handles `undefined` and \
         LenientCborCodec's normalization pass is no longer needed"
    );
}
