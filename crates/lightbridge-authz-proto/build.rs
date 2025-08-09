fn main() {
    tonic_build::compile_protos("proto/api_key_service.proto").unwrap();
}
