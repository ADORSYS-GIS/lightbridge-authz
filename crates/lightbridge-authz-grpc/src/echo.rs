use lightbridge_authz_proto::*;
use tonic::{Request, Response, Status};

/// Implementation of the Echo service
#[derive(Debug, Default)]
pub struct EchoServiceImpl {}

#[tonic::async_trait]
impl echo_service_server::EchoService for EchoServiceImpl {
    async fn echo(
        &self,
        request: Request<EchoRequest>,
    ) -> std::result::Result<Response<EchoResponse>, Status> {
        let req = request.into_inner();
        let message = req.message;

        let reply = EchoResponse { message };

        Ok(Response::new(reply))
    }
}
