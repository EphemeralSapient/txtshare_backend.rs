use super::{Request, Response, Status};

use super::{demo_server::Demo, PingReq, PongResp}; 

#[derive(Debug, Default)]
pub struct MyPingService {} 

#[tonic::async_trait]
impl Demo for MyPingService {
    async fn ping(
        &self,
        request: Request<PingReq>,
    ) -> Result<Response<PongResp>, Status> {

        let reply = PongResp {
            message: format!("Pong {}!", request.into_inner().message),
        };

        Ok(Response::new(reply))
    }
}
