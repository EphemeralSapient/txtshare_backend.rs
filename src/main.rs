use std::env;

use dotenv::dotenv;

mod controllers;

use tonic::transport::Server;
use controllers::{demo_server, auth_server,account_server, txt_server};
use controllers::ping::MyPingService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let postgres_url = env::var("POSTGRES").unwrap();
    let addr = format!("[::1]:{}", env::var("PORT").unwrap_or("4321".to_string())).parse()?; // Hosting the server 

    // Init the postgres connection
    controllers::init_db_connection(postgres_url).await?;


    println!("Server listening on {}", addr);
    Server::builder()  
        .add_service(demo_server::DemoServer::new(MyPingService::default()))
        .add_service(txt_server::TxtServer::new(controllers::txt::TxtService::default()))
        .add_service(auth_server::AuthServer::new(controllers::auth::AuthService::default()))
        .add_service(account_server::AccountServer::new(controllers::account::AccountService::default()))
        .serve(addr)
        .await?;

    Ok(())
}