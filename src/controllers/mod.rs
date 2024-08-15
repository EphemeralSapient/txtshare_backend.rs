use std::env; // To access senstive information from the .env file

use tokio_postgres::{Client, NoTls, Error};
use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::sync::Mutex; // To safely share the client across async contexts

// Initialize the database connection
pub static DB_CONNECTION: OnceCell<Arc<Mutex<Client>>> = OnceCell::new();

pub async fn init_db_connection(url: String) -> Result<(), Error> {
    let (client, connection) = tokio_postgres::connect(
        &url,
        NoTls,
    )
    .await?;

    // Spawn the connection task
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    // Store the client in a Mutex to allow safe shared access across async contexts
    DB_CONNECTION.set(Arc::new(Mutex::new(client))).unwrap();
    Ok(())
}


tonic::include_proto!("ping");
tonic::include_proto!("auth");
tonic::include_proto!("account");
tonic::include_proto!("txt");

pub mod auth;
pub mod account;
pub mod txt;
pub mod ping;

use tonic::{Request, Response, Status};
