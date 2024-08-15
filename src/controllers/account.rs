
use jsonwebtoken::{decode ,DecodingKey, Validation};

use super::{Request, Response, Status};
use super::DB_CONNECTION as db;
use super::{account_server::Account, AccountDetails, AccountResult, AccountQuery};

#[derive(Debug, Default)]
pub struct AccountService {}

#[tonic::async_trait]
impl Account for AccountService {
    async fn get_details(
        &self,
        request: Request<AccountQuery>,
    ) -> Result<Response<AccountDetails>, Status> {
        let id = request.into_inner().account_id;
        let client: tokio::sync::MutexGuard<tokio_postgres::Client> = db.get().unwrap().lock().await;

        let result = client.query_one("SELECT account_id, username, created FROM accounts WHERE account_id = $1", &[&id]).await;

        if result.is_err() {
            return Err(Status::not_found("Account not found"));
        }

        let account = result.unwrap();

        let txt_files = client.query("SELECT url_code FROM account_files WHERE account_id = $1", &[&id]).await.unwrap();

        let txt_files = txt_files.iter().map(|row| {
            row.get(0)
        }).collect();

        Ok(Response::new( AccountDetails {
            account_id: account.get(0),
            username: account.get(1),
            created: account.get(2),
            txt_files: txt_files,
        }))
    }

    async fn update_details(
        &self,
        request: Request<AccountDetails>,
    ) -> Result<Response<AccountResult>, Status> {
        let token = request.metadata().get("authorization");
        
        if token.is_none() {
            return Err(Status::unauthenticated("Authorization header is required to update the account."));
        }

        let token = token.unwrap();

        let id = &request.get_ref().account_id;
        
        let token = token.to_str().unwrap().split(" ").collect::<Vec<&str>>()[1];

        let decoded = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(std::env::var("JWT_SECRET").unwrap().as_ref()), &Validation::default());

        if decoded.is_err() {
            return Err(Status::unauthenticated("Invalid JWT token."));
        }

        let decoded = decoded.unwrap().claims;
        let decoded = decoded.as_object().unwrap();

        if decoded.get("account_id").unwrap().as_i64().unwrap() as i32 != *id {
            return Err(Status::permission_denied("You are not authorized to update this account."));
        }

        // Checks are done, now updating
        let new_username = &request.get_ref().username;
        let client = db.get().unwrap().lock().await;

        let result = client.query("UPDATE accounts SET username = $1 WHERE account_id = $2", &[&new_username, &id]).await;

        if result.is_err() {
            return Err(Status::internal("Failed to update account."));
        }

        Ok(Response::new(AccountResult {
            message: "Account updated successfully.".to_string(),
            success: true,
        }))
    }

}