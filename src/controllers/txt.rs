
use time::{Duration, PrimitiveDateTime};
use jsonwebtoken::{ DecodingKey, decode, Validation};
use sha2::{Sha256, Digest};

use super::{Request, Response, Status};
use super::DB_CONNECTION as db;
use super::{txt_server::Txt, UploadRequest, FileDetail, TxtResult, TxtUrl, TxtUpdate, TxtResultState};

fn generate_random_string(length: usize) -> String {
    const CHARACTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut result = String::new();
    let characters_length = CHARACTERS.len();
    
    for _ in 0..length {
        let index = rand::random::<usize>() % characters_length;
        result.push(CHARACTERS.chars().nth(index).unwrap());
    }
    
    result
}

async fn delete_file(url_code: &String,id: &String, single : bool) {

    let client = db.get().unwrap().lock().await;
    if single {
        client.query("DELETE FROM files WHERE commit_id = $1", &[&id]).await.unwrap();
    } else {
        let result = client.query("SELECT commit_id FROM file_data WHERE url_code = $1", &[&url_code]).await.unwrap();

        if result.is_empty() {
            return;
        }

        for row in result {
            let commit_id: String = row.get("commit_id");
            client.query("DELETE FROM files WHERE commit_id = $1", &[&commit_id]).await.unwrap();
        }
    }
}

#[derive(Debug, Default)]
pub struct TxtService {}

#[tonic::async_trait]
impl Txt for TxtService {
    async fn get(&self, req: Request<TxtUrl>) -> Result<Response<TxtResult>, Status> {
        let url_code = &req.get_ref().url_code;
        // Check if urlCode is suplied or not [length should be above 7 chars]
        if url_code.len() != 7 {
            return Err(Status::invalid_argument("urlCode is required and within range of 7 characters."));
        }


        let client = db.get().unwrap().lock().await;
        
        let result = client.query_one("SELECT * FROM url_lookup WHERE url_code = $1", &[&url_code]).await;
        
        drop(client);

        if result.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let url_lookup = result.unwrap();
        // Obtianed the url_lookup record

        let commit_id: String = url_lookup.get("head");
        let count:i32 = url_lookup.get("changes_counts");

        // Check if the file is expired or not [UTC]
        let expire: PrimitiveDateTime = url_lookup.get("expire");
        let current_utc = time::OffsetDateTime::now_utc();
        if current_utc > expire.assume_utc() {
            delete_file(&url_code, &commit_id, count==1).await;
            return Err(Status::unavailable("File has been expired."));
        }
        
        // Password check
        let txt_password: Option<String> = url_lookup.get("pass");
        if let Some(pass) = txt_password {
            // Verify for password header
            let password = req.metadata().get("password");

            if password.is_none() {
                return Err(Status::unauthenticated("Password protected file."));
            }
            
            let password = password.unwrap();

            // Convert it to sha-256 hash
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());

            let hash = hasher.finalize();
            
            // Converting hash to string in hex
            let hash_str = format!("{:x}", hash);
            
            if hash_str != pass {
                return Err(Status::unauthenticated("Password protected file."));
            }
        }

        let client = db.get().unwrap().lock().await;

        let file_data = client.query_one("SELECT * FROM file_data WHERE commit_id = $1", &[&commit_id]).await;
        let file_txt = client.query_one("SELECT txt FROM files WHERE commit_id = $1", &[&commit_id]).await;

        if file_data.is_err() || file_txt.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let file_data = file_data.unwrap();
        let file_txt = file_txt.unwrap();

        
        //expire and created are timestamp in postgres
        let created: PrimitiveDateTime = file_data.get("created");
        
        // Linked account id can be null
        let linked_account_id: Option<i32> = file_data.get("linked_account_id");

        let txt_result = TxtResult {
            url_code: url_lookup.get("url_code"),            
            file_txt: file_txt.get("txt"),
            file_detail: Some(FileDetail {
                burn: file_data.get("burn"),
                category: file_data.get("category"),
                expire: expire.to_string(),
                r#type: file_data.get("type"),
                created: created.to_string(),
                linked_account_id: linked_account_id,
                commit_id: file_data.get("commit_id"),
                // ..Default::default()
            }),
            // ..Default::default()
        };

        Ok(Response::new(txt_result))
    }

    async fn delete(&self, req: Request<TxtUrl>) -> Result<Response<TxtResultState>, Status> {
        let url_code = &req.get_ref().url_code;
        // Check if urlCode is suplied or not [length should be above 7 chars]
        if url_code.len() != 7 {
            return Err(Status::invalid_argument("urlCode is required and within range of 7 characters."));
        }


        let client = db.get().unwrap().lock().await;
        
        let result = client.query_one("SELECT * FROM url_lookup WHERE url_code = $1", &[&url_code]).await;
        
        drop(client);

        if result.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let url_lookup = result.unwrap();
        // Obtianed the url_lookup record

        let commit_id: String = url_lookup.get("head");
        let count:i32 = url_lookup.get("changes_counts");

        // Check if the file is expired or not [UTC]
        let expire: PrimitiveDateTime = url_lookup.get("expire");
        let current_utc = time::OffsetDateTime::now_utc();
        if current_utc > expire.assume_utc() {
            delete_file(&url_code, &commit_id, count==1).await;
            return Err(Status::unavailable("File has been expired."));
        }

        // Validate the token
        let token = req.metadata().get("authorization");
        if token.is_none() {
            return Err(Status::unauthenticated("Authorization token is required."));
        }

        let token = token.unwrap().to_str().unwrap().to_string().replace("Bearer ", "");
        // Using jsonwebtoken to verify the token

        let secret = std::env::var("JWT_SECRET").unwrap();

        let token = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default());

        if token.is_err() {
            return Err(Status::unauthenticated("Invalid token."));
        }

        let token = token.unwrap();
        let token = token.claims.as_object().unwrap();

        // Checking if token's account id is same as the linked account id
        let account_id = token.get("id").unwrap().as_i64().unwrap() as i32;
        let client = db.get().unwrap().lock().await;
        let file_data = client.query_one("SELECT linked_account_id FROM file_data WHERE commit_id = $1", &[&commit_id]).await;

        if file_data.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let file_data = file_data.unwrap();
        let linked_account_id: Option<i32> = file_data.get("linked_account_id");

        // Trying to perform delete operation on guest file is not allowed
        if linked_account_id.is_none() {
            return Err(Status::unauthenticated("Unauthorized access."));
        }

        let linked_account_id = linked_account_id.unwrap();
        if linked_account_id != account_id {
            return Err(Status::unauthenticated("Unauthorized access."));
        }

        // Delete the file since access is granted.
        delete_file(&url_code, &commit_id, count==1).await;
        Ok(Response::new(TxtResultState {
            message: "File has been deleted.".to_string(),
            success: true,
        }))
    }

    async fn upload(&self, req: Request<UploadRequest>) -> Result<Response<TxtResult>, Status> {

        let token = req.metadata().get("authorization");
        let secret = std::env::var("JWT_SECRET").unwrap();

        // Suppose token is supplied, validate it
        if token.is_none() == false {
            let token = token.unwrap().to_str().unwrap().to_string().replace("Bearer ", "");
            // Using jsonwebtoken to verify the token
    
            let token = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default());
    
            if token.is_err() {
                return Err(Status::unauthenticated("Invalid token."));
            }
        }

        let file_data = &req.get_ref().file_data;
        let file_name = &req.get_ref().file_name;
        let password = &req.get_ref().password;
        let category = &req.get_ref().category;
        let file_type = &req.get_ref().file_type;
        let expire = &req.get_ref().expire;

        // Check if fileData is suplied or not 
        if file_data.len() == 0  {
            return Err(Status::invalid_argument("fileData is required."));
        }
        // Check if file name is suplied or not 
        if file_name.len() == 0 {
            return Err(Status::invalid_argument("fileName is required."));
        }

        // Length check
        if file_name.len() > 30 || password.len() > 30 || category.len() > 30 || file_type.len() > 30 {
            return Err(Status::invalid_argument("Field should not exceed 30 characters."));
        }

        // Default value in case of nothing
        let category = if category.len() == 0 { "None".to_string() } else { category.to_string() };
        let file_type = if file_type.len() == 0 { "None".to_string() } else { file_type.to_string() };
        let expire = if expire.len() == 0 { "hour".to_string() } else { expire.to_string() };

        // Checking expire value to be within type
        if expire != "once" && expire != "hour" && expire != "day" && expire != "week" && expire != "month" && expire != "year" {
            return Err(Status::invalid_argument("Invalid value for field expire. Allowed values are: once, hour, day, week, month, year"));
        }

        // Check if file_data memory size to be within {limit} kb
        let file_data_size_limit = std::env::var("MAX_TXT_SIZE_KB");
        // env var can be null, default will be 512 kb 
        let file_data_size_limit = if file_data_size_limit.is_err() { 512 } else { file_data_size_limit.unwrap().parse::<usize>().unwrap() };

        if file_data.len() > file_data_size_limit {
            return Err(Status::invalid_argument("File size exceeds the allowed limit."));
        }

        // Validated the inputs, now processing 

        // Hash the fileData with TimeStamp of now [commit_id]
        let commit_id = format!("{:x}", Sha256::digest(file_data.as_bytes()));
        let url_code = generate_random_string(7);

        // Hashing the password if supplied
        let pass = if password.len() == 0 { None } else { Some(format!("{:x}",
            Sha256::digest(password.as_bytes()))) };
        
        // Generate the expiry timestamp
        let mut expiry = time::OffsetDateTime::now_utc();
        if expire == "hour" {
            expiry += Duration::hours(1);
        } else if expire == "day" {
            expiry += Duration::days(1);
        } else if expire == "week" {
            expiry += Duration::weeks(1);
        } else if expire == "month" {
            expiry += Duration::weeks(1 * 4);
        } else {
            expiry += Duration::weeks(1 * 4 * 12);
        }

        let expiry = time::PrimitiveDateTime::new(expiry.date(), expiry.time());

        // Adding the data into the database
        let client = db.get().unwrap().lock().await;

        let result = client.query("INSERT INTO files (commit_id, txt) VALUES ($1, $2)", &[&commit_id, &file_data]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        let result = client.query("INSERT INTO file_data (url_code, commit_id ,expire, type, category, burn) VALUES ($1, $2, $3, $4, $5, $6)", 
            &[&url_code, &commit_id, &expiry, &file_type, &category, &(expire == "once")]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        let result = client.query("INSERT INTO url_lookup (url_code, head, expire, pass) VALUES ($1, $2, $3, $4)", 
            &[&url_code, &commit_id, &expiry, &pass]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        // Null value in case of nothing
        let mut linked_account = -1;
        // Update account details [if authenticated] for count and url
        if token.is_some() {
            let token = token.unwrap().to_str().unwrap().to_string().replace("Bearer ", "");
            let token = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).unwrap();
            let token = token.claims.as_object().unwrap();
            let account_id = token.get("id").unwrap().as_i64().unwrap() as i32;

            linked_account = account_id;

            client.query("INSERT INTO account_files (account_id, url_code) VALUES ($1, $2)", &[&account_id, &url_code]).await.unwrap();
        }

        Ok(Response::new(TxtResult{
            url_code: url_code,
            file_txt: file_data.to_string(),
            file_detail: Some(FileDetail {
                burn: expire == "once",
                category: category,
                expire: expiry.to_string(),
                r#type: file_type,
                created: time::OffsetDateTime::now_utc().to_string(),
                linked_account_id: Some(linked_account),  
                commit_id: commit_id,
            }),
        }))
    }

    async fn update(&self, req: Request<TxtUpdate>) -> Result<Response<TxtResult>, Status> {
        let url_code = &req.get_ref().url_code;
        let token = req.metadata().get("authorization");
        let secret = std::env::var("JWT_SECRET").unwrap();

        if token.is_none() {
            return Err(Status::unauthenticated("Authorization token is required."));
        }

        let token = token.unwrap().to_str().unwrap().to_string().replace("Bearer ", "");

        // Using jsonwebtoken to verify the token
        let token = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default());

        if token.is_err() {
            return Err(Status::unauthenticated("Invalid token."));
        }

        let token = token.unwrap();
        let token = token.claims.as_object().unwrap();

        // Checking if token's account id is same as the linked account id
        let account_id = token.get("id").unwrap().as_i64().unwrap() as i32;
        let client = db.get().unwrap().lock().await;

        let result = client.query_one("SELECT * FROM url_lookup WHERE url_code = $1", &[&url_code]).await;
        if result.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let url_lookup = result.unwrap();
        let commit_id: String = url_lookup.get("head");
        
        // File data for given commit_id
        let file_data = client.query_one("SELECT * FROM file_data WHERE commit_id = $1", &[&commit_id]).await;

        if file_data.is_err() {
            return Err(Status::not_found("No record found for the given urlCode."));
        }

        let file_data = file_data.unwrap();
        let linked_account_id: Option<i32> = file_data.get("linked_account_id");

        // Checking if linked account id is null or does not match
        if linked_account_id.is_none() || linked_account_id.unwrap() != account_id {
            return Err(Status::unauthenticated("Unauthorized access."));
        }

        drop(client);
        // Same as upload, just updating the file
        let new_details = &req.get_ref().new_details;
        let new_details = new_details.as_ref().unwrap();
        let file_data = &new_details.file_data;
        let file_name = &new_details.file_name;
        let password = &new_details.password;
        let category = &new_details.category;
        let file_type = &new_details.file_type;
        let expire = &new_details.expire;

        // Check if fileData is suplied or not 
        if file_data.len() == 0  {
            return Err(Status::invalid_argument("fileData is required."));
        }
        // Check if file name is suplied or not 
        if file_name.len() == 0 {
            return Err(Status::invalid_argument("fileName is required."));
        }

        // Length check
        if file_name.len() > 30 || password.len() > 30 || category.len() > 30 || file_type.len() > 30 {
            return Err(Status::invalid_argument("Field should not exceed 30 characters."));
        }

        // Default value in case of nothing
        let category = if category.len() == 0 { "None".to_string() } else { category.to_string() };
        let file_type = if file_type.len() == 0 { "None".to_string() } else { file_type.to_string() };
        let expire = if expire.len() == 0 { "hour".to_string() } else { expire.to_string() };

        // Checking expire value to be within type
        if expire != "once" && expire != "hour" && expire != "day" && expire != "week" && expire != "month" && expire != "year" {
            return Err(Status::invalid_argument("Invalid value for field expire. Allowed values are: once, hour, day, week, month, year"));
        }

        // Check if file_data memory size to be within {limit} kb
        let file_data_size_limit = std::env::var("MAX_TXT_SIZE_KB");
        // env var can be null, default will be 512 kb 
        let file_data_size_limit = if file_data_size_limit.is_err() { 512 } else { file_data_size_limit.unwrap().parse::<usize>().unwrap() };

        if file_data.len() > file_data_size_limit {
            return Err(Status::invalid_argument("File size exceeds the allowed limit."));
        }

        // Validated the inputs, now processing 

        // Hash the fileData with TimeStamp of now [commit_id]
        let commit_id = format!("{:x}", Sha256::digest(file_data.as_bytes()));
        let url_code = generate_random_string(7);

        // Hashing the password if supplied
        let pass = if password.len() == 0 { None } else { Some(format!("{:x}",
            Sha256::digest(password.as_bytes()))) };
        
        // Generate the expiry timestamp
        let mut expiry = time::OffsetDateTime::now_utc();
        if expire == "hour" {
            expiry += Duration::hours(1);
        } else if expire == "day" {
            expiry += Duration::days(1);
        } else if expire == "week" {
            expiry += Duration::weeks(1);
        } else if expire == "month" {
            expiry += Duration::weeks(1 * 4);
        } else {
            expiry += Duration::weeks(1 * 4 * 12);
        }

        let expiry = time::PrimitiveDateTime::new(expiry.date(), expiry.time());

        // Adding the data into the database
        let client = db.get().unwrap().lock().await;

        let result = client.query("INSERT INTO files (commit_id, txt) VALUES ($1, $2)", &[&commit_id, &file_data]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        let result = client.query("INSERT INTO file_data (url_code, commit_id ,expire, type, category, burn) VALUES ($1, $2, $3, $4, $5, $6)", 
            &[&url_code, &commit_id, &expiry, &file_type, &category, &(expire == "once")]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        // Updating url_lookup
        let result = client.query("UPDATE url_lookup SET head = $1, expire = $3, changes_count = changes_count + 1 WHERE url_code = $2", 
            &[&commit_id, &url_code, &expiry]).await;
        if result.is_err() {
            return Err(Status::internal("Internal server error, failed to insert the data into the database."));
        }

        // Update account details [if authenticated] for count and url
        if pass != None {
            client.query("INSERT INTO account_files (account_id, url_code, pass) VALUES ($1, $2, $3)", &[&account_id, &url_code, &pass]).await.unwrap();
        } else {
            client.query("INSERT INTO account_files (account_id, url_code) VALUES ($1, $2)", &[&account_id, &url_code]).await.unwrap();
        }
        

        Ok(Response::new(TxtResult{
            url_code: url_code,
            file_txt: file_data.to_string(),
            file_detail: Some(FileDetail {
                burn: expire == "once",
                category: category,
                expire: expiry.to_string(),
                r#type: file_type,
                created: time::OffsetDateTime::now_utc().to_string(),
                linked_account_id: Some(account_id),  
                commit_id: commit_id,
            }),
        }))
    }

}