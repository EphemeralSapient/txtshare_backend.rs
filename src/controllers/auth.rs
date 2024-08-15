// Javascript reference
// const querystring = require('querystring');
// const axios = require("axios");
// const config = require('../config');
// const jwt = require('jsonwebtoken');
// const pool = config.pool;

// exports.googleAuth = (req, res) => {
//     const params = {
//         client_id: config.oauth.clientID, // Client ID
//         redirect_uri: config.oauth.redirectUri, // Callback
//         response_type: 'code', // Authorization code for token exchange
//         scope: 'https://www.googleapis.com/auth/userinfo.email', // Email is only required
//         access_type: 'offline', // Access token never expires
//         prompt: 'consent', // Always prompt for consent from the user
//     };
//     const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + querystring.stringify(params);
//     res.redirect(url);
// };

// exports.googleAuthCallback = async (req, res) => {
//     const { code } = req.query;
//     const tokenParams = {
//         code,
//         client_id: config.oauth.clientID,
//         client_secret: config.oauth.clientSecret,
//         redirect_uri: config.oauth.redirectUri,
//         grant_type: 'authorization_code',
//     };

//     try {
//         const response = await axios.post('https://oauth2.googleapis.com/token', querystring.stringify(tokenParams));
//         const tokens = response.data;
        
//         // Use the tokens to get user info
//         const userInfo = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
//             headers: {
//                 Authorization: `Bearer ${tokens.access_token}`,
//             },
//         });
        
//         // Extract user info
//         const { email,name, verified_email } = userInfo.data;

//         if(!verified_email){
//             res.status(500).json({ error: 'Email not verified' });
//         }

//         // Check if user exists, otherwise create
//         let acc_id;
//         let user = await pool.query('SELECT account_id FROM accounts WHERE email = $1', [email]);
//         if (user.rowCount === 0) {
//             await pool.query('INSERT INTO accounts (oauth_provider, email, username) VALUES ($1, $2, $3)', ['google', email, name]);
//             user = await pool.query('SELECT account_id FROM accounts WHERE email = $1', [email]);
//             acc_id = user.rows[0].account_id;
//         } else {
//             acc_id = user.rows[0].account_id;
//         }

//         // Generate JWT token
//         const token = jwt.sign({ "email" : email, "id" : acc_id }, config.security.jwtToken);

//         res.json({token: token});
//     } catch (error) {
//         console.error('Error during OAuth callback:', error);
//         res.status(500).json({ error: 'Failed to authenticate' });
//     }
// };

use form_urlencoded::Serializer;
use jsonwebtoken;

use super::{Request, Response, Status};
use super::DB_CONNECTION as db;
use super::{auth_server::Auth, OAuthCallback, OAuthInit, OAuthResult, OAuthUrl};

#[derive(Debug, Default)]
pub struct AuthService {}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn initiate_o_auth(
        &self,
        _request: Request<OAuthInit>,
    ) -> Result<Response<OAuthUrl>, Status> {
        let params = Serializer::new(String::new())
            .append_pair("client_id", &std::env::var("GOOGLE_CLIENT_ID").unwrap())
            .append_pair("redirect_uri", &std::env::var("GOOGLE_REDIRECT_URI").unwrap())
            .append_pair("response_type", "code")
            .append_pair("scope", "https://www.googleapis.com/auth/userinfo.email")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .finish();
        

        Ok(Response::new(OAuthUrl {
            url: format!("https://accounts.google.com/o/oauth2/v2/auth?{}", params),
        }))
    }


    async fn callback_o_auth(
        &self,
        request: Request<OAuthCallback>,
    ) -> Result<Response<OAuthResult>, Status> {
        
        let code = request.into_inner().code;
        let token_params = Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("client_id", &std::env::var("GOOGLE_CLIENT_ID").unwrap())
            .append_pair("client_secret", &std::env::var("GOOGLE_CLIENT_SECRET").unwrap())
            .append_pair("redirect_uri", &std::env::var("GOOGLE_REDIRECT_URI").unwrap())
            .append_pair("grant_type", "authorization_code")
            .finish();

        let response = reqwest::Client::new()
            .post("https://oauth2.googleapis.com/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(token_params)
            .send()
            .await
            .map_err(|_| Status::internal("Failed to authenticate"))?
            .text()
            .await
            .map_err(|_| Status::internal("Failed to authenticate"))?;
        let response: serde_json::Value = serde_json::from_str(&response)
        .map_err(|_| Status::internal("Failed to parse JSON"))?;

        let access_token = response["access_token"].as_str().ok_or(Status::internal("Failed to authenticate"))?;
        let user_info = reqwest::Client::new()
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|_| Status::internal("Failed to authenticate"))?
            .text()
            .await
            .map_err(|_| Status::internal("Failed to authenticate"))?;
        let user_info: serde_json::Value = serde_json::from_str(&user_info)
        .map_err(|_| Status::internal("Failed to parse JSON"))?;
    
        let email = user_info["email"].as_str().ok_or(Status::internal("Failed to authenticate"))?;
        let name = user_info["name"].as_str().ok_or(Status::internal("Failed to authenticate"))?;
        let verified_email = user_info["verified_email"].as_bool().ok_or(Status::internal("Failed to authenticate"))?;

        if !verified_email {
            return Err(Status::unauthenticated("Email not verified"));
        }

        let client = db.get().unwrap().lock().await;

        let user = client.query_one("SELECT account_id FROM accounts WHERE email = $1", &[&email]).await;

        let acc_id: i32;
        // Create if user does not exist
        if user.is_err() {
            client.execute("INSERT INTO accounts (oauth_provider, email, username) VALUES ($1, $2, $3)", &[&"google", &email, &name]).await.unwrap();

            let user = client.query_one("SELECT account_id FROM accounts WHERE email = $1", &[&email]).await.unwrap();
            acc_id = user.get(0);

        } else {
            acc_id = user.unwrap().get(0);
        }

        // Creating the token for infinite time
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &serde_json::json!({"email": email, "id": acc_id}),
            &jsonwebtoken::EncodingKey::from_secret(std::env::var("JWT_SECRET").unwrap().as_ref())
        ).unwrap();

        Ok(Response::new(OAuthResult {
            token: token,
        }))

    }
}