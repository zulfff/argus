use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRY_SECS: usize = 900;
const REFRESH_TOKEN_EXPIRY_SECS: usize = 86400;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: Role,
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,
    pub iss: String,
    pub aud: String,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "operator")]
    Operator,
    #[serde(rename = "viewer")]
    Viewer,
}

impl Role {
    pub fn can_read(&self) -> bool {
        matches!(self, Role::Admin | Role::Operator | Role::Viewer)
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Role::Admin | Role::Operator)
    }

    pub fn can_delete(&self) -> bool {
        matches!(self, Role::Admin)
    }

    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Operator => write!(f, "operator"),
            Role::Viewer => write!(f, "viewer"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: usize,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub struct UserStore {
    users: Arc<Mutex<HashMap<String, User>>>,
}

impl UserStore {
    pub fn new() -> Self {
        let users = Arc::new(Mutex::new(HashMap::new()));
        Self { users }
    }

    pub async fn add_user(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<User, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("password hash error: {}", e))?
            .to_string();

        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            password_hash,
            role,
            enabled: true,
        };

        self.users
            .lock()
            .await
            .insert(username.to_string(), user.clone());

        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> Option<User> {
        self.users.lock().await.get(username).cloned()
    }

    pub async fn verify_password(&self, username: &str, password: &str) -> Option<User> {
        let user = self.find_by_username(username).await?;
        if !user.enabled {
            return None;
        }

        let parsed_hash = PasswordHash::new(&user.password_hash).ok()?;
        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .ok()?;

        Some(user)
    }

    pub async fn list_users(&self) -> Vec<User> {
        self.users.lock().await.values().cloned().collect()
    }

    pub async fn delete_user(&self, username: &str) -> bool {
        self.users.lock().await.remove(username).is_some()
    }

    pub async fn update_user(
        &self,
        username: &str,
        password: Option<&str>,
        role: Option<Role>,
    ) -> Result<User, String> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| format!("user '{}' not found", username))?;

        if let Some(pass) = password {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            user.password_hash = argon2
                .hash_password(pass.as_bytes(), &salt)
                .map_err(|e| format!("password hash error: {}", e))?
                .to_string();
        }

        if let Some(role) = role {
            user.role = role;
        }

        Ok(user.clone())
    }

    pub async fn disable_user(&self, username: &str) -> Result<User, String> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| format!("user '{}' not found", username))?;
        user.enabled = false;
        Ok(user.clone())
    }

    pub async fn enable_user(&self, username: &str) -> Result<User, String> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| format!("user '{}' not found", username))?;
        user.enabled = true;
        Ok(user.clone())
    }

    pub async fn change_password(&self, username: &str, new_password: &str) -> Result<(), String> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(username)
            .ok_or_else(|| format!("user '{}' not found", username))?;

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        user.password_hash = argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|e| format!("password hash error: {}", e))?
            .to_string();

        Ok(())
    }

    pub async fn clear_users(&self) {
        self.users.lock().await.clear();
    }
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtAuth {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn generate_tokens(&self, user: &User) -> Result<TokenResponse, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("time error: {}", e))?
            .as_secs() as usize;

        let access_claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            role: user.role.clone(),
            exp: now + ACCESS_TOKEN_EXPIRY_SECS,
            iat: now,
            nbf: now,
            iss: "argus".into(),
            aud: "argus-api".into(),
            jti: Uuid::new_v4().to_string(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| format!("token encode error: {}", e))?;

        let refresh_claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            role: user.role.clone(),
            exp: now + REFRESH_TOKEN_EXPIRY_SECS,
            iat: now,
            nbf: now,
            iss: "argus".into(),
            aud: "argus-api".into(),
            jti: Uuid::new_v4().to_string(),
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| format!("token encode error: {}", e))?;

        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".into(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            role: user.role.to_string(),
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, String> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&["argus"]);
        validation.set_audience(&["argus-api"]);
        validation.leeway = 5;
        validation.required_spec_claims = ["exp", "iat", "nbf", "iss", "aud"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| format!("token validation error: {}", e))?;

        Ok(token_data.claims)
    }

    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenResponse, String> {
        let claims = self.validate_token(refresh_token)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("time error: {}", e))?
            .as_secs() as usize;

        let access_claims = Claims {
            sub: claims.sub.clone(),
            username: claims.username.clone(),
            role: claims.role.clone(),
            exp: now + ACCESS_TOKEN_EXPIRY_SECS,
            iat: now,
            nbf: now,
            iss: "argus".into(),
            aud: "argus-api".into(),
            jti: Uuid::new_v4().to_string(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| format!("token encode error: {}", e))?;

        Ok(TokenResponse {
            access_token,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer".into(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            role: claims.role.to_string(),
        })
    }
}

pub struct AuthenticatedUser {
    pub claims: Claims,
}

impl Clone for AuthenticatedUser {
    fn clone(&self) -> Self {
        Self {
            claims: self.claims.clone(),
        }
    }
}

impl AuthenticatedUser {
    #[allow(dead_code)]
    pub async fn from_request(parts: &mut Parts, jwt_auth: &JwtAuth) -> Result<Self, AuthError> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingToken)?;

        let claims = jwt_auth
            .validate_token(bearer.token())
            .map_err(AuthError::InvalidToken)?;

        Ok(AuthenticatedUser { claims })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum AuthError {
    MissingToken,
    InvalidToken(String),
    Forbidden,
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization token"),
            AuthError::InvalidToken(_e) => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal auth error"),
        };

        let body = serde_json::json!({
            "error": message,
            "code": status.as_u16(),
        });

        (status, Json(body)).into_response()
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: Vec<u8>,
    pub user_store: Arc<UserStore>,
}

impl AuthConfig {
    pub fn new(jwt_secret: Vec<u8>) -> Self {
        Self {
            jwt_secret,
            user_store: Arc::new(UserStore::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generate_and_validate() {
        let secret = b"test-secret-key-for-jwt-signing-32bytes!!";
        let auth = JwtAuth::new(secret);

        let user = User {
            id: Uuid::new_v4(),
            username: "admin".into(),
            password_hash: "hash".into(),
            role: Role::Admin,
            enabled: true,
        };

        let tokens = auth.generate_tokens(&user).unwrap();
        assert_eq!(tokens.token_type, "Bearer");

        let claims = auth.validate_token(&tokens.access_token).unwrap();
        assert_eq!(claims.username, "admin");
        assert_eq!(claims.role, Role::Admin);
    }

    #[test]
    fn test_invalid_token() {
        let auth = JwtAuth::new(b"valid-secret-key-that-is-32-bytes!!");
        let result = auth.validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_role_permissions() {
        assert!(Role::Admin.can_delete());
        assert!(Role::Admin.can_manage_users());

        assert!(!Role::Operator.can_delete());
        assert!(Role::Operator.can_write());

        assert!(Role::Viewer.can_read());
        assert!(!Role::Viewer.can_write());
    }

    #[tokio::test]
    async fn test_user_store_password() {
        let store = UserStore::new();
        store
            .add_user("test", "password123", Role::Admin)
            .await
            .unwrap();

        let user = store.verify_password("test", "password123").await;
        assert!(user.is_some());

        let wrong = store.verify_password("test", "wrongpass").await;
        assert!(wrong.is_none());
    }

    #[tokio::test]
    async fn test_user_store_delete() {
        let store = UserStore::new();
        store
            .add_user("deleteMe", "pass", Role::Viewer)
            .await
            .unwrap();

        assert!(store.delete_user("deleteMe").await);
        assert!(store.find_by_username("deleteMe").await.is_none());
    }
}
