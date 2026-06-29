use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

const ACCESS_TOKEN_EXPIRY_SECS: usize = 900;
const REFRESH_TOKEN_EXPIRY_SECS: usize = 86400;
const REFRESH_TOKEN_REUSE_GRACE_SECS: u64 = 5;

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let params =
        Params::new(4096, 3, 1, None).map_err(|e| format!("argon2 params error: {}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("password hash error: {}", e))
        .map(|h| h.to_string())
}

pub fn hash_password_for_restore() -> String {
    let random_pass = Uuid::new_v4().to_string();
    hash_password(&random_pass).unwrap_or_else(|_| String::new())
}

#[derive(Clone, Serialize, Deserialize)]
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
    pub token_type: String,
    pub parent_jti: Option<String>,
}

impl std::fmt::Debug for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claims")
            .field("sub", &self.sub)
            .field("username", &self.username)
            .field("role", &self.role)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
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

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("role", &self.role)
            .field("enabled", &self.enabled)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: usize,
    pub role: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
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
        let password_hash = hash_password(password)?;
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

    pub async fn restore_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
        enabled: bool,
    ) -> Result<User, String> {
        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            role,
            enabled,
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
        let user = self.find_by_username(username).await;
        if user.is_none() || user.as_ref().is_some_and(|u| !u.enabled) {
            let dummy = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$dummy-salt-16-bytes-x$dummy-hash-32-bytes-0000000000000000").ok()?;
            let _ = Argon2::default().verify_password(password.as_bytes(), &dummy);
            return None;
        }
        let user = user?;

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
            user.password_hash = hash_password(pass)?;
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

        user.password_hash = hash_password(new_password)?;

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

#[derive(Clone)]
pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    used_refresh_tokens: Arc<std::sync::Mutex<HashMap<String, std::time::SystemTime>>>,
    revoked_families: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl JwtAuth {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            used_refresh_tokens: Arc::new(std::sync::Mutex::new(HashMap::new())),
            revoked_families: Arc::new(std::sync::Mutex::new(HashSet::new())),
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
            token_type: "access".into(),
            parent_jti: None,
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
            token_type: "refresh".into(),
            parent_jti: None,
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

    pub fn validate_access_token(&self, token: &str) -> Result<Claims, String> {
        let claims = self.validate_token(token)?;
        if claims.token_type != "access" {
            return Err("not an access token".to_string());
        }
        Ok(claims)
    }

    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenResponse, String> {
        let claims = self.validate_token(refresh_token)?;

        if claims.token_type != "refresh" {
            return Err("not a refresh token".to_string());
        }

        // Check token family (sub) has not been revoked
        {
            let revoked = match self.revoked_families.lock() {
                Ok(f) => f,
                Err(_) => return Err("internal error".to_string()),
            };
            let family_id = claims.parent_jti.as_ref().unwrap_or(&claims.jti);
            if revoked.contains(family_id) {
                return Err("token family revoked".to_string());
            }
        }

        // Check for refresh token reuse with grace period
        {
            let mut used = match self.used_refresh_tokens.lock() {
                Ok(u) => u,
                Err(_) => return Err("internal error".to_string()),
            };
            if let Some(&first_use) = used.get(&claims.jti) {
                let now = std::time::SystemTime::now();
                let elapsed = now
                    .duration_since(first_use)
                    .unwrap_or(std::time::Duration::from_secs(999));

                if elapsed.as_secs() > REFRESH_TOKEN_REUSE_GRACE_SECS {
                    let mut revoked = match self.revoked_families.lock() {
                        Ok(r) => r,
                        Err(_) => return Err("internal error".to_string()),
                    };
                    let family_id = claims.parent_jti.as_ref().unwrap_or(&claims.jti);
                    revoked.insert(family_id.clone());
                    return Err("refresh token reused — family revoked".to_string());
                }
            } else {
                used.insert(claims.jti.clone(), std::time::SystemTime::now());
            }
        }

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
            token_type: "access".into(),
            parent_jti: Some(claims.parent_jti.clone().unwrap_or_else(|| claims.jti.clone())),
        };

        let refresh_claims = Claims {
            sub: claims.sub.clone(),
            username: claims.username.clone(),
            role: claims.role.clone(),
            exp: now + REFRESH_TOKEN_EXPIRY_SECS,
            iat: now,
            nbf: now,
            iss: "argus".into(),
            aud: "argus-api".into(),
            jti: Uuid::new_v4().to_string(),
            token_type: "refresh".into(),
            parent_jti: Some(claims.parent_jti.clone().unwrap_or_else(|| claims.jti.clone())),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| format!("token encode error: {}", e))?;

        let new_refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| format!("refresh token encode error: {}", e))?;

        Ok(TokenResponse {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".into(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECS,
            role: claims.role.to_string(),
        })
    }

    pub fn gc_token_families(&self) {
        if let Ok(mut used) = self.used_refresh_tokens.lock() {
            let now = std::time::SystemTime::now();
            let cutoff = REFRESH_TOKEN_EXPIRY_SECS as u64;

            used.retain(|_, &mut timestamp| {
                now.duration_since(timestamp)
                    .map(|d| d.as_secs() < cutoff)
                    .unwrap_or(false)
            });

            if used.len() > 100_000 {
                used.clear();
            }
        }
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
    pub jwt_secret: Zeroizing<Vec<u8>>,
    pub jwt_auth: JwtAuth,
    pub user_store: Arc<UserStore>,
}

impl AuthConfig {
    pub fn new(jwt_secret: Vec<u8>) -> Self {
        let jwt_auth = JwtAuth::new(&jwt_secret);
        Self {
            jwt_secret: Zeroizing::new(jwt_secret),
            jwt_auth,
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
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_refresh_token_reuse_detected() {
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

        let refreshed1 = auth.refresh_access_token(&tokens.refresh_token).unwrap();
        assert_eq!(refreshed1.role, "admin");

        let reuse_within_grace = auth.refresh_access_token(&tokens.refresh_token);
        assert!(
            reuse_within_grace.is_ok(),
            "refresh token reuse within grace period should succeed (prevents false positives from network retries)"
        );

        let refreshed2 = auth
            .refresh_access_token(&refreshed1.refresh_token)
            .unwrap();
        assert_eq!(refreshed2.role, "admin");

        std::thread::sleep(std::time::Duration::from_secs(6));

        let reuse_old_after_grace = auth.refresh_access_token(&tokens.refresh_token);
        assert!(
            reuse_old_after_grace.is_err(),
            "refresh token reuse after grace period should be rejected and revoke family"
        );

        let family_revoked = auth.refresh_access_token(&refreshed2.refresh_token);
        assert!(
            family_revoked.is_err(),
            "all tokens in family should be revoked after reuse detection"
        );
    }

    #[test]
    fn test_access_token_rejected_as_refresh() {
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
        let result = auth.refresh_access_token(&tokens.access_token);
        assert!(
            result.is_err(),
            "access token should not work as refresh token"
        );
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
