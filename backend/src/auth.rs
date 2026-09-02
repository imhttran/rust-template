// Port of auth.go — scrypt password hashing (Node-compatible `salt:hash` hex
// format so existing hashes verify unchanged), HS256 JWTs, and the auth
// endpoints.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::random;
use scrypt::{scrypt, Params};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::mail;
use crate::queue::{self, QueueError};
use crate::routes::{decode, fail, msg, respond, respond_500};
use crate::state::AppState;
use crate::validators::{validate_email, validate_password};

// ---- password hashing ----

// Node scrypt defaults: N=16384, r=8, p=1, salt hex-encoded as a string.
const SCRYPT_LOG_N: u8 = 14; // N = 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
// 16-byte salt, 64-byte key, stored as `salt:hash` hex.
const KEY_LEN: usize = 64;

// The salt input is the hex-encoded string itself (not the raw bytes) —
// that's what the Node/Go implementations feed scrypt.
fn scrypt_key(password: &str, salt_hex: &str) -> [u8; KEY_LEN] {
    let params =
        Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LEN).expect("static params are valid");
    let mut key = [0u8; KEY_LEN];
    scrypt(password.as_bytes(), salt_hex.as_bytes(), &params, &mut key)
        .expect("fixed output length cannot be invalid");
    key
}

pub fn hash_password(password: &str) -> String {
    let salt_hex = hex::encode(random::<[u8; 16]>());
    let key = scrypt_key(password, &salt_hex);
    format!("{salt_hex}:{}", hex::encode(key))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt_hex, hash_hex)) = stored.split_once(':') else {
        return false;
    };
    let key = scrypt_key(password, salt_hex);
    let Ok(hash) = hex::decode(hash_hex) else {
        return false;
    };
    hash.len() == key.len() && bool::from(hash.as_slice().ct_eq(&key))
}

// ---- tokens ----

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    email: String,
    exp: u64,
    iat: u64,
}

// Sessions expire SESSION_TTL_SECS after issue (the extractor enforces the
// hard expiry); the router's middleware slides active sessions forward by
// re-issuing past the half-life (see maybe_renew_session).
pub const SESSION_TTL_SECS: i64 = 600; // 10 minutes
const RENEW_THRESHOLD_SECS: u64 = 300; // half-life

pub fn issue_token_with_ttl(email: &str, secret: &str, ttl_secs: i64) -> String {
    let now = Utc::now().timestamp();
    let claims = Claims {
        email: email.to_string(),
        exp: (now + ttl_secs) as u64,
        iat: now as u64,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("signing with a string secret can't fail")
}

// HS256, claim {email}, 10-minute expiry.
pub fn issue_token(email: &str, secret: &str) -> String {
    issue_token_with_ttl(email, secret, SESSION_TTL_SECS)
}

// Returns the email claim, or None on any failure (mirrors verifyToken).
pub fn verify_token(token: &str, secret: &str) -> Option<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0; // golang-jwt has no default leeway
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    // A signed token without a usable email claim still fails the lookup and
    // reads as "Invalid or expired token".
    let email = data.claims.email;
    if email.is_empty() {
        None
    } else {
        Some(email)
    }
}

pub fn random_token() -> String {
    hex::encode(random::<[u8; 32]>())
}

// Returns a fresh token when the current one is past its half-life, so an
// active user's session slides forward instead of hard-expiring mid-use.
// Expired or invalid tokens are never renewed.
pub fn renew_token_if_due(token: &str, secret: &str) -> Option<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    let now = Utc::now().timestamp() as u64;
    (data.claims.exp.saturating_sub(now) < RENEW_THRESHOLD_SECS)
        .then(|| issue_token(&data.claims.email, secret))
}

// A 4-digit login code. In development it's always 1234 so testing doesn't
// need a mail server; otherwise a random code.
pub fn random_code(env: &str) -> String {
    if env == "development" {
        return "1234".to_string();
    }
    let b: [u8; 2] = random();
    let n = (u16::from(b[0]) << 8) | u16::from(b[1]);
    format!("{:04}", n % 10000)
}

// ---- request bodies ----

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SignupBody {
    email: String,
    password: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct EmailBody {
    email: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResetPasswordBody {
    token: String,
    password: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LoginBody {
    email: String,
    password: String,
    device_id: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct VerifyLoginBody {
    token: String,
    code: String,
    device_id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResendCodeBody {
    token: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize, Default)]
pub struct VerifyQuery {
    token: Option<String>,
}

// ---- handlers ----

pub async fn me(user: crate::routes::AuthUser) -> Response {
    respond(
        StatusCode::OK,
        json!({
            "message": "Welcome to the secret area!",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "emailVerified": user.email_verified,
                "mustChangePassword": user.must_change_password,
                "hasProfile": user.has_profile,
            },
        }),
    )
}

pub async fn signup(State(state): State<AppState>, body: Bytes) -> Response {
    let body: SignupBody = decode(&body);
    if !validate_email(&body.email) {
        return respond(StatusCode::BAD_REQUEST, fail("Invalid email address"));
    }
    if let Some(password_error) = validate_password(&body.password) {
        return respond(StatusCode::BAD_REQUEST, fail(&password_error));
    }

    // Atomic: user + welcome-email row together, so a failed email never
    // leaves an orphaned account and a rolled-back signup leaves no queued
    // email. Actual send is deferred to the worker — signup is never blocked
    // on mail delivery.
    let token = random_token();
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => return respond_500("Signup Error", err, true),
    };
    if let Err(err) = sqlx::query(
        "INSERT INTO users (email, password, email_verified, verification_token) VALUES ($1, $2, false, $3)",
    )
    .bind(&body.email)
    .bind(hash_password(&body.password))
    .bind(&token)
    .execute(&mut *tx)
    .await
    {
        if crate::routes::is_unique_violation(&err) {
            // Keep the user-facing message generic so the API doesn't reveal
            // whether an email is already registered (prevents user enumeration).
            // The real reason is logged server-side for debugging.
            eprintln!("[signup] rejected: email already registered (email={})", body.email);
            return respond(
                StatusCode::BAD_REQUEST,
                fail("Unable to sign up. Please try again later."),
            );
        }
        return respond_500("Signup Error", err, true);
    }
    if let Err(err) = mail::enqueue_email(&mut *tx, &mail::welcome_email(&body.email)).await {
        return respond_500("Signup Error", err, true);
    }
    let link = mail::token_link(&state.cfg.frontend_url, "verify", &token);
    if let Err(err) =
        mail::enqueue_email(&mut *tx, &mail::verification_email(&body.email, &link)).await
    {
        return respond_500("Signup Error", err, true);
    }
    if let Err(err) = tx.commit().await {
        return respond_500("Signup Error", err, true);
    }
    respond(
        StatusCode::CREATED,
        json!({
            "success": true,
            "message": "User created successfully!",
            "user": { "email": body.email },
        }),
    )
}

pub async fn verify(State(state): State<AppState>, Query(query): Query<VerifyQuery>) -> Response {
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Missing verification token"),
        );
    }
    let id: Option<i32> =
        match sqlx::query_scalar("SELECT id FROM users WHERE verification_token = $1")
            .bind(&token)
            .fetch_optional(&state.db)
            .await
        {
            Ok(id) => id,
            Err(err) => return respond_500("Verify Error", err, true),
        };
    let Some(id) = id else {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired verification link"),
        );
    };
    if let Err(err) = sqlx::query(
        "UPDATE users SET email_verified = true, verification_token = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await
    {
        return respond_500("Verify Error", err, true);
    }
    respond(
        StatusCode::OK,
        json!({"success": true, "message": "Email verified successfully!"}),
    )
}

pub async fn resend_verification(State(state): State<AppState>, body: Bytes) -> Response {
    let body: EmailBody = decode(&body);
    if !validate_email(&body.email) {
        return respond(StatusCode::BAD_REQUEST, fail("Invalid email address"));
    }
    let row: Result<Option<(i32, bool)>, _> =
        sqlx::query_as("SELECT id, email_verified FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&state.db)
            .await;
    // Same response regardless of account existence/verified state, so this
    // endpoint can't be used to enumerate registered emails.
    if let Ok(Some((id, false))) = row {
        if let Err(err) =
            queue::queue_verification_email(&state.db, &state.cfg.frontend_url, id, &body.email)
                .await
        {
            return respond_500("Resend Verification Error", err, true);
        }
    }
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": "If that email is registered and unverified, a verification link has been sent.",
        }),
    )
}

pub async fn forgot_password(State(state): State<AppState>, body: Bytes) -> Response {
    let body: EmailBody = decode(&body);
    if !validate_email(&body.email) {
        return respond(StatusCode::BAD_REQUEST, fail("Invalid email address"));
    }
    // No such user: fall through to the generic response (P2025 equivalent).
    if let Err(err) = queue::queue_password_reset(
        &state.db,
        &state.cfg.frontend_url,
        queue::ResetKey::Email(body.email),
    )
    .await
    {
        if !matches!(err, QueueError::NotFound) {
            return respond_500("Forgot Password Error", err, true);
        }
    }
    // Same response whether or not the account exists, so this endpoint
    // can't be used to enumerate registered emails.
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": "If that email is registered, a reset link has been sent.",
        }),
    )
}

pub async fn reset_password(State(state): State<AppState>, body: Bytes) -> Response {
    let body: ResetPasswordBody = decode(&body);
    if body.token.is_empty() {
        return respond(StatusCode::BAD_REQUEST, fail("Missing reset token"));
    }
    if let Some(password_error) = validate_password(&body.password) {
        return respond(StatusCode::BAD_REQUEST, fail(&password_error));
    }
    // Any failure to find a usable unexpired token reads the same.
    let row: Option<(i32, String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT id, email, reset_token_expiry FROM users WHERE reset_token = $1")
            .bind(&body.token)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);
    let Some((id, email, expiry)) = row else {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired reset link"),
        );
    };
    if expiry.is_none_or(|e| e < Utc::now()) {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired reset link"),
        );
    }
    if let Err(err) = sqlx::query(
        "UPDATE users
         SET password = $1, reset_token = NULL, reset_token_expiry = NULL, must_change_password = false
         WHERE id = $2",
    )
    .bind(hash_password(&body.password))
    .bind(id)
    .execute(&state.db)
    .await
    {
        return respond_500("Reset Password Error", err, true);
    }
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": "Password reset successfully!",
            "token": issue_token(&email, &state.cfg.jwt_secret),
            "user": { "email": email },
        }),
    )
}

pub async fn login(State(state): State<AppState>, body: Bytes) -> Response {
    let body: LoginBody = decode(&body);
    let row: Result<Option<(i32, String, bool)>, _> =
        sqlx::query_as("SELECT id, password, email_verified FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&state.db)
            .await;
    let (id, stored_hash, verified) = match row {
        Ok(Some(row)) => row,
        // Bad credentials and lookup failures read the same (mirrors err != nil || !verify).
        _ => {
            return respond(
                StatusCode::UNAUTHORIZED,
                fail("Invalid email or password"),
            )
        }
    };
    if !verify_password(&body.password, &stored_hash) {
        return respond(
            StatusCode::UNAUTHORIZED,
            fail("Invalid email or password"),
        );
    }
    if state.cfg.email_verification_required && !verified {
        return respond(
            StatusCode::FORBIDDEN,
            fail("Please verify your email before logging in."),
        );
    }
    // Trusted device? Skip 2FA.
    if !body.device_id.is_empty() {
        let known: Result<Option<bool>, _> = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = $2)",
        )
        .bind(id)
        .bind(&body.device_id)
        .fetch_optional(&state.db)
        .await;
        if let Ok(Some(true)) = known {
            return respond(
                StatusCode::OK,
                json!({
                    "success": true,
                    "message": "Login successful!",
                    "token": issue_token(&body.email, &state.cfg.jwt_secret),
                    "user": { "email": body.email },
                }),
            );
        }
    }
    // New device — require 2FA: queue an emailed code and hand back a pending
    // token; the real JWT is only issued by /api/login/verify.
    let pending = random_token();
    let code = random_code(&state.cfg.env);
    if let Err(err) = sqlx::query(
        "INSERT INTO login_codes (user_id, token, code, expires_at)
         VALUES ($1, $2, $3, now() + interval '10 minutes')",
    )
    .bind(id)
    .bind(&pending)
    .bind(&code)
    .execute(&state.db)
    .await
    {
        return respond_500("Login Error", err, false);
    }
    send_login_code(&state.db, &body.email, &code).await;
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "twoFactorRequired": true,
            "token": pending,
            "message": "Enter the code sent to your device",
        }),
    )
}

// Completes a 2FA login: validates the code, issues the real JWT, and
// registers the device so future logins from it skip 2FA.
pub async fn verify_login(State(state): State<AppState>, body: Bytes) -> Response {
    let body: VerifyLoginBody = decode(&body);
    let row: Result<Option<(i32, String, DateTime<Utc>, bool, i32, String)>, _> = sqlx::query_as(
        "SELECT lc.user_id, lc.code, lc.expires_at, lc.used, lc.attempts, u.email
         FROM login_codes lc JOIN users u ON u.id = lc.user_id
         WHERE lc.token = $1",
    )
    .bind(&body.token)
    .fetch_optional(&state.db)
    .await;
    let (user_id, code, expires_at, used, attempts, email) = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return respond(
                StatusCode::BAD_REQUEST,
                fail("Invalid or expired code"),
            );
        }
        Err(err) => return respond_500("Verify Login Error", err, false),
    };
    // Lock the code after a handful of failed tries so a 4-digit code can't be
    // brute-forced within its 10-minute window.
    if used || Utc::now() > expires_at || attempts >= 5 {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired code"),
        );
    }
    if !bool::from(code.as_bytes().ct_eq(body.code.as_bytes())) {
        let _ = sqlx::query("UPDATE login_codes SET attempts = attempts + 1 WHERE token = $1")
            .bind(&body.token)
            .execute(&state.db)
            .await;
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired code"),
        );
    }
    if let Err(err) = sqlx::query("UPDATE login_codes SET used = true WHERE token = $1")
        .bind(&body.token)
        .execute(&state.db)
        .await
    {
        return respond_500("Verify Login Error", err, false);
    }
    if !body.device_id.is_empty() {
        let _ = sqlx::query(
            "INSERT INTO user_devices (user_id, device_id) VALUES ($1, $2) ON CONFLICT (device_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(&body.device_id)
        .execute(&state.db)
        .await;
    }
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": "Login successful!",
            "token": issue_token(&email, &state.cfg.jwt_secret),
            "user": { "email": email },
        }),
    )
}

// Resends the 2FA code for a pending login, up to 3 times.
pub async fn resend_login_code(State(state): State<AppState>, body: Bytes) -> Response {
    let body: ResendCodeBody = decode(&body);
    let row: Result<Option<(i32, DateTime<Utc>, bool, String)>, _> = sqlx::query_as(
        "SELECT lc.resends, lc.expires_at, lc.used, u.email
         FROM login_codes lc JOIN users u ON u.id = lc.user_id
         WHERE lc.token = $1",
    )
    .bind(&body.token)
    .fetch_optional(&state.db)
    .await;
    let (resends, expires_at, used, email) = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return respond(
                StatusCode::BAD_REQUEST,
                fail("Invalid or expired code"),
            );
        }
        Err(err) => return respond_500("Resend Code Error", err, false),
    };
    if used || Utc::now() > expires_at {
        return respond(
            StatusCode::BAD_REQUEST,
            fail("Invalid or expired code"),
        );
    }
    if resends >= 3 {
        return respond(
            StatusCode::TOO_MANY_REQUESTS,
            fail("Too many resend attempts"),
        );
    }
    let code = random_code(&state.cfg.env);
    if let Err(err) = sqlx::query(
        "UPDATE login_codes
         SET code = $1, resends = resends + 1, expires_at = now() + interval '10 minutes'
         WHERE token = $2",
    )
    .bind(&code)
    .bind(&body.token)
    .execute(&state.db)
    .await
    {
        return respond_500("Resend Code Error", err, false);
    }
    send_login_code(&state.db, &email, &code).await;
    respond(StatusCode::OK, msg("Code resent"))
}

// Emails the 2FA code through the shared queue; the worker delivers it.
async fn send_login_code(db: &sqlx::PgPool, email: &str, code: &str) {
    let _ = mail::enqueue_email(db, &mail::login_code_email(email, code)).await;
}

// Authenticated self-service password change. Used both for the general
// "change my password" case and to clear the forced-change flag an
// admin-created account starts with.
pub async fn change_password(
    State(state): State<AppState>,
    user: crate::routes::AuthUser,
    body: Bytes,
) -> Response {
    let body: ChangePasswordBody = decode(&body);
    if !verify_password(&body.current_password, &user.password) {
        return respond(
            StatusCode::UNAUTHORIZED,
            fail("Current password is incorrect"),
        );
    }
    if let Some(password_error) = validate_password(&body.new_password) {
        return respond(StatusCode::BAD_REQUEST, fail(&password_error));
    }
    if let Err(err) =
        sqlx::query("UPDATE users SET password = $1, must_change_password = false WHERE id = $2")
            .bind(hash_password(&body.new_password))
            .bind(user.id)
            .execute(&state.db)
            .await
    {
        return respond_500("Change Password Error", err, false);
    }
    respond(
        StatusCode::OK,
        json!({"success": true, "message": "Password changed successfully!"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let stored = hash_password("Valid123!");
        assert!(verify_password("Valid123!", &stored));
        assert!(!verify_password("Wrong123!", &stored));
    }

    // A hash created by the Go backend (the dev-admin seed in main.go). If
    // this ever fails, the Node-compatible scrypt format has drifted.
    #[test]
    fn verifies_hashes_created_by_the_go_backend() {
        let stored = "1b3720e73189cbc4c90595519584e629:b9d00978ebbb9477a6751a63c02933922146945a21ae6ee7c25d012cb33509174daef57c7f782cfed8f811c4af52a6cc07ff476fccf2f3fe1b7abe880211772d";
        assert!(verify_password("Password1234!", stored));
        assert!(!verify_password("Password12345", stored));
    }

    #[test]
    fn jwt_round_trip() {
        let token = issue_token("a@b.c", "secret");
        assert_eq!(verify_token(&token, "secret").as_deref(), Some("a@b.c"));
        assert_eq!(verify_token(&token, "other"), None);
    }

    #[test]
    fn renewal_only_past_half_life() {
        // A fresh (full-life) token is not renewed...
        let fresh = issue_token("a@b.c", "secret");
        assert_eq!(renew_token_if_due(&fresh, "secret"), None);
        // ...one deep into its life is...
        let due = issue_token_with_ttl("a@b.c", "secret", 60);
        let renewed = renew_token_if_due(&due, "secret").expect("due for renewal");
        assert_eq!(verify_token(&renewed, "secret").as_deref(), Some("a@b.c"));
        // ...and an expired one is dead, not renewable.
        let expired = issue_token_with_ttl("a@b.c", "secret", -60);
        assert_eq!(renew_token_if_due(&expired, "secret"), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(verify_token("not-a-jwt", "secret"), None);
        assert!(!verify_password("x", "no-colon"));
    }
}
