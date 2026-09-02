// Port of app.go's router, response helpers, and auth middleware.

use axum::body::Bytes;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::auth;
use crate::profile;
use crate::roles::has_role;
use crate::state::AppState;
use crate::users;

// Route-for-route mirror of newRouter() in app.go. No CORS middleware:
// browsers only talk to the Next.js server, which proxies /api/* to this API
// (see frontend/next.config.ts) — same-origin.
pub fn new_router(state: AppState) -> Router {
    Router::new()
        .route("/api/signup", post(auth::signup))
        .route("/api/verify", get(auth::verify))
        .route("/api/resend-verification", post(auth::resend_verification))
        .route("/api/forgot-password", post(auth::forgot_password))
        .route("/api/reset-password", post(auth::reset_password))
        .route("/api/login", post(auth::login))
        .route("/api/login/verify", post(auth::verify_login))
        .route("/api/login/resend", post(auth::resend_login_code))
        .route("/api/me", get(auth::me))
        .route("/api/change-password", post(auth::change_password))
        .route(
            "/api/profile",
            get(profile::get_profile).post(profile::save_profile),
        )
        .route(
            "/api/users",
            get(users::list_users).post(users::admin_create_user),
        )
        .route("/api/users/{id}", delete(users::delete_user))
        .route(
            "/api/users/{id}/verification",
            patch(users::patch_verification),
        )
        .route("/api/users/{id}/role", patch(users::patch_role))
        .route(
            "/api/users/{id}/resend-verification",
            post(users::staff_resend_verification),
        )
        .route(
            "/api/users/{id}/reset-password",
            post(users::admin_reset_password),
        )
        .with_state(state)
}

// ---- response helpers ----

pub fn respond(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

pub fn msg(message: &str) -> Value {
    json!({ "message": message })
}

// The status parameter exists to mirror the Go signature; the payload never
// carries it (matching the frontend's expectations).
pub fn fail(_status: u16, message: &str) -> Value {
    json!({ "success": false, "message": message })
}

// Node logs the server-side reason, then answers with the same shape whether
// or not the response carries the success field.
pub fn respond_500(context: &str, err: impl std::fmt::Display, with_success: bool) -> Response {
    eprintln!("{context}: {err}");
    if with_success {
        respond(
            StatusCode::INTERNAL_SERVER_ERROR,
            fail(500, "Internal server error"),
        )
    } else {
        respond(
            StatusCode::INTERNAL_SERVER_ERROR,
            msg("Internal server error"),
        )
    }
}

// Express treats a missing/unparsable body as an empty object and lets
// route-level validation produce the 400s, so decode errors are ignored.
pub fn decode<T: DeserializeOwned + Default>(body: &Bytes) -> T {
    serde_json::from_slice(body).unwrap_or_default()
}

// Prisma's P2002 (unique constraint) as a Postgres error code check.
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .is_some_and(|e| e.code().is_some_and(|c| c == "23505"))
}

// ---- auth ----

// A logged-in user. Extracting this in a handler IS the auth check (the port
// of requireAuth) — token verification, user lookup, verification flag, and
// the onboarding gates all run here.
#[derive(Clone, sqlx::FromRow)]
pub struct AuthUser {
    pub id: i32,
    pub email: String,
    pub role: String,
    pub email_verified: bool,
    pub must_change_password: bool,
    pub has_profile: bool,
    pub password: String, // stored hash, for /api/change-password
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(' ').nth(1))
            .unwrap_or("");
        if token.is_empty() {
            return Err(respond(StatusCode::UNAUTHORIZED, msg("No token provided")));
        }
        let Some(email) = auth::verify_token(token, &state.cfg.jwt_secret) else {
            return Err(respond(
                StatusCode::FORBIDDEN,
                msg("Invalid or expired token"),
            ));
        };
        let row: Result<Option<AuthUser>, _> = sqlx::query_as(
            "SELECT id, email, role, email_verified, must_change_password, password,
                    EXISTS (SELECT 1 FROM user_profiles WHERE user_id = users.id) AS has_profile
             FROM users WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&state.db)
        .await;
        let user = match row {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err(respond(StatusCode::NOT_FOUND, msg("User not found")));
            }
            // Node wraps the user lookup in the same try/catch as the JWT
            // check, so any failure here reads as a bad token.
            Err(_) => {
                return Err(respond(
                    StatusCode::FORBIDDEN,
                    msg("Invalid or expired token"),
                ));
            }
        };
        if state.cfg.email_verification_required && !user.email_verified {
            return Err(respond(
                StatusCode::FORBIDDEN,
                msg("Please verify your email"),
            ));
        }
        // Gates only need to know a profile exists, not its contents — routes
        // that need the full row (GET /api/profile) fetch it themselves.
        let route = format!("{} {}", parts.method, parts.uri.path());
        if !onboarding_exempt(&route) {
            // A logged-in user can be mid-onboarding — temp password not yet
            // changed, registration details not yet filled in, possibly both
            // at once. Each gate owns its own clearing route(s), always
            // exempt from every gate (not just its own) so a user working
            // through one gate can still reach the other's route — enforced
            // here so the frontend redirect isn't the only thing stopping a
            // temp password or empty profile from driving the API.
            if user.must_change_password {
                return Err(respond(
                    StatusCode::FORBIDDEN,
                    msg("Password change required"),
                ));
            }
            if !user.has_profile {
                return Err(respond(
                    StatusCode::FORBIDDEN,
                    msg("Profile information required"),
                ));
            }
        }
        Ok(user)
    }
}

fn onboarding_exempt(route: &str) -> bool {
    matches!(
        route,
        "GET /api/me" | "POST /api/change-password" | "GET /api/profile" | "POST /api/profile"
    )
}

// Shared by role-gated handlers (users.rs, Phase 4): 403s unless the user's
// role is minRole or higher.
pub fn ensure_role(user: &AuthUser, min_role: &str) -> Result<(), Response> {
    if has_role(&user.role, min_role) {
        Ok(())
    } else {
        Err(respond(
            StatusCode::FORBIDDEN,
            msg("Insufficient permissions"),
        ))
    }
}
