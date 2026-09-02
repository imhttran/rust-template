// Port of users.go — staff/admin user management.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::hash_password;
use crate::queue::{self, QueueError};
use crate::roles::{has_role, role_index};
use crate::routes::{
    decode, ensure_role, fail, is_unique_violation, msg, respond, respond_500, AuthUser,
};
use crate::state::AppState;
use crate::validators::{validate_email, validate_password};

// Staff can nudge a not-yet-verified user's verification email along.
pub async fn list_users(State(state): State<AppState>, user: AuthUser) -> Response {
    if let Err(rejection) = ensure_role(&user, "staff") {
        return rejection;
    }
    // Staff sees clients and other staff — admin accounts aren't theirs to
    // manage. Admin sees everyone.
    let filter = if has_role(&user.role, "admin") {
        ""
    } else {
        " WHERE role IN ('client', 'staff')"
    };
    let sql = format!(
        "SELECT id, email, role, email_verified, created_at FROM users{filter} ORDER BY created_at ASC"
    );
    let rows: Result<Vec<(i32, String, String, bool, DateTime<Utc>)>, _> =
        sqlx::query_as(&sql).fetch_all(&state.db).await;
    match rows {
        Ok(rows) => {
            let users: Vec<Value> = rows
                .iter()
                .map(|(id, email, role, verified, created_at)| {
                    json!({
                        "id": id,
                        "email": email,
                        "role": role,
                        "emailVerified": verified,
                        "createdAt": created_at,
                    })
                })
                .collect();
            respond(StatusCode::OK, json!({ "users": users }))
        }
        Err(err) => respond_500("List Users Error", err, false),
    }
}

// Admin-only: creates a user with an admin-chosen password, already verified
// (the admin vouches for the email) and flagged to force a password change
// on first login — the admin never needs to share the real password twice.
pub async fn admin_create_user(
    State(state): State<AppState>,
    user: AuthUser,
    body: Bytes,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "admin") {
        return rejection;
    }
    let body: CreateUserBody = decode(&body);
    if !validate_email(&body.email) {
        return respond(StatusCode::BAD_REQUEST, fail("Invalid email address"));
    }
    if let Some(password_error) = validate_password(&body.password) {
        return respond(StatusCode::BAD_REQUEST, fail(&password_error));
    }
    let row: Result<(i32, String, String, bool), _> = sqlx::query_as(
        "INSERT INTO users (email, password, email_verified, must_change_password)
         VALUES ($1, $2, true, true)
         RETURNING id, email, role, email_verified",
    )
    .bind(&body.email)
    .bind(hash_password(&body.password))
    .fetch_one(&state.db)
    .await;
    let (id, email, role, verified) = match row {
        Ok(row) => row,
        Err(err) => {
            if is_unique_violation(&err) {
                return respond(StatusCode::BAD_REQUEST, fail("Email is already registered"));
            }
            return respond_500("Admin Create User Error", err, true);
        }
    };
    respond(
        StatusCode::CREATED,
        json!({
            "success": true,
            "message": "User created successfully!",
            "user": {
                "id": id,
                "email": email,
                "role": role,
                "emailVerified": verified,
            },
        }),
    )
}

// Staff can nudge a not-yet-verified user's verification email along.
pub async fn staff_resend_verification(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "staff") {
        return rejection;
    }
    let Ok(id) = id.parse::<i32>() else {
        return respond(StatusCode::BAD_REQUEST, msg("Invalid user id"));
    };
    let row: Result<Option<(i32, String, bool)>, _> =
        sqlx::query_as("SELECT id, email, email_verified FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await;
    let (user_id, email, verified) = match row {
        Ok(Some(row)) => row,
        Ok(None) => return respond(StatusCode::NOT_FOUND, msg("User not found")),
        Err(err) => return respond_500("Resend Verification Error", err, false),
    };
    if verified {
        return respond(StatusCode::BAD_REQUEST, msg("User is already verified"));
    }
    if let Err(err) =
        queue::queue_verification_email(&state.db, &state.cfg.frontend_url, user_id, &email).await
    {
        return respond_500("Resend Verification Error", err, false);
    }
    respond(
        StatusCode::OK,
        json!({"success": true, "message": "Verification email sent"}),
    )
}

// Admin-only: flip a user's verified flag directly, no email round-trip.
pub async fn patch_verification(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "admin") {
        return rejection;
    }
    let Ok(id) = id.parse::<i32>() else {
        return respond(StatusCode::BAD_REQUEST, msg("Invalid user id"));
    };
    // Decoded loosely so a present-but-non-boolean value (string, number)
    // reads as not-a-boolean, exactly like `typeof emailVerified !== "boolean"`.
    let body: Value = decode(&body);
    let Some(verified) = body.get("emailVerified").and_then(Value::as_bool) else {
        return respond(
            StatusCode::BAD_REQUEST,
            msg("emailVerified must be a boolean"),
        );
    };
    let row: Result<Option<(i32, String, bool)>, _> = sqlx::query_as(
        "UPDATE users SET email_verified = $1, verification_token = NULL
         WHERE id = $2
         RETURNING id, email, email_verified",
    )
    .bind(verified)
    .bind(id)
    .fetch_optional(&state.db)
    .await;
    let (id, email, verified) = match row {
        Ok(Some(row)) => row,
        Ok(None) => return respond(StatusCode::NOT_FOUND, msg("User not found")),
        Err(err) => return respond_500("Update Verification Error", err, false),
    };
    let response_message = if verified {
        "User marked as verified"
    } else {
        "User marked as unverified"
    };
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": response_message,
            "user": {
                "id": id,
                "email": email,
                "emailVerified": verified,
            },
        }),
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CreateUserBody {
    email: String,
    password: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PatchRoleBody {
    role: String,
}

// Admin-only: changes a user's role. Blocks self-demotion so an admin can't
// lock themselves (and potentially every other admin) out of admin routes.
pub async fn patch_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "admin") {
        return rejection;
    }
    let Ok(id) = id.parse::<i32>() else {
        return respond(StatusCode::BAD_REQUEST, msg("Invalid user id"));
    };
    let body: PatchRoleBody = decode(&body);
    if role_index(&body.role).is_none() {
        return respond(
            StatusCode::BAD_REQUEST,
            msg("role must be one of: client, staff, admin"),
        );
    }
    if id == user.id {
        return respond(StatusCode::BAD_REQUEST, msg("Cannot change your own role"));
    }
    let row: Result<Option<(i32, String, String)>, _> =
        sqlx::query_as("UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, role")
            .bind(&body.role)
            .bind(id)
            .fetch_optional(&state.db)
            .await;
    let (id, email, role) = match row {
        Ok(Some(row)) => row,
        Ok(None) => return respond(StatusCode::NOT_FOUND, msg("User not found")),
        Err(err) => return respond_500("Update Role Error", err, false),
    };
    respond(
        StatusCode::OK,
        json!({
            "success": true,
            "message": "User role updated",
            "user": { "id": id, "email": email, "role": role },
        }),
    )
}

// Admin-only: sends the same reset-password email a user would trigger themselves,
// so an admin never has to see or set anyone's plaintext password.
pub async fn admin_reset_password(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "admin") {
        return rejection;
    }
    let Ok(id) = id.parse::<i32>() else {
        return respond(StatusCode::BAD_REQUEST, msg("Invalid user id"));
    };
    match queue::queue_password_reset(&state.db, &state.cfg.frontend_url, queue::ResetKey::Id(id))
        .await
    {
        Err(QueueError::NotFound) => respond(StatusCode::NOT_FOUND, msg("User not found")),
        Err(err) => respond_500("Admin Reset Password Error", err, false),
        Ok(()) => respond(
            StatusCode::OK,
            json!({"success": true, "message": "Password reset email sent"}),
        ),
    }
}

pub async fn delete_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    if let Err(rejection) = ensure_role(&user, "admin") {
        return rejection;
    }
    let Ok(id) = id.parse::<i32>() else {
        return respond(StatusCode::BAD_REQUEST, msg("Invalid user id"));
    };
    if id == user.id {
        return respond(
            StatusCode::BAD_REQUEST,
            msg("Cannot delete your own account"),
        );
    }
    let tag = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await;
    match tag {
        Err(err) => respond_500("Delete User Error", err, false),
        Ok(result) if result.rows_affected() == 0 => {
            respond(StatusCode::NOT_FOUND, msg("User not found"))
        }
        Ok(_) => respond(
            StatusCode::OK,
            json!({"success": true, "message": "User deleted"}),
        ),
    }
}
