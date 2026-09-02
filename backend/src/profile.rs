// Port of profile.go — the one-time registration form, submitted once per
// user. A missing row (not a boolean flag, unlike must_change_password) is
// what gates a user into the completion form.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::routes::{decode, is_unique_violation, msg, respond, respond_500, AuthUser};
use crate::state::AppState;
use crate::validators::{
    is_country, is_us_state, validate_email, validate_phone, validate_url, validate_zip,
};

// Field names match the Postgres columns; serde's camelCase rename produces
// the wire format. Nullable columns are Option, matching Go's *string.
#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: i32,
    pub user_id: i32,
    pub first_name: String,
    pub last_name: String,
    pub address: String,
    pub address2: Option<String>,
    pub state: String,
    pub zip: String,
    pub country: String,
    pub phone: String,
    pub communication_preference: String,
    pub linkedin: Option<String>,
    pub github: Option<String>,
    pub alt_email: Option<String>,
}

const PROFILE_COLUMNS: &str = "id, user_id, first_name, last_name, address, address2, state, zip, country, phone, communication_preference, linkedin, github, alt_email";

pub async fn get_profile(State(state): State<AppState>, user: AuthUser) -> Response {
    let sql = format!("SELECT {PROFILE_COLUMNS} FROM user_profiles WHERE user_id = $1");
    let profile: Result<Option<Profile>, _> = sqlx::query_as(&sql)
        .bind(user.id)
        .fetch_optional(&state.db)
        .await;
    match profile {
        // Mirrors the Go handler: a missing profile is a 200 with null, not a
        // 404 — the absence is the gate, not an error.
        Ok(profile) => respond(StatusCode::OK, json!({ "profile": profile })),
        Err(err) => respond_500("Get Profile Error", err, false),
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct ProfileInput {
    pub first_name: String,
    pub last_name: String,
    pub address: String,
    pub address2: Option<String>,
    pub state: String,
    pub zip: String,
    pub country: String,
    pub phone: String,
    pub communication_preference: String,
    pub linkedin: Option<String>,
    pub github: Option<String>,
    pub alt_email: Option<String>,
}

const COMMUNICATION_PREFERENCES: &[&str] = &["email", "text", "phone"];

// `body.x?.trim() || null` — blank optionals are stored as NULL.
fn optional_trimmed(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

// One-time registration form. Returns an error message describing the first
// unmet rule, or None if valid (same convention as validate_password).
pub fn validate_profile_fields(body: &ProfileInput) -> Option<String> {
    let required = [
        ("firstName", body.first_name.as_str()),
        ("lastName", body.last_name.as_str()),
        ("address", body.address.as_str()),
        ("state", body.state.as_str()),
        ("zip", body.zip.as_str()),
        ("phone", body.phone.as_str()),
        (
            "communicationPreference",
            body.communication_preference.as_str(),
        ),
    ];
    let missing: Vec<&str> = required
        .iter()
        .filter(|(_, value)| value.trim().is_empty())
        .map(|(name, _)| *name)
        .collect();
    if !missing.is_empty() {
        return Some(format!("Missing required field(s): {}", missing.join(", ")));
    }
    if !COMMUNICATION_PREFERENCES.contains(&body.communication_preference.as_str()) {
        return Some(format!(
            "communicationPreference must be one of: {}",
            COMMUNICATION_PREFERENCES.join(", ")
        ));
    }
    if !validate_phone(&body.phone) {
        return Some("Phone number is invalid".to_string());
    }
    if !validate_zip(&body.zip) {
        return Some("Zip code is invalid".to_string());
    }
    if !is_us_state(&body.state) {
        return Some("State is invalid".to_string());
    }
    // Dropdown only ever offers what's in COUNTRY_CODES, but a direct API call
    // could still send something else.
    if !body.country.is_empty() && !is_country(&body.country) {
        return Some("Country is invalid".to_string());
    }
    if let Some(alt_email) = body.alt_email.as_deref() {
        if !alt_email.is_empty() && !validate_email(alt_email) {
            return Some("Additional email address is invalid".to_string());
        }
    }
    if let Some(linkedin) = body.linkedin.as_deref() {
        if !linkedin.is_empty() && !validate_url(linkedin) {
            return Some("LinkedIn URL is invalid".to_string());
        }
    }
    if let Some(github) = body.github.as_deref() {
        if !github.is_empty() && !validate_url(github) {
            return Some("GitHub URL is invalid".to_string());
        }
    }
    None
}

pub async fn save_profile(State(state): State<AppState>, user: AuthUser, body: Bytes) -> Response {
    let body: ProfileInput = decode(&body);
    if let Some(validation_error) = validate_profile_fields(&body) {
        return respond(StatusCode::BAD_REQUEST, msg(&validation_error));
    }
    // Blank country falls back to 'US' (mirrors the Go handler).
    let country = body.country.trim();
    let country = if country.is_empty() { "US" } else { country };
    let sql = format!(
        "INSERT INTO user_profiles
             (user_id, first_name, last_name, address, address2, state, zip, country,
              phone, communication_preference, linkedin, github, alt_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING {PROFILE_COLUMNS}"
    );
    let result: Result<Profile, _> = sqlx::query_as(&sql)
        .bind(user.id)
        .bind(body.first_name.trim())
        .bind(body.last_name.trim())
        .bind(body.address.trim())
        .bind(optional_trimmed(&body.address2))
        .bind(body.state.trim())
        .bind(body.zip.trim())
        .bind(country)
        .bind(body.phone.trim())
        .bind(&body.communication_preference)
        .bind(optional_trimmed(&body.linkedin))
        .bind(optional_trimmed(&body.github))
        .bind(optional_trimmed(&body.alt_email))
        .fetch_one(&state.db)
        .await;
    let profile = match result {
        Ok(profile) => profile,
        Err(err) => {
            if is_unique_violation(&err) {
                return respond(StatusCode::BAD_REQUEST, msg("Profile already exists"));
            }
            return respond_500("Save Profile Error", err, false);
        }
    };
    respond(
        StatusCode::CREATED,
        json!({
            "success": true,
            "message": "Profile saved!",
            "profile": profile,
        }),
    )
}
