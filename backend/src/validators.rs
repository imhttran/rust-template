// Port of validators.go (auth-related validators; the profile validators —
// phone, zip, URL — land with profile.rs in Phase 3).

use regex::Regex;
use std::sync::LazyLock;

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());

// US phone numbers only, digits with optional standard formatting
// (spaces/dots/dashes/parens) and an optional leading +1/1.
static PHONE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$").unwrap());

// US zip codes only — 5 digits, matching the frontend's pattern="[0-9]{5}"
// (no ZIP+4 support yet).
static ZIP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{5}$").unwrap());

pub fn validate_email(email: &str) -> bool {
    EMAIL_RE.is_match(email)
}

pub fn validate_phone(phone: &str) -> bool {
    PHONE_RE.is_match(phone)
}

pub fn validate_zip(zip: &str) -> bool {
    ZIP_RE.is_match(zip)
}

// http(s) only — good enough for LinkedIn/GitHub profile links.
pub fn validate_url(raw_url: &str) -> bool {
    match url::Url::parse(raw_url) {
        Ok(u) => (u.scheme() == "http" || u.scheme() == "https") && u.host().is_some(),
        Err(_) => false,
    }
}

// Port of common/usStates.js — one list shared with the frontend so the two
// can't drift out of sync.
const US_STATE_CODES: &[&str] = &[
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA",
    "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM",
    "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY",
];

// One entry today, but a list, so adding a second country later is additive.
const COUNTRY_CODES: &[&str] = &["US"];

pub fn is_us_state(state: &str) -> bool {
    US_STATE_CODES.contains(&state)
}

pub fn is_country(country: &str) -> bool {
    COUNTRY_CODES.contains(&country)
}

// Returns an error message describing the first unmet rule, or None if valid.
pub fn validate_password(password: &str) -> Option<String> {
    // Go's len() counts bytes — match that, not chars.
    if password.len() < 8 {
        return Some("Password must be at least 8 characters long".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Some("Password must contain at least one uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Some("Password must contain at least one number".to_string());
    }
    static SPECIAL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"[!@#$%^&*(),.?":{}|<>]"#).unwrap());
    if !SPECIAL_RE.is_match(password) {
        return Some("Password must contain at least one special character".to_string());
    }
    None
}
