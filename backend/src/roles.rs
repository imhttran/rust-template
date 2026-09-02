// Port of roles.go — ranked lowest to highest: a role satisfies a check for
// itself or anything below it.

pub const ROLES: [&str; 3] = ["client", "staff", "admin"];

pub fn role_index(role: &str) -> Option<usize> {
    ROLES.iter().position(|r| *r == role)
}

pub fn has_role(user_role: &str, min_role: &str) -> bool {
    match (role_index(user_role), role_index(min_role)) {
        (Some(ui), Some(mi)) => ui >= mi,
        _ => false,
    }
}
