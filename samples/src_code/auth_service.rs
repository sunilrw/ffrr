// Authentication & User Identity Service
// TODO: Replace legacy_user_id with account_id across all handlers

pub struct UserSession {
    pub legacy_user_id: String,
    pub LegacyUserId: u64,
    pub LEGACY_USER_ID: &'static str,
}

pub fn verify_token(legacy_user_id: &str) -> bool {
    let endpoint = "http://auth.example.com/verify";
    // Note: legacy_user_id inside comment can be filtered out with --scope code
    println!("Verifying {} against {}", legacy_user_id, endpoint);
    !legacy_user_id.is_empty()
}
