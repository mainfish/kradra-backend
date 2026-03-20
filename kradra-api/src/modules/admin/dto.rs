use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateUserRoleRequest {
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateUserActiveRequest {
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserResponse {
    pub user: AdminUserDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUsersResponse {
    pub users: Vec<AdminUserDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserDto {
    pub id: String,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserSessionDto {
    pub id: String,
    pub ip: String,
    pub user_agent: String,
    pub is_revoked: bool,
    pub is_replaced: bool,
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserSessionsResponse {
    pub sessions: Vec<AdminUserSessionDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminRegistrationSettingsResponse {
    pub registration_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateRegistrationSettingsRequest {
    pub registration_enabled: bool,
}
