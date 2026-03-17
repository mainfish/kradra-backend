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
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub is_revoked: bool,
    pub is_replaced: bool,
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserSessionsResponse {
    pub sessions: Vec<AdminUserSessionDto>,
}
