use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateUserRoleRequest {
    pub role: String,
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
