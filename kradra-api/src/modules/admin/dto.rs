use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AdminUserDto {
    pub id: String,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUsersResponse {
    pub users: Vec<AdminUserDto>,
}
