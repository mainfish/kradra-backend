use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct MeUser {
    pub id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: MeUser,
}
