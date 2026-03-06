use crate::error::AppError;

pub async fn me() -> Result<(), AppError> {
    Err(AppError::Unauthorized)
}
