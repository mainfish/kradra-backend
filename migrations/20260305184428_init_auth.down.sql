DROP TABLE IF EXISTS refresh_tokens;
DROP TRIGGER IF EXISTS users_set_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();
DROP TABLE IF EXISTS users;
-- DROP EXTENSION IF EXISTS pgcrypto;
