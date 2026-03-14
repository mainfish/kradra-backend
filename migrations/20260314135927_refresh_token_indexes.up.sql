CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_token_hash_uq
ON refresh_tokens (token_hash);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_revoked_at_idx
ON refresh_tokens (user_id, revoked_at);