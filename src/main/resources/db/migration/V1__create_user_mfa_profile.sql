CREATE TABLE IF NOT EXISTS user_mfa_profile (
    id               BIGSERIAL PRIMARY KEY,
    user_id          VARCHAR(255) NOT NULL,
    encrypted_secret VARCHAR(512) NOT NULL,
    algorithm        VARCHAR(20)  NOT NULL,
    enabled          BOOLEAN      NOT NULL DEFAULT TRUE,
    version          BIGINT       NOT NULL DEFAULT 0,
    created_at       TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP    NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_mfa_profile_user_id UNIQUE (user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_profile_user_id ON user_mfa_profile (user_id);
