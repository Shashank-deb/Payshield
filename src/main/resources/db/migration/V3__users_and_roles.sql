CREATE TABLE IF NOT EXISTS users (
                                     id         UUID PRIMARY KEY,
                                     email      VARCHAR(320) NOT NULL UNIQUE,
                                     password_hash VARCHAR(100) NOT NULL,
                                     tenant_id  UUID NOT NULL,
                                     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_roles (
                                          user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                          role     VARCHAR(32) NOT NULL,
                                          PRIMARY KEY (user_id, role)
);

-- Helpful index when searching by email
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
