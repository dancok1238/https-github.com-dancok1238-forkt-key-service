CREATE TABLE IF NOT EXISTS user_keys (
    key_id TEXT PRIMARY KEY,
    roblox_user_id TEXT NOT NULL,
    roblox_username TEXT,
    key_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_hash TEXT PRIMARY KEY,
    roblox_user_id TEXT NOT NULL,
    roblox_username TEXT,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS key_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_keys_status ON user_keys(status);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_key_per_user
    ON user_keys(roblox_user_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expiry ON oauth_states(expires_at);
