-- Users table
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT    NOT NULL UNIQUE,
  password   TEXT    NOT NULL,
  name       TEXT    NOT NULL DEFAULT '',
  role       TEXT    NOT NULL CHECK(role IN ('executive', 'admin')),
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- One-time registration keys
CREATE TABLE IF NOT EXISTS registration_keys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key         TEXT    NOT NULL UNIQUE,
  role        TEXT    NOT NULL CHECK(role IN ('executive', 'admin')),
  used        INTEGER NOT NULL DEFAULT 0,
  used_by     INTEGER DEFAULT NULL,
  used_at     TEXT    DEFAULT NULL,
  created_by  INTEGER NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT    NOT NULL,
  FOREIGN KEY (used_by)    REFERENCES users(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Index for fast key lookup
CREATE INDEX IF NOT EXISTS idx_registration_keys_key ON registration_keys(key);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
