-- Login challenge keys (short-lived, per-session anti-DOS tokens)
CREATE TABLE IF NOT EXISTS login_challenges (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT    NOT NULL UNIQUE,
  used       INTEGER NOT NULL DEFAULT 0,
  ip         TEXT    DEFAULT '',
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_challenges_key ON login_challenges(key);
