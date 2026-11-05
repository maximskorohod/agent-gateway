-- Схема данных v1.1 (раздел 10 ТЗ). Время везде — unixepoch().
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owner (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash   TEXT,
  totp_secret_enc TEXT,
  totp_enabled    INTEGER NOT NULL DEFAULT 0,
  tg_chat_id      INTEGER,
  tg_bot_param    TEXT,
  setup_done      INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS backup_codes (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL,
  used_at   INTEGER
);

-- Н-3: в базе только sha256 от cookie; дамп базы не даёт войти. user_id — константа 'owner' без FK (users придёт позже).
CREATE TABLE IF NOT EXISTS sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL DEFAULT 'owner',
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at   INTEGER NOT NULL,
  ua           TEXT,
  totp_ok      INTEGER NOT NULL DEFAULT 0,
  totp_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, totp_ok);

-- П-32: использованные шаги TOTP; переживают перезапуск, чистятся reap-циклом (старше 10 минут)
CREATE TABLE IF NOT EXISTS totp_used (
  user_id TEXT NOT NULL,
  step    INTEGER NOT NULL,
  used_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (user_id, step)
);

-- П-19: черновик действия, сохранённый при уходе на ввод кода 2FA. Одна запись на сессию (UNIQUE), удаляется вместе с сессией.
-- user_id — константа владельца без FK на users (таблица придёт с командой); body_json — только поля allowlist типа, без секретов.
CREATE TABLE IF NOT EXISTS pending_actions (
  id           TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL UNIQUE REFERENCES sessions(id_hash) ON DELETE CASCADE,
  user_id      TEXT NOT NULL,
  type         TEXT NOT NULL,
  target_id    TEXT NOT NULL,
  version      TEXT NOT NULL,
  body_json    TEXT NOT NULL,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_links (
  token_hash TEXT PRIMARY KEY,
  purpose    TEXT NOT NULL CHECK (purpose IN ('setup','open','tg_link')),
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS credentials (
  id             TEXT PRIMARY KEY,
  provider       TEXT NOT NULL,
  label          TEXT NOT NULL,
  kind           TEXT NOT NULL CHECK (kind IN ('static','path')),
  host           TEXT NOT NULL,
  injection_json TEXT NOT NULL,
  vault_param    TEXT NOT NULL,
  mode           TEXT NOT NULL DEFAULT 'ask' CHECK (mode IN ('always','ask','deny')),
  approval       TEXT NOT NULL DEFAULT 'web_button' CHECK (approval IN ('tg_button','tg_code','web_button','web_code')),
  max_ttl        INTEGER NOT NULL DEFAULT 3600,
  max_calls      INTEGER NOT NULL DEFAULT 100,
  max_parallel   INTEGER NOT NULL DEFAULT 2,
  window_json    TEXT,
  expires_at     INTEGER,
  always_until   INTEGER, -- mode='always' до этого момента, потом ключ возвращается в 'ask'; NULL = бессрочно
  last4          TEXT NOT NULL,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
  deleted_at     INTEGER,
  filter_json    TEXT -- фильтр данных (ТЗ v1.3): {enabled, preset, methods, fields}; NULL = выключен
);

CREATE TABLE IF NOT EXISTS agents (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  enabled      INTEGER NOT NULL DEFAULT 1,
  all_credentials INTEGER NOT NULL DEFAULT 1, -- 1: агенту доступны все ключи; 0: только из agent_credentials
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  last_seen_at INTEGER
);

-- Какие ключи доступны агенту при all_credentials = 0
CREATE TABLE IF NOT EXISTS agent_credentials (
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL REFERENCES credentials(id),
  PRIMARY KEY (agent_id, credential_id)
);

CREATE TABLE IF NOT EXISTS requests (
  id            TEXT PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES agents(id),
  credential_id TEXT NOT NULL REFERENCES credentials(id),
  ttl           INTEGER NOT NULL,
  calls         INTEGER NOT NULL,
  reason        TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at    INTEGER NOT NULL,
  decided_at    INTEGER,
  decided_via   TEXT CHECK (decided_via IN ('tg','web','auto','timeout')),
  tg_message_id INTEGER
);
CREATE INDEX IF NOT EXISTS requests_pending ON requests(status, expires_at);

CREATE TABLE IF NOT EXISTS grants (
  id            TEXT PRIMARY KEY,
  request_id    TEXT NOT NULL REFERENCES requests(id),
  agent_id      TEXT NOT NULL REFERENCES agents(id),
  credential_id TEXT NOT NULL REFERENCES credentials(id),
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at    INTEGER NOT NULL,
  max_calls     INTEGER NOT NULL,
  calls_used    INTEGER NOT NULL DEFAULT 0,
  max_parallel  INTEGER NOT NULL,
  inflight      INTEGER NOT NULL DEFAULT 0,
  revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS grants_active ON grants(agent_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS leases (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  grant_id   TEXT NOT NULL REFERENCES grants(id),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS leases_exp ON leases(expires_at);

CREATE TABLE IF NOT EXISTS audit (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  at        INTEGER NOT NULL DEFAULT (unixepoch()),
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT,
  meta_json TEXT
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
-- Журнал вызовов для страницы «Запросы»: action = 'proxy.call' за период
CREATE INDEX IF NOT EXISTS audit_action_at ON audit(action, at);

-- Аудит только на запись (раздел 9.8)
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN
  SELECT RAISE(ABORT, 'audit is append-only');
END;
