// Открытие базы SQLite (better-sqlite3) и применение схемы из schema.sql.
import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';

// Схема лежит рядом с этим файлом; читаем один раз при загрузке модуля.
const schema = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');

// Часть схемы про audit (таблица, индексы, триггеры append-only) для ротации (П-37): берётся из schema.sql, не дублируется.
export const AUDIT_DDL = schema.slice(schema.indexOf('CREATE TABLE IF NOT EXISTS audit ('));
export const AUDIT_TABLE_DDL = AUDIT_DDL.slice(0, AUDIT_DDL.indexOf(');') + 2);

/**
 * Открывает базу по пути (или ':memory:'), включает foreign_keys и WAL
 * (WAL не применяется к :memory:), затем накатывает схему (IF NOT EXISTS, идемпотентно).
 * @param {string} path
 * @returns {import('better-sqlite3').Database}
 */
export function openDb(path) {
  const db = new Database(path);
  // foreign_keys — per-connection настройка, внутри транзакции её менять нельзя, поэтому ставим до схемы.
  db.pragma('foreign_keys = ON');
  if (path !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  // Н-3: старая sessions хранила открытый id (колонка id). Пересчитать в хэш нельзя, поэтому таблица
  // удаляется, все сессии закрываются, владелец входит заново один раз. Выполняется до schema.sql
  // (индекс новой схемы ссылается на user_id). Секреты 2FA, привязанные к старым сессиям, тоже удаляются.
  const oldSessions = db.prepare('PRAGMA table_info(sessions)').all().map((c) => c.name);
  if (oldSessions.length && !oldSessions.includes('id_hash')) {
    db.transaction(() => {
      db.exec('DROP TABLE sessions');
      if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'").get()) {
        db.exec("DELETE FROM meta WHERE key LIKE 'pending:%'");
      }
    })();
  }
  db.exec(schema);
  // миграции для уже существующих баз
  const credCols = db.prepare('PRAGMA table_info(credentials)').all().map((c) => c.name);
  if (!credCols.includes('always_until')) db.exec('ALTER TABLE credentials ADD COLUMN always_until INTEGER;');
  if (!credCols.includes('filter_json')) db.exec('ALTER TABLE credentials ADD COLUMN filter_json TEXT;');
  // Уже созданным агентам остаются все ключи (DEFAULT 1), привязку владелец включает сам.
  const agentCols = db.prepare('PRAGMA table_info(agents)').all().map((c) => c.name);
  if (!agentCols.includes('all_credentials')) db.exec('ALTER TABLE agents ADD COLUMN all_credentials INTEGER NOT NULL DEFAULT 1;');
  // Один пропуск на заявку (П-10). В старой базе дубликатов быть не должно; если есть — индекс не создаётся, шлюз работает,
  // а buildApp пишет об этом в журнал (repo.hasGrantsRequestIndex). Прочие ошибки не скрываем.
  try {
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS grants_request ON grants(request_id);');
  } catch (e) {
    if (!String(e.code).startsWith('SQLITE_CONSTRAINT')) throw e;
  }
  return db;
}
