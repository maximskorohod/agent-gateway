// Логика команд CLI (init, restore, audit rotate); bin/gateway.js только разбирает аргументы.
// Всё приходит через deps, чтобы команды можно было тестировать без процесса и сети.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openDb } from './db/index.js';
import { createRepo } from './db/repo.js';
import { makeLink } from './auth/links.js';
import { t } from './i18n.js';

const noop = () => {};

/**
 * Повторный мастер: пароль, 2FA и Telegram заново; ключи и агенты остаются (ТЗ §11).
 * @param {{ repo: object, config: object, log?: Function }} deps
 */
export function runInit({ repo, config, log = noop }) {
  repo.resetOwnerSetup();
  const reset = repo.resetPendingStates();
  repo.audit('system', 'init', null, { revoked: reset.grants });
  const { url } = makeLink(repo, 'setup', 900, config.publicUrl);
  log('\n' + t('cli.init_open') + '\n\n  ' + url + '\n');
  return { url, ...reset };
}

/**
 * Восстановление из расшифрованного файла базы (шлюз остановлен): подмена gw.db, новый ключ подписи пропусков,
 * сброс незавершённых состояний (П-35), сверка credentials с сейфом.
 * @param {{ config: object, vault: object, file: string, log?: Function }} deps
 */
export async function runRestore({ config, vault, file, log = noop }) {
  if (!file || !fs.existsSync(file)) throw Object.assign(new Error(t('cli.restore_file')), { exitCode: 2 });
  if (path.resolve(file) === path.resolve(config.dbPath)) throw Object.assign(new Error(t('cli.restore_same')), { exitCode: 2 });
  for (const suf of ['', '-wal', '-shm']) if (fs.existsSync(config.dbPath + suf)) fs.unlinkSync(config.dbPath + suf);
  fs.copyFileSync(file, config.dbPath);
  const db = openDb(config.dbPath);
  try {
    const repo = createRepo(db);
    await vault.put('sys/signing', crypto.randomBytes(32).toString('hex')); // все старые пропуска недействительны
    const reset = repo.resetPendingStates();
    let missing = 0;
    for (const c of repo.listCredentials()) {
      if (!(await vault.get(`cred/${c.id}`))) { repo.softDeleteCredential(c.id); missing++; }
    }
    repo.audit('system', 'restore', path.basename(file), { revoked: reset.grants, missingKeys: missing, requestsExpired: reset.requests, metaCleared: reset.meta });
    log(t('cli.restored', { n: reset.grants, missing, requests: reset.requests }));
    return { ...reset, missing };
  } finally {
    db.close();
  }
}

const pad = (n) => String(n).padStart(2, '0');
const day = (sec) => { const d = new Date(sec * 1000); return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`; };

/** Пишет архив JSON Lines (0600, fsync) во временный файл и переименовывает; -> итоговый путь. */
function writeArchiveFile(dir, rows) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const base = `audit-${day(rows[0].at)}-${day(rows[rows.length - 1].at)}`;
  let final = path.join(dir, base + '.jsonl');
  for (let i = 1; fs.existsSync(final); i++) final = path.join(dir, `${base}-${i}.jsonl`);
  const tmp = final + '.tmp';
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
    fs.fsyncSync(fd);
  } catch (e) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw e;
  }
  fs.closeSync(fd);
  fs.renameSync(tmp, final);
  return final;
}

/**
 * Ротация аудита (П-37, Н-6): строки старше days уходят в архив, таблица пересоздаётся вместе с триггерами.
 * Запускать при остановленном шлюзе: сервер держит подготовленные запросы к audit.
 * @param {{ repo: object, config: object, days?: number, outDir?: string, log?: Function, warn?: Function }} deps
 */
export function runAuditRotate({ repo, config, days = 90, outDir, log = noop, warn = noop }) {
  if (!Number.isInteger(days) || days < 1) throw Object.assign(new Error(t('cli.audit_days')), { exitCode: 2 });
  warn(t('cli.audit_stop_warning'));
  const dir = outDir || path.join(config.dataDir, 'audit-archive');
  const r = repo.rotateAudit(days, (rows) => writeArchiveFile(dir, rows));
  log(r.archived ? t('cli.audit_rotated', { n: r.archived, file: r.file }) : t('cli.audit_nothing', { days }));
  return r;
}
