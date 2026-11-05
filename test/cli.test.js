// Тесты CLI (П-35, П-37): restore чистит незавершённые состояния, init, ротация аудита, backup.sh. Без сети и AWS, сейф file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { createVault } from '../src/vault/index.js';
import { runInit, runRestore, runAuditRotate } from '../src/cli.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const DAY = 86400;
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

function mkConfig() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-cli-'));
  return {
    dataDir, dbPath: path.join(dataDir, 'gw.db'), publicUrl: 'http://127.0.0.1:8080', vault: 'file',
    vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
  };
}

const cred = (id) => ({
  id, provider: 'openrouter', label: 'k-' + id, kind: 'static', host: 'openrouter.ai',
  injection: { type: 'header', name: 'Authorization', prefix: 'Bearer ' }, vault_param: 'cred/' + id,
  mode: 'ask', approval: 'web_button', max_ttl: 3600, max_calls: 100, max_parallel: 2, window: null, expires_at: null, last4: 'abcd',
});

/** База с «грязными» незавершёнными состояниями. */
function seedDirty(repo, db) {
  repo.createAgent({ id: 'a1', name: 'agent', token_hash: 'th1', enabled: 1 });
  repo.createCredential(cred('c1'));
  repo.createCredential(cred('c2'));
  const exp = db.prepare('SELECT unixepoch() + 600 AS t').get().t;
  repo.createRequest({ id: 'r-pend', agent_id: 'a1', credential_id: 'c1', ttl: 60, calls: 1, reason: 'x', status: 'pending', expires_at: exp });
  repo.createRequest({ id: 'r-ok', agent_id: 'a1', credential_id: 'c1', ttl: 60, calls: 1, reason: 'x', status: 'approved', expires_at: exp });
  repo.createGrant({ id: 'g1', request_id: 'r-ok', agent_id: 'a1', credential_id: 'c1', expires_at: exp + 3600, max_calls: 5, max_parallel: 1 });
  for (const k of ['setup_totp_secret', 'setup_backup_codes', 'setup_tg_code', 'reissue_totp_secret', 'new_backup_codes', 'pending:reissue:abc']) repo.setMeta(k, 'secret-value');
  repo.setMeta('csrf_key', 'keep-me');
  repo.createSession('hash1', exp, 'ua');
  repo.takeTotpStep('owner', 12345);
  repo.createLink('lh1', 'open', exp);
}

test('restore: чистит pending, временные секреты, сессии, TOTP-шаги, ссылки; пропуска отозваны; нет ключа в сейфе → удалён', async () => {
  const cfg = mkConfig();
  const backup = path.join(cfg.dataDir, 'backup.db');
  const src = openDb(backup); seedDirty(createRepo(src), src); src.close();
  const vault = createVault(cfg);
  await vault.put('cred/c1', 'sk-test-value'); // у c2 значения в сейфе нет

  const out = [];
  const res = await runRestore({ config: cfg, vault, file: backup, log: (s) => out.push(s) });
  assert.equal(res.missing, 1);
  assert.equal(res.grants, 1);
  assert.equal(res.requests, 1);
  assert.match(out[0], /Restored/);

  const db = openDb(cfg.dbPath); const repo = createRepo(db);
  assert.equal(db.prepare("SELECT status FROM requests WHERE id = 'r-pend'").get().status, 'expired');
  assert.equal(db.prepare("SELECT status FROM requests WHERE id = 'r-ok'").get().status, 'approved');
  assert.equal(repo.listActiveGrants().length, 0);
  for (const k of ['setup_totp_secret', 'setup_backup_codes', 'setup_tg_code', 'reissue_totp_secret', 'new_backup_codes', 'pending:reissue:abc']) assert.ok(!repo.getMeta(k), k);
  assert.equal(repo.getMeta('csrf_key'), 'keep-me');
  assert.equal(repo.listSessions().length, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM totp_used').get().n, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM one_time_links').get().n, 0);
  assert.deepEqual(repo.listCredentials().map((c) => c.id), ['c1']);
  const last = db.prepare("SELECT * FROM audit WHERE action = 'restore'").get();
  assert.ok(last);
  assert.ok(!last.meta_json.includes('secret-value'));
  assert.ok(await vault.get('sys/signing'));
  db.close();
});

test('restore: файл не найден и «сама база» отвергаются', async () => {
  const cfg = mkConfig();
  const vault = createVault(cfg);
  await assert.rejects(runRestore({ config: cfg, vault, file: path.join(cfg.dataDir, 'nope.db') }), /backup file/);
  fs.writeFileSync(cfg.dbPath, '');
  await assert.rejects(runRestore({ config: cfg, vault, file: cfg.dbPath }), /live database/);
});

test('init: сброс владельца и временных состояний, ключи и агенты остаются, печатается ссылка', () => {
  const cfg = mkConfig();
  const db = openDb(':memory:'); const repo = createRepo(db);
  seedDirty(repo, db);
  repo.setPasswordHash('hash'); repo.setTotp('enc', 1); repo.setSetupDone();
  repo.replaceBackupCodes(['h1', 'h2']);
  const out = [];
  const r = runInit({ repo, config: cfg, log: (s) => out.push(s) });
  assert.equal(r.grants, 1);
  assert.match(out[0], /http:\/\/127\.0\.0\.1:8080\/setup\//);
  const o = repo.getOwner();
  assert.equal(o.setup_done, 0); assert.equal(o.totp_enabled, 0); assert.equal(o.password_hash, null);
  assert.equal(repo.listCredentials().length, 2);
  assert.equal(repo.listAgents().length, 1);
  assert.equal(db.prepare('SELECT count(*) AS n FROM backup_codes').get().n, 0);
  assert.ok(!repo.getMeta('setup_totp_secret'));
  assert.equal(db.prepare('SELECT count(*) AS n FROM one_time_links').get().n, 1); // только новая ссылка мастера
});

function oldAuditSetup() {
  const cfg = mkConfig();
  const db = openDb(cfg.dbPath); const repo = createRepo(db);
  const now = db.prepare('SELECT unixepoch() AS t').get().t;
  const ins = db.prepare('INSERT INTO audit (at, actor, action, target, meta_json) VALUES (?, ?, ?, ?, ?)');
  ins.run(now - 200 * DAY, 'owner', 'old.one', 't1', '{"n":1}');
  ins.run(now - 100 * DAY, 'owner', 'old.two', null, null);
  ins.run(now - 10 * DAY, 'owner', 'new.one', null, null);
  ins.run(now - 1 * DAY, 'owner', 'new.two', null, null);
  return { cfg, db, repo, now };
}

test('audit rotate: старые строки в архив 0600, новые остаются, триггеры на месте, запись audit.rotated', () => {
  const { cfg, db, repo, now } = oldAuditSetup();
  const outDir = path.join(cfg.dataDir, 'arch');
  const log = []; const warn = [];
  const r = runAuditRotate({ repo, config: cfg, days: 90, outDir, log: (s) => log.push(s), warn: (s) => warn.push(s) });
  assert.equal(r.archived, 2);
  assert.match(warn[0], /stop the gateway/);
  const files = fs.readdirSync(outDir);
  assert.equal(files.length, 1);
  assert.match(files[0], /^audit-\d{8}-\d{8}\.jsonl$/);
  const file = path.join(outDir, files[0]);
  const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(rows.map((x) => x.action), ['old.one', 'old.two']);
  assert.equal(rows[0].meta_json, '{"n":1}');
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);

  const left = db.prepare('SELECT action FROM audit ORDER BY id').all().map((x) => x.action);
  assert.deepEqual(left, ['new.one', 'new.two', 'audit.rotated']);
  const rot = db.prepare("SELECT * FROM audit WHERE action = 'audit.rotated'").get();
  const meta = JSON.parse(rot.meta_json);
  assert.equal(meta.archived, 2);
  assert.equal(meta.file, files[0]);
  assert.ok(Math.abs(meta.cutoff - (now - 90 * DAY)) <= 5);
  // id не сбрасываются: новая запись идёт после всех прежних
  assert.ok(rot.id > 4);
  // индексы и оба триггера на месте
  const names = db.prepare("SELECT name FROM sqlite_master WHERE tbl_name = 'audit'").all().map((x) => x.name);
  for (const n of ['audit_at', 'audit_action_at', 'audit_no_update', 'audit_no_delete']) assert.ok(names.includes(n), n);
  assert.ok(!db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'audit_new'").get());
  assert.throws(() => db.prepare('DELETE FROM audit').run(), /append-only/);
  assert.throws(() => db.prepare("UPDATE audit SET actor = 'x'").run(), /append-only/);
  repo.audit('system', 'after.rotate', null); // сервер продолжает писать
  assert.equal(db.prepare("SELECT count(*) AS n FROM audit WHERE action = 'after.rotate'").get().n, 1);
  db.close();
});

test('audit rotate: нечего архивировать — файл не создаётся, таблица не тронута', () => {
  const cfg = mkConfig();
  const db = openDb(cfg.dbPath); const repo = createRepo(db);
  repo.audit('owner', 'fresh', null);
  const outDir = path.join(cfg.dataDir, 'arch');
  const r = runAuditRotate({ repo, config: cfg, days: 90, outDir });
  assert.equal(r.archived, 0);
  assert.ok(!fs.existsSync(outDir));
  assert.equal(db.prepare('SELECT count(*) AS n FROM audit').get().n, 1);
  assert.throws(() => runAuditRotate({ repo, config: cfg, days: 0 }), /positive integer/);
  db.close();
});

test('audit rotate: сбой записи архива оставляет таблицу нетронутой', () => {
  const { cfg, db, repo } = oldAuditSetup();
  const blocker = path.join(cfg.dataDir, 'not-a-dir');
  fs.writeFileSync(blocker, 'x'); // файл на месте каталога: mkdir/запись упадёт
  assert.throws(() => runAuditRotate({ repo, config: cfg, days: 90, outDir: path.join(blocker, 'sub') }));
  const actions = db.prepare('SELECT action FROM audit ORDER BY id').all().map((x) => x.action);
  assert.deepEqual(actions, ['old.one', 'old.two', 'new.one', 'new.two']);
  assert.ok(!db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'audit_new'").get());
  assert.throws(() => db.prepare('DELETE FROM audit').run(), /append-only/);
  db.close();
});

const script = path.join(root, 'scripts', 'backup.sh');
const bashOk = spawnSync('bash', ['-c', 'exit 0']).status === 0;

test('backup.sh: синтаксис bash -n', { skip: !bashOk && 'bash недоступен' }, () => {
  const r = spawnSync('bash', ['-n', script.replace(/\\/g, '/')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

test('backup.sh: ветки с открытой копией нет, шифрование обязательно, сейф включён в архив', () => {
  const s = fs.readFileSync(script, 'utf8');
  assert.ok(!/not encrypted/i.test(s));
  assert.ok(!/FINAL="\$PLAIN"/.test(s));
  assert.match(s, /nothing to encrypt with[^\n]*\n[^\n]*\n\s*exit 1/);
  assert.match(s, /trap rm_plain EXIT/);
  assert.ok(s.includes('vault.json') && s.includes('master.key'));
  assert.ok(!s.includes('trap - EXIT'));
});
