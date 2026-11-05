// Н-3 и П-32: сессии хранятся по хэшу, лимит полных сессий вытесняет при markTotp, шаги TOTP живут в базе.
// Контрактные тесты 25 и 26 (docs/contracts/drafts-team-auth.md). Без сети: vault file, fetch на localhost.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { buildApp } from '../src/app.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-sess-'));
const dbPath = path.join(dataDir, 'gw.db');
const mkApp = (dir = dataDir) => buildApp({ dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });

let app, base, totpSecret, step0;
const usedSteps = new Set();
/** Шаг из окна ±1, который ещё не использован в этом тестовом файле. */
function freshCode() {
  const s = Math.floor(Date.now() / 30000);
  const step = [s, s - 1, s + 1].find((x) => !usedSteps.has(x));
  usedSteps.add(step);
  return totpAt(totpSecret, step);
}

function client() {
  const jar = new Map();
  const c = { jar, token: '' };
  const store = (res) => {
    for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' });
    store(r);
    const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/);
    if (m) c.token = m[1];
    return r;
  };
  c.post = async (p, fields = {}) => {
    const body = new URLSearchParams({ _csrf: c.token, ...fields });
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
    store(r);
    return r;
  };
  return c;
}

/** Полная сессия по ссылке мастера (без кода) — удобный способ получить сессию, не расходуя шаги TOTP. */
async function fullViaSetupLink() {
  const c = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  const r = await c.get(`/setup/${token}`);
  assert.equal(r.status, 302);
  return c;
}
/** Половинная сессия: только пароль. */
async function halfViaPassword() {
  const c = client();
  await c.get('/login');
  const r = await c.post('/login', { password: PASSWORD });
  assert.equal(r.status, 302);
  await c.get('/totp');
  return c;
}
const sidOf = (c) => c.jar.get('gw_sid');
const hashes = () => new Set(app.repo.listSessions().map((s) => s.id_hash));

before(async () => {
  app = await mkApp();
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const a = await fullViaSetupLink();
  await a.get('/setup');
  await a.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  totpSecret = (await (await a.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  step0 = Math.floor(Date.now() / 30000);
  usedSteps.add(step0);
  await a.post('/setup', { step: '2', code: totpAt(totpSecret, step0) });
  await a.post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); });

test('25: четвёртая полная сессия при markTotp вытесняет самую старую, половинная — нет (П-32)', async () => {
  app.db.exec('DELETE FROM sessions');
  const [c1, c2, c3] = [await fullViaSetupLink(), await fullViaSetupLink(), await fullViaSetupLink()];
  const h = [c1, c2, c3].map((c) => sha256(sidOf(c)));
  // c1 — самая давняя по активности
  const setSeen = app.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?');
  setSeen.run(1000, h[0]); setSeen.run(2000, h[1]); setSeen.run(3000, h[2]);
  assert.equal(app.repo.countFullSessions(), 3);

  // пароль без кода: половинная сессия есть, ни одна полная не пострадала
  const half = await halfViaPassword();
  assert.equal(app.repo.countFullSessions(), 3);
  for (const x of h) assert.ok(hashes().has(x), 'полные сессии целы после ввода пароля');
  assert.ok(hashes().has(sha256(sidOf(half))));

  // код принят: полная четвёртая, вытеснена самая старая
  const r = await half.post('/totp', { code: freshCode(), next: '/' });
  assert.equal(r.status, 302);
  assert.equal(app.repo.countFullSessions(), 3);
  assert.ok(!hashes().has(h[0]), 'самая старая вытеснена');
  assert.ok(hashes().has(h[1]) && hashes().has(h[2]));
  assert.ok(hashes().has(sha256(sidOf(half))), 'новая полная жива');
  assert.equal((await half.get('/')).status, 200);
  assert.equal((await c1.get('/')).status, 302, 'вытесненная сессия больше не входит');
});

test('26: в файле базы нет открытого значения cookie, есть его sha256', async () => {
  const c = await fullViaSetupLink();
  const raw = sidOf(c);
  assert.ok(raw && raw.length >= 40);
  assert.ok(hashes().has(sha256(raw)));
  // читаем базу вместе с WAL: свежие записи лежат там
  const bytes = Buffer.concat(fs.readdirSync(dataDir).filter((f) => f.startsWith('gw.db')).map((f) => fs.readFileSync(path.join(dataDir, f))));
  assert.equal(bytes.includes(Buffer.from(raw)), false, 'открытого id в базе нет');
  assert.equal(bytes.includes(Buffer.from(sha256(raw))), true, 'хэш в базе есть');
});

test('половинных сессий не больше 5, самые старые удаляются', async () => {
  app.db.exec('DELETE FROM sessions');
  for (let i = 0; i < 6; i++) await halfViaPassword();
  const half = app.repo.listSessions().filter((s) => !s.totp_ok);
  assert.equal(half.length, 5);
});

test('повтор кода отклоняется и после перезапуска (шаги в базе)', async () => {
  // шаг помечается использованным прямо перед перезапуском — он гарантированно в окне ±1 (не зависит от длины прогона)
  const reused = Math.floor(Date.now() / 30000);
  if (!usedSteps.has(reused)) { app.repo.takeTotpStep('owner', reused); usedSteps.add(reused); }
  await app.stop();
  app = await mkApp();
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const c = await halfViaPassword();
  const s = Math.floor(Date.now() / 30000);
  const bad = await c.post('/totp', { code: totpAt(totpSecret, reused), next: '/' });
  assert.match(bad.headers.get('location'), /e=code/, 'использованный шаг не принят после перезапуска');
  const freshStep = [s, s - 1, s + 1].find((x) => !usedSteps.has(x));
  usedSteps.add(freshStep);
  const ok = await c.post('/totp', { code: totpAt(totpSecret, freshStep), next: '/' });
  assert.equal(ok.headers.get('location'), '/');
});

test('takeTotpStep: шаг берётся один раз, пользователи независимы, purge чистит старые', () => {
  const repo = app.repo;
  assert.equal(repo.takeTotpStep('owner', 9_000_001), true);
  assert.equal(repo.takeTotpStep('owner', 9_000_001), false);
  assert.equal(repo.takeTotpStep('other', 9_000_001), true);
  // свежие шаги purge не трогает, старые (> 10 мин) удаляет
  assert.equal(repo.purgeTotpSteps() >= 0, true);
  assert.equal(repo.takeTotpStep('owner', 9_000_001), false, 'свежий шаг остался');
  app.db.prepare('UPDATE totp_used SET used_at = unixepoch() - 601 WHERE step = 9000001').run();
  assert.equal(repo.purgeTotpSteps(), 2);
  assert.equal(repo.takeTotpStep('owner', 9_000_001), true, 'после purge шаг снова свободен');
});

test('миграция: старая sessions с открытым id удаляется, владелец входит заново, шлюз работает', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-sess-mig-'));
  const p = path.join(dir, 'gw.db');
  const old = new Database(p);
  old.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE sessions (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
      expires_at INTEGER NOT NULL, ua TEXT, totp_ok INTEGER NOT NULL DEFAULT 0, totp_at INTEGER NOT NULL DEFAULT 0);
  `);
  old.prepare('INSERT INTO sessions (id, expires_at, totp_ok) VALUES (?, unixepoch() + 3600, 1)').run('old-open-session-id');
  old.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('pending:reissue:abcdef', 'enc');
  old.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run('keep_me', '1');
  old.close();

  const db = openDb(p);
  const cols = db.prepare('PRAGMA table_info(sessions)').all().map((c) => c.name);
  assert.ok(cols.includes('id_hash') && !cols.includes('id'));
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions').get().n, 0, 'старые сессии закрыты');
  assert.equal(createRepo(db).getMeta('pending:reissue:abcdef'), null);
  assert.equal(createRepo(db).getMeta('keep_me'), '1');
  // повторное открытие идемпотентно
  db.close();
  openDb(p).close();

  // приложение на мигрированной базе: старый cookie не даёт входа
  const a = await mkApp(dir);
  await a.start();
  try {
    const b = `http://127.0.0.1:${a.fastify.server.address().port}`;
    const r = await fetch(b + '/', { headers: { cookie: 'gw_sid=old-open-session-id' }, redirect: 'manual' });
    assert.equal(r.status, 302);
    assert.match(r.headers.get('location'), /\/login|\/setup/);
  } finally { await a.stop(); }
});
