// Контрактные тесты 30-33 (docs/contracts/drafts-team-auth.md): сменный модуль входа auth/provider.js.
// Без сети: vault file, сервер на localhost. Облачных провайдеров нет, поддельный внешний провайдер живёт только здесь.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { createAuthProvider, DEFAULT_PROVIDER } from '../src/auth/provider.js';
import { hashPassword } from '../src/auth/password.js';
import { makeLink } from '../src/auth/links.js';
import * as totp from '../src/auth/totp.js';
import { OWNER_USER_ID } from '../src/db/repo.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
const BACKUP = ['abcdefghjk', 'mnpqrstuvw'];
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dirs = [];
const apps = [];

const mkApp = async (extra = {}) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-authp-'));
  dirs.push(dir);
  const app = await buildApp({ dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', ...extra });
  apps.push(app);
  return app;
};
after(async () => { for (const a of apps) await a.stop().catch(() => {}); for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* Windows: файл ещё занят */ } } });

/** Владелец с паролем, TOTP и резервными кодами, мастер пройден. Возвращает секрет TOTP. */
async function seedOwner(app) {
  const secret = totp.generateSecret();
  app.repo.setPasswordHash(await hashPassword(PASSWORD));
  app.repo.setTotp(totp.encryptSecret(secret, app.ctx.keys.totp), 1);
  app.repo.replaceBackupCodes(BACKUP.map(totp.hashCode));
  app.repo.setSetupDone();
  return secret;
}
/** Свежий экземпляр провайдера на той же базе: свои счётчики блокировок. */
const mkProvider = (app) => createAuthProvider({ config: { authProvider: '', publicUrl: 'http://127.0.0.1' }, repo: app.repo, keys: app.ctx.keys });

function client(base) {
  const jar = new Map();
  const c = { jar, token: '' };
  const store = (res) => { for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); } };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' });
    store(r);
    const text = await r.clone().text();
    const m = text.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    r.body_ = text;
    return r;
  };
  c.post = async (p, fields = {}) => {
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ _csrf: c.token, ...fields }), redirect: 'manual' });
    store(r);
    return r;
  };
  return c;
}
async function listen(app) {
  await app.start();
  return `http://127.0.0.1:${app.fastify.server.address().port}`;
}
/** Полная сессия по ссылке мастера. */
async function fullSession(app, base) {
  const c = client(base);
  const { token } = makeLink(app.repo, 'setup', 900, base);
  assert.equal((await c.get(`/setup/${token}`)).status, 302);
  return c;
}

// ---- 30
test('30: local.verifyLogin: пароль, логин, неизвестный логин, блокировка', async () => {
  const app = await mkApp();
  assert.equal(mkProvider(app).getUser(OWNER_USER_ID), null, 'до мастера пользователя нет');
  await seedOwner(app);
  const p = mkProvider(app);

  assert.equal(p.name, DEFAULT_PROVIDER);
  assert.deepEqual(p.capabilities, { password: true, secondFactor: 'local', external: false, manageCredentials: true });

  // без поля логина (пользователь один) и с логином в любом регистре
  const ok = await p.verifyLogin({ password: PASSWORD });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.user, { id: OWNER_USER_ID, login: 'owner', name: 'Owner', role: 'owner', disabled: false, totpEnabled: true, tgChatId: null, externalId: null });
  assert.equal((await p.verifyLogin({ login: 'OWNER', password: PASSWORD })).ok, true);

  assert.deepEqual(await p.verifyLogin({ password: 'wrong' }), { ok: false, reason: 'bad' });
  assert.deepEqual(await p.verifyLogin({ login: 'nobody', password: PASSWORD }), { ok: false, reason: 'bad' }, 'неизвестный логин');

  // неизвестные логины считаются отдельно и владельца не блокируют
  const p2 = mkProvider(app);
  for (let i = 0; i < 6; i++) await p2.verifyLogin({ login: 'ghost', password: 'x' });
  assert.equal((await p2.verifyLogin({ password: PASSWORD })).ok, true);

  // 5 ошибок -> locked, даже верный пароль не пускает
  const p3 = mkProvider(app);
  for (let i = 0; i < 5; i++) assert.equal((await p3.verifyLogin({ password: 'wrong' })).reason, 'bad');
  assert.deepEqual(await p3.verifyLogin({ password: PASSWORD }), { ok: false, reason: 'locked' });
  // блокировка по пользователю не касается другого экземпляра (т.е. живёт в провайдере, а не в базе)
  assert.equal((await mkProvider(app).verifyLogin({ password: PASSWORD })).ok, true);

  assert.equal(p.getUser('someone-else'), null);
});

test('30: неизвестное имя провайдера и слот supabase — ошибка старта, по умолчанию local', async () => {
  const app = await mkApp();
  const deps = { repo: app.repo, keys: app.ctx.keys };
  assert.equal(createAuthProvider({ ...deps, config: { publicUrl: 'http://x' } }).name, 'local');
  assert.throws(() => createAuthProvider({ ...deps, config: { authProvider: 'ldap' } }), /Unknown auth provider "ldap"/);
  assert.throws(() => createAuthProvider({ ...deps, config: { authProvider: 'supabase' } }), /not implemented/);
  await assert.rejects(() => mkApp({ authProvider: 'nope' }), /Unknown auth provider "nope"/);
});

// ---- 31
test('31: local.verifySecondFactor: TOTP, резервный код, locked, чужой пользователь', async () => {
  const app = await mkApp();
  const secret = await seedOwner(app);
  const p = mkProvider(app);
  const step = Math.floor(Date.now() / 30000);
  const code = (d) => totp.totpAt(secret, step + d);

  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: code(0) }), { ok: true, kind: 'totp' });
  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: code(0) }), { ok: false, reason: 'bad' }, 'повтор шага');
  // код пользователя А не подходит пользователю Б (и неизвестному)
  assert.deepEqual(await p.verifySecondFactor({ userId: 'other', code: code(-1) }), { ok: false, reason: 'bad' });
  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: code(-1) }), { ok: true, kind: 'totp' }, 'отказ чужому не сжёг шаг');

  // резервный код одноразовый, регистр и пробелы не важны
  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: ` ${BACKUP[0].toUpperCase()} ` }), { ok: true, kind: 'backup' });
  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: BACKUP[0] }), { ok: false, reason: 'bad' });

  // 5 ошибок подряд -> locked, верный код тоже не принимается
  const q = mkProvider(app);
  for (let i = 0; i < 5; i++) assert.equal((await q.verifySecondFactor({ userId: OWNER_USER_ID, code: '000000' })).reason, 'bad');
  assert.deepEqual(await q.verifySecondFactor({ userId: OWNER_USER_ID, code: code(1) }), { ok: false, reason: 'locked' });
  assert.deepEqual(await q.verifySecondFactor({ userId: OWNER_USER_ID, code: BACKUP[1] }), { ok: false, reason: 'locked' });
});

test('31: управление данными входа: пароль, перевыпуск 2FA с резервными кодами', async () => {
  const app = await mkApp();
  await seedOwner(app);
  const p = mkProvider(app);
  await p.setPassword(OWNER_USER_ID, 'a-brand-new-password');
  assert.equal((await p.verifyLogin({ password: PASSWORD })).ok, false);
  assert.equal((await p.verifyLogin({ password: 'a-brand-new-password' })).ok, true);

  const { secret, otpauthUrl } = await p.beginSecondFactorEnrollment(OWNER_USER_ID);
  assert.match(otpauthUrl, /^otpauth:\/\/totp\//);
  assert.deepEqual(await p.confirmSecondFactorEnrollment(OWNER_USER_ID, secret, '000000'), { ok: false });
  const done = await p.confirmSecondFactorEnrollment(OWNER_USER_ID, secret, totp.totpAt(secret, Math.floor(Date.now() / 30000)));
  assert.equal(done.ok, true);
  assert.equal(done.backupCodes.length, 10);
  // старый секрет больше не действует, новый резервный код работает один раз
  assert.equal((await p.verifySecondFactor({ userId: OWNER_USER_ID, code: BACKUP[0] })).ok, false);
  assert.deepEqual(await p.verifySecondFactor({ userId: OWNER_USER_ID, code: done.backupCodes[0] }), { ok: true, kind: 'backup' });
});

// ---- 32
test('32: поддельный внешний провайдер: /login редиректит, настройки пароля и 2FA — 404, блоки скрыты', async () => {
  const fake = {
    name: 'fake', capabilities: { password: false, secondFactor: 'provider', external: true, manageCredentials: false },
    async verifyLogin() { throw new Error('must not be called'); },
    async verifySecondFactor() { return { ok: false, reason: 'bad' }; },
    getUser: (id) => (id === OWNER_USER_ID ? { id, login: 'owner', name: 'Owner', role: 'owner', disabled: false, totpEnabled: true, tgChatId: null, externalId: 'ext-1' } : null),
    getUserByTelegram: () => null,
    async startExternalLogin() { return { redirect: 'https://idp.example/authorize' }; },
  };
  const app = await mkApp({ auth: fake });
  await seedOwner(app);
  const base = await listen(app);

  const anon = client(base);
  const login = await anon.get('/login');
  assert.equal(login.status, 302);
  assert.equal(login.headers.get('location'), 'https://idp.example/authorize');

  const c = await fullSession(app, base);
  await c.get('/'); // страница с формой выхода даёт CSRF-токен
  assert.equal((await c.post('/login', { password: PASSWORD })).status, 404, 'форма пароля не принимается');
  const settings = await c.get('/settings');
  assert.equal(settings.status, 200);
  assert.ok(!settings.body_.includes('/settings/password') && !settings.body_.includes('/settings/2fa/'), 'блоки пароля и 2FA скрыты');
  for (const p of ['/settings/password', '/settings/2fa/reissue', '/settings/2fa/confirm', '/settings/2fa/backup-codes']) {
    assert.equal((await c.post(p, { password_old: 'x', code: '123456' })).status, 404, p);
  }
  assert.equal((await c.get('/invite/whatever')).status, 404);
});

test('32: локальный провайдер: блоки на месте, форма входа показана', async () => {
  const app = await mkApp();
  await seedOwner(app);
  const base = await listen(app);
  assert.equal((await client(base).get('/login')).status, 200);
  const c = await fullSession(app, base);
  const s = await c.get('/settings');
  assert.ok(s.body_.includes('/settings/password') && s.body_.includes('/settings/2fa/reissue'));
});

test('32: имена провайдеров как строки — только в src/auth', () => {
  const bad = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (p !== path.join(root, 'src', 'auth')) walk(p); continue; }
      if (!e.name.endsWith('.js')) continue;
      const src = fs.readFileSync(p, 'utf8');
      if (/['"`](supabase|local)['"`]/.test(src)) bad.push(path.relative(root, p));
    }
  };
  walk(path.join(root, 'src'));
  walk(path.join(root, 'bin'));
  assert.deepEqual(bad, []);
  // веб-слой и бот не читают строку владельца для входа напрямую
  assert.ok(!/getOwner\(\)\??\.(password_hash|totp_secret_enc|tg_chat_id)/.test(fs.readFileSync(path.join(root, 'src', 'web', 'server.js'), 'utf8')));
  const bot = fs.readFileSync(path.join(root, 'src', 'tg', 'bot.js'), 'utf8');
  assert.ok(bot.includes('auth.getUserByTelegram(') && !/getOwner\(\)\?\.tg_chat_id/.test(bot), 'бот определяет владельца через провайдер');
});

// ---- 33
test('33: src/auth сканируется тестом кириллицы', () => {
  const src = fs.readFileSync(path.join(root, 'test', 'no-cyrillic.test.js'), 'utf8');
  assert.ok(src.includes("walk(path.join(root, 'src'))"), 'src обходится целиком, включая src/auth');
  assert.ok(fs.existsSync(path.join(root, 'src', 'auth', 'provider.js')));
});

// ---- ревью 9.1: блокировка по паре «пользователь + адрес», глобальный потолок выше
test('9.1: перебор пароля с адреса A не запирает владельца на адресе B; 5 ошибок блокируют только свой адрес', async () => {
  const app = await mkApp();
  await seedOwner(app);
  const p = mkProvider(app);
  for (let i = 0; i < 5; i++) assert.equal((await p.verifyLogin({ password: 'wrong', ip: '203.0.113.1' })).reason, 'bad');
  assert.deepEqual(await p.verifyLogin({ password: PASSWORD, ip: '203.0.113.1' }), { ok: false, reason: 'locked' }, 'адрес A заперт');
  assert.equal((await p.verifyLogin({ password: PASSWORD, ip: '198.51.100.7' })).ok, true, 'владелец с адреса B входит');
});

test('M2: распределённый перебор пароля (55 ошибок с 11 адресов) владельца не запирает, уведомление один раз', async () => {
  const app = await mkApp();
  await seedOwner(app);
  const p = mkProvider(app);
  const alerts = [];
  for (let i = 0; i < 11; i++) {
    for (let j = 0; j < 5; j++) {
      const r = await p.verifyLogin({ password: 'bad' + j, ip: `203.0.113.${i}` });
      if (r.alert) alerts.push(r.alert);
    }
  }
  assert.deepEqual(alerts, ['distributed'], 'уведомление при пороге 50, один раз за окно');
  assert.equal((await p.verifyLogin({ password: PASSWORD, ip: '198.51.100.7' })).ok, true, 'верный пароль с нового адреса проходит');
  // сам перебравший адрес остаётся запертым
  assert.deepEqual(await p.verifyLogin({ password: PASSWORD, ip: '203.0.113.1' }), { ok: false, reason: 'locked' });
});

test('M2: сайт шлёт уведомление владельцу при распределённом переборе пароля', async () => {
  const sent = [];
  const app = await mkApp();
  await seedOwner(app);
  app.ctx.notify.info = async (text) => { sent.push(text); };
  const base = await listen(app);
  const p = app.ctx.auth;
  // 49 ошибок напрямую в провайдер, 50-я идёт через форму входа
  for (let i = 0; i < 49; i++) await p.verifyLogin({ password: 'wrong', ip: `10.1.${i}.1` });
  const c = client(base);
  await c.get('/login');
  await c.post('/login', { password: 'wrong' });
  assert.ok(sent.some((s) => /different addresses/.test(s)), 'уведомление отправлено');
});

test('9.1: ошибки второго фактора считаются по адресу; потолок в час общий и выше 10', async () => {
  const app = await mkApp();
  const secret = await seedOwner(app);
  const p = mkProvider(app);
  for (let i = 0; i < 5; i++) assert.equal((await p.verifySecondFactor({ userId: OWNER_USER_ID, code: '000000', ip: '203.0.113.1' })).reason, 'bad');
  assert.equal((await p.verifySecondFactor({ userId: OWNER_USER_ID, code: '000000', ip: '203.0.113.1' })).reason, 'locked');
  const ok = await p.verifySecondFactor({ userId: OWNER_USER_ID, code: totp.totpAt(secret, Math.floor(Date.now() / 30000)), ip: '198.51.100.7' });
  assert.deepEqual(ok, { ok: true, kind: 'totp' }, 'другой адрес не заперт, верный код принят');
  // 12 ошибок с разных адресов (больше прежнего потолка 10) владельца не запирают
  const q = mkProvider(app);
  for (let i = 0; i < 12; i++) await q.verifySecondFactor({ userId: OWNER_USER_ID, code: '000000', ip: `10.4.${i}.1` });
  assert.notEqual((await q.verifySecondFactor({ userId: OWNER_USER_ID, code: '000000', ip: '10.5.0.1' })).reason, 'locked');
});
