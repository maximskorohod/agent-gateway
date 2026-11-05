// П-22: CSRF-токен привязан к сессии (HMAC), cookie с префиксом __Host- на https, проверка Origin/Referer.
// Без сети: vault file, https проверяется через fastify.inject.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
const PUBLIC = 'http://127.0.0.1';
let app, base, totpSecret;

const mkApp = (publicUrl) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-csrf-'));
  return buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl, logLevel: 'silent' });
};

/** Клиент со своей банкой cookie; токен берёт из последней показанной формы. */
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
  c.post = async (p, fields = {}, { headers = {}, token = c.token } = {}) => {
    const body = new URLSearchParams({ _csrf: token, ...fields });
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded', ...headers }, body, redirect: 'manual' });
    store(r);
    return r;
  };
  return c;
}

// Шаги TOTP одноразовые (П-32): берём ещё не использованный из окна ±1, иначе тест падает на границе 30 с
const usedSteps = new Set();
function freshCode() {
  const s = Math.floor(Date.now() / 30000);
  const step = [s, s - 1, s + 1].find((x) => !usedSteps.has(x));
  usedSteps.add(step);
  return totpAt(totpSecret, step);
}

/** Вход: пароль, затем свежий код. */
async function login(c) {
  await c.get('/login');
  let r = await c.post('/login', { password: PASSWORD }); assert.equal(r.status, 302);
  await c.get('/totp');
  r = await c.post('/totp', { code: freshCode(), next: '/' });
  assert.equal(r.status, 302);
  assert.equal((await c.get('/')).status, 200, 'вошли');
}

before(async () => {
  app = await mkApp(PUBLIC);
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const { token } = makeLink(app.repo, 'setup', 900, base);
  const a = client();
  await a.get(`/setup/${token}`); await a.get('/setup');
  await a.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  totpSecret = (await (await a.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  await a.post('/setup', { step: '2', code: freshCode() });
  await a.post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); });

test('подсадка cookie с соседнего поддомена не даёт токен', async () => {
  const planted = 'A'.repeat(32);
  // старая схема: gw_csrf=значение в cookie и то же значение в теле
  const c = client(); c.jar.set('gw_csrf', planted);
  assert.equal((await c.post('/login', { password: 'x' }, { token: planted })).status, 403);
  // подсаженная pre-session cookie с произвольным значением: токен злоумышленник посчитать не может
  const d = client(); d.jar.set('gw_pre', planted);
  assert.equal((await d.post('/login', { password: 'x' }, { token: planted })).status, 403);
  assert.equal((await d.post('/login', { password: 'x' }, { token: '' })).status, 403);
  // токен, полученный на чужой pre-cookie, к подсаженной не подходит
  const e = client(); await e.get('/login');
  const f = client(); f.jar.set('gw_pre', planted);
  assert.equal((await f.post('/login', { password: 'x' }, { token: e.token })).status, 403);
  // законный путь работает (неверный пароль → 302 назад на форму, не 403)
  assert.equal((await e.post('/login', { password: 'wrong-password-123' })).status, 302);
});

test('токен сессии A не подходит сессии B', async () => {
  const a = client(); await login(a);
  const b = client(); await login(b);
  assert.notEqual(a.token, b.token);
  assert.equal((await b.post('/logout', {}, { token: a.token })).status, 403);
  assert.equal((await b.post('/logout')).status, 302);
});

test('после входа токен меняется: pre-токен со старой формы не годится новой сессии', async () => {
  const c = client();
  await c.get('/login'); const pre = c.token;
  let r = await c.post('/login', { password: PASSWORD }); assert.equal(r.status, 302);
  assert.ok(c.jar.has('gw_sid'));
  assert.equal((await c.post('/totp', { code: '000000', next: '/' }, { token: pre })).status, 403, 'pre-токен отвергнут');
  await c.get('/totp'); assert.notEqual(c.token, pre);
  r = await c.post('/totp', { code: '000000', next: '/' }); assert.notEqual(r.status, 403, 'новый токен принят');
});

test('Origin: чужой, null и неверный Referer отклоняются; свой и отсутствие — проходят', async () => {
  const c = client(); await c.get('/login');
  const send = (headers) => c.post('/login', { password: 'wrong-password-123' }, { headers });
  assert.equal((await send({ origin: 'https://evil.example' })).status, 403);
  assert.equal((await send({ origin: 'null' })).status, 403);
  assert.equal((await send({ origin: 'http://127.0.0.1.evil.example' })).status, 403);
  assert.equal((await send({ origin: 'https://127.0.0.1' })).status, 403, 'схема важна');
  assert.equal((await send({ referer: 'https://evil.example/login' })).status, 403);
  assert.equal((await send({ origin: 'http://127.0.0.1', referer: 'https://evil.example/' })).status, 302, 'Origin главнее Referer');
  assert.equal((await send({ origin: 'https://evil.example', referer: 'http://127.0.0.1/login' })).status, 403);
  assert.equal((await send({ origin: 'http://127.0.0.1' })).status, 302);
  assert.equal((await send({ origin: 'http://127.0.0.1:80' })).status, 302, 'порт по умолчанию нормализуется');
  assert.equal((await send({ referer: 'http://127.0.0.1/login' })).status, 302);
  assert.equal((await send({})).status, 302, 'без Origin и Referer (Node fetch) — по токену');
  // отказ по Origin идёт раньше токена, но с верным токеном чужой Origin всё равно не проходит
  assert.equal((await send({ origin: 'https://evil.example' })).status, 403);
});

test('агентский API /v1/* не затронут CSRF и Origin', async () => {
  for (const headers of [{}, { origin: 'https://evil.example' }]) {
    const r = await fetch(base + '/v1/grants', { method: 'POST', headers: { ...headers, 'content-type': 'application/json', authorization: 'Bearer gwa_bad' }, body: '{}' });
    assert.equal(r.status, 401);
  }
});

test('http: имена cookie без префикса', async () => {
  const r = await app.fastify.inject({ method: 'GET', url: '/login' });
  const sc = [].concat(r.headers['set-cookie']);
  assert.ok(sc.some((s) => s.startsWith('gw_pre=')), 'pre-cookie');
  assert.ok(!sc.some((s) => s.includes('__Host-')));
});

test('https: cookie с префиксом __Host-, Secure, Path=/, без Domain', async () => {
  const secureApp = await mkApp('https://gw.example.test');
  try {
    await secureApp.fastify.ready();
    const check = (res, name) => {
      const sc = [].concat(res.headers['set-cookie']).find((s) => s.startsWith(name + '='));
      assert.ok(sc, `${name} выставлена`);
      assert.match(sc, /;\s*Path=\/(;|$)/); assert.match(sc, /;\s*Secure/); assert.match(sc, /;\s*HttpOnly/); assert.match(sc, /;\s*SameSite=Strict/i);
      assert.doesNotMatch(sc, /Domain=/i);
    };
    const pre = await secureApp.fastify.inject({ method: 'GET', url: '/login' });
    check(pre, '__Host-gw_pre');
    assert.ok(![].concat(pre.headers['set-cookie']).some((s) => /^(gw_pre|gw_sid|gw_csrf)=/.test(s)));
    // сессия: ссылка мастера выдаёт __Host-gw_sid
    const { token } = makeLink(secureApp.repo, 'setup', 900, 'https://gw.example.test');
    const s = await secureApp.fastify.inject({ method: 'GET', url: `/setup/${token}` });
    check(s, '__Host-gw_sid');
    // и обратно: форма с токеном из этой сессии проходит при своём Origin и не проходит при чужом
    const sid = [].concat(s.headers['set-cookie']).find((x) => x.startsWith('__Host-gw_sid=')).split(';')[0];
    const page = await secureApp.fastify.inject({ method: 'GET', url: '/setup', headers: { cookie: sid } });
    const tok = page.body.match(/name="_csrf" value="([^"]+)"/)[1];
    const post = (origin) => secureApp.fastify.inject({ method: 'POST', url: '/setup', headers: { cookie: sid, 'content-type': 'application/x-www-form-urlencoded', origin }, payload: new URLSearchParams({ _csrf: tok, step: '1', password: 'short', password_repeat: 'short' }).toString() });
    assert.equal((await post('https://evil.example')).statusCode, 403);
    assert.notEqual((await post('https://gw.example.test')).statusCode, 403);
  } finally { await secureApp.stop(); }
});
