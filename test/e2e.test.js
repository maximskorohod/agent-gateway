// Сквозной сценарий: мастер → ключ → агент → заявка → одобрение → прокси → квота → удаление
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const SECRET = '123456:' + 'A'.repeat(35);
let app, base, mock, mockPort, seen = [];
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0|expires=thu, 01 jan 1970/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
// CSRF-токен берётся из последней показанной формы (в cookie он не хранится, П-22)
let csrfTok = '';
async function grabCsrf(r) { if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; } }
async function get(p) { const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r); await grabCsrf(r); return r; }
async function post(p, fields) {
  const body = new URLSearchParams({ _csrf: csrfTok, ...fields });
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r); await grabCsrf(r);
  // сессия сменилась (вход, выход): токен меняется вместе с ней, берём из следующей страницы
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}
const api = (p, opts = {}) => fetch(base + p, opts);

before(async () => {
  mock = http.createServer((req, res) => {
    let data = ''; req.on('data', (c) => (data += c));
    req.on('end', () => { seen.push({ url: req.url, headers: req.headers, body: data }); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true, echo_url: req.url, token_leak: SECRET })); });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r)); mockPort = mock.address().port;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-e2e-')); dataDirGlobal = dataDir;
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'ru', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', testUpstream: { 'api.telegram.org': `http://127.0.0.1:${mockPort}` } });
  await app.start();
  const port = app.fastify.server.address().port; base = `http://127.0.0.1:${port}`;
});
after(async () => { await app.stop(); mock.close(); });

let agentToken, requestId, grantToken, credId, dataDirGlobal;

test('мастер первого запуска', async () => {
  const { token } = makeLink(app.repo, 'setup', 900, base);
  let r = await get(`/setup/${token}`); assert.equal(r.status, 302);
  r = await get(`/setup/${token}`); assert.equal(r.status, 404, 'ссылка одноразовая');
  r = await get('/setup'); assert.equal(r.status, 200); assert.match(await r.text(), /Пароль/);
  r = await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' }); assert.equal(r.status, 302);
  r = await get('/setup'); const html = await r.text(); assert.match(html, /<svg/);
  const secret = html.match(/Ключ вручную: <code>([A-Z2-7]+)<\/code>/)[1];
  r = await post('/setup', { step: '2', code: '000000' }); assert.equal(r.status, 302, 'неверный код → назад');
  r = await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) }); assert.equal(r.status, 200); assert.match(await r.text(), /резервные коды/i);
  r = await post('/setup', { step: '3', mode: 'skip' }); assert.equal(r.status, 302);
  r = await get('/'); assert.equal(r.status, 200); assert.match(await r.text(), /Добавить ключ/);
  app.ctx._totpSecret = secret;
});

test('добавление ключа Telegram (секрет в пути)', async () => {
  let r = await get('/keys/new/telegram'); assert.equal(r.status, 200);
  r = await post('/keys/new/telegram', { key: 'wrong', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  assert.equal(r.status, 400); assert.match(await r.text(), /не тот ключ/);
  r = await post('/keys/new/telegram', { key: SECRET, label: 'бот', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  assert.equal(r.status, 302);
  const list = app.repo.listCredentials(); assert.equal(list.length, 1); credId = list[0].id;
  assert.equal(list[0].kind, 'path'); assert.equal(list[0].last4, SECRET.slice(-4));
  const html = await (await get('/')).text(); assert.doesNotMatch(html, new RegExp(SECRET));
});

test('агент, заявка, одобрение на сайте, получение пропуска', async () => {
  const r = await post('/agents', { name: 'парсер' }); assert.equal(r.status, 200);
  agentToken = (await r.text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  let a = await api('/v1/grants', { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'telegram', ttl: 600, calls: 2, reason: '<b>лиды</b> https://evil' }) });
  assert.equal(a.status, 202); requestId = (await a.json()).request_id;
  const page = await (await get('/')).text(); assert.match(page, /Ожидают/); assert.match(page, /&lt;b&gt;лиды/);
  const d = await post(`/requests/${requestId}/approve`, {}); assert.equal(d.status, 302);
  a = await api(`/v1/grants/${requestId}`, { headers: { authorization: `Bearer ${agentToken}` } }); assert.equal(a.status, 200);
  const j = await a.json(); assert.equal(j.status, 'approved'); assert.match(j.token, /^gwt_/); grantToken = j.token; assert.equal(j.max_calls, 2);
  a = await api(`/v1/grants/${requestId}`, { headers: { authorization: `Bearer ${agentToken}` } }); assert.equal(a.status, 410, 'токен выдаётся один раз');
  const bad = await api('/v1/grants', { method: 'POST', headers: { authorization: 'Bearer gwa_nope', 'content-type': 'application/json' }, body: '{}' }); assert.equal(bad.status, 401);
});

test('прокси: подстановка в путь, маскирование ответа, квота', async () => {
  const call = () => api('/v1/proxy/telegram/getMe?x=1', { method: 'POST', headers: { authorization: `Bearer ${grantToken}`, 'content-type': 'application/json', 'x-custom': 'yes' }, body: '{"a":1}' });
  let r = await call(); assert.equal(r.status, 200);
  const body = await r.text(); assert.doesNotMatch(body, new RegExp(SECRET.replace(/[:]/g, '\\$&'))); assert.match(body, /\*\*\*\*/);
  assert.equal(seen[0].url, `/bot${SECRET}/getMe?x=1`); assert.equal(seen[0].body, '{"a":1}'); assert.equal(seen[0].headers['x-custom'], 'yes'); assert.equal(seen[0].headers.authorization, undefined, 'пропуск агента не уходит в сервис');
  r = await call(); assert.equal(r.status, 200);
  r = await call(); assert.equal(r.status, 429); assert.deepEqual(await r.json(), { error: 'quota_exceeded' });
  const g = app.repo.getGrant(app.repo.listActiveGrants()[0].id); assert.equal(g.inflight, 0, 'lease освобождён'); assert.equal(g.calls_used, 2);
  const audit = app.repo.listAudit({ limit: 10 }).map((x) => x.target + ' ' + x.meta_json).join('\n'); assert.doesNotMatch(audit, new RegExp(SECRET));
  const bad = await api('/v1/proxy/telegram/../x', { headers: { authorization: `Bearer ${grantToken}` } }); assert.ok([400, 404].includes(bad.status));
});

test('привязка ключей: чужой ключ не виден, отвязка отзывает пропуск, страница «Запросы»', async () => {
  const grantReq = (token, body) => api('/v1/grants', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  // Новый агент только с отмеченными ключами, ни одного не отмечено
  let r = await post('/agents', { name: 'узкий', keys_all: '0' }); assert.equal(r.status, 200);
  const narrowToken = (await r.text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  const narrow = app.repo.listAgents().find((a) => a.name === 'узкий');
  assert.equal(narrow.all_credentials, 0);
  r = await grantReq(narrowToken, { provider: 'telegram', ttl: 60, calls: 1 }); assert.equal(r.status, 403); assert.deepEqual(await r.json(), { error: 'no_credential' });
  r = await grantReq(narrowToken, { provider: 'telegram', credential_id: credId, ttl: 60, calls: 1 }); assert.equal(r.status, 403, 'явный id чужого ключа тоже не работает');
  // Привязали ключ — заявка проходит
  r = await post(`/agents/${narrow.id}/keys`, { keys_all: '0', keys: credId }); assert.equal(r.status, 302);
  assert.deepEqual(app.repo.listAgentCredentials(narrow.id), [credId]);
  r = await grantReq(narrowToken, { provider: 'telegram', ttl: 60, calls: 1 }); assert.equal(r.status, 202);
  const pendingId = (await r.json()).request_id;
  // Отвязали, пока заявка ждала: одобрить уже нельзя
  r = await post(`/agents/${narrow.id}/keys`, { keys_all: '0' }); assert.equal(r.status, 302);
  await post(`/requests/${pendingId}/approve`, {});
  assert.equal(app.repo.getRequest(pendingId).status, 'denied');
  // Снова привязали, получили пропуск, отвязали: пропуск отозван, прокси отвечает 401
  await post(`/agents/${narrow.id}/keys`, { keys_all: '0', keys: credId });
  r = await grantReq(narrowToken, { provider: 'telegram', ttl: 60, calls: 1 }); const okId = (await r.json()).request_id;
  await post(`/requests/${okId}/approve`, {});
  r = await api(`/v1/grants/${okId}`, { headers: { authorization: `Bearer ${narrowToken}` } }); const narrowGrant = (await r.json()).token;
  assert.match(narrowGrant, /^gwt_/);
  const grantId = app.repo.listActiveGrants().find((g) => g.agent_id === narrow.id).id;
  await post(`/agents/${narrow.id}/keys`, { keys_all: '0' });
  assert.ok(app.repo.getGrant(grantId).revoked_at, 'пропуск отозван');
  r = await api('/v1/proxy/telegram/getMe', { headers: { authorization: `Bearer ${narrowGrant}` } }); assert.equal(r.status, 401);
  const first = app.repo.listAgents().find((a) => a.name === 'парсер');
  assert.equal(first.all_credentials, 1, 'старые агенты по умолчанию со всеми ключами');
  // Статистика: два вызова первого агента видны в разрезе агента и ключа
  r = await get('/stats?d=1'); assert.equal(r.status, 200);
  const stats = await r.text();
  assert.match(stats, /По агентам/); assert.match(stats, /парсер/); assert.match(stats, /POST telegram\/getMe/);
  assert.doesNotMatch(stats, new RegExp(SECRET.replace(/[:]/g, '\\$&')));
  const calls = app.repo.callStats(1).filter((x) => x.agent_id === first.id);
  assert.equal(calls.reduce((s, x) => s + x.calls, 0) >= 2, true);
  r = await get(`/stats?d=7&agent=${first.id}`); assert.match(await r.text(), /Активность: парсер/);
  r = await get('/stats?d=999&agent=nope'); assert.equal(r.status, 200, 'неизвестные параметры не ломают страницу');
});

test('отказ: не тот провайдер, выключенный агент, удалённый ключ', async () => {
  let r = await api('/v1/proxy/groq/x', { headers: { authorization: `Bearer ${grantToken}` } }); assert.equal(r.status, 401);
  const agent = app.repo.listAgents().find((a) => a.name === 'парсер');
  await post(`/agents/${agent.id}/disable`, {});
  r = await api('/v1/proxy/telegram/getMe', { headers: { authorization: `Bearer ${grantToken}` } }); assert.equal(r.status, 401);
  await post(`/agents/${agent.id}/enable`, {});
  // удаление ключа требует недавнего кода — код был введён в мастере < 5 мин назад
  r = await post(`/keys/${credId}/delete`, {}); assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/');
  assert.equal(app.repo.listCredentials().length, 0);
  assert.equal(await app.ctx.vault.get(`cred/${credId}`), null);
});

test('ответ сервиса: gzip и Location не выдают секрет; заголовок агента не дублирует инъекцию', async () => {
  // новый ключ в режиме always, чтобы получить пропуск без одобрения (код вводился < 5 мин назад)
  await post('/login', { password: 'correct-horse-battery' });
  await post('/totp', { code: totpAt(app.ctx._totpSecret, Math.floor(Date.now() / 30000) + 1), next: '/' });
  const r0 = await post('/keys/new/telegram', { key: SECRET, label: 'бот2', mode: 'always', approval: 'web_button', max_ttl: '3600', max_calls: '10', max_parallel: '2' }); assert.equal(r0.status, 302);
  const a = await api('/v1/grants', { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'telegram', ttl: 600, calls: 5 }) });
  assert.equal(a.status, 200); const tok = (await a.json()).token;
  seen = [];
  const r = await api('/v1/proxy/telegram/getMe', { headers: { authorization: `Bearer ${tok}`, 'accept-encoding': 'gzip', 'Authorization-X': 'x' } });
  assert.equal(seen[0].headers['accept-encoding'], 'identity', 'сервис просим отвечать без сжатия');
  assert.doesNotMatch(await r.text(), new RegExp(SECRET));
  mock.removeAllListeners('request');
  mock.on('request', (q, s) => { s.statusCode = 302; s.setHeader('location', `https://api.telegram.org/bot${SECRET}/x`); s.end(JSON.stringify({ u: `bot${SECRET}` })); });
  const r2 = await api('/v1/proxy/telegram/getMe', { headers: { authorization: `Bearer ${tok}` }, redirect: 'manual' });
  assert.equal(r2.status, 302); assert.doesNotMatch(r2.headers.get('location'), new RegExp(SECRET)); assert.match(r2.headers.get('location'), /\*\*\*\*/);
  assert.doesNotMatch(await r2.text(), new RegExp(SECRET));
});

test('половинная сессия (только пароль) не становится полной после перезапуска', async () => {
  await post('/logout', {});
  let r = await post('/login', { password: 'correct-horse-battery' }); assert.equal(r.status, 302);
  r = await get('/agents'); assert.equal(r.status, 302, 'до кода — редирект');
  // «перезапуск»: новый процесс приложения на той же базе
  const port = app.fastify.server.address().port;
  await app.stop();
  app = await buildApp({ dataDir: dataDirGlobal, dbPath: path.join(dataDirGlobal, 'gw.db'), vaultFile: path.join(dataDirGlobal, 'vault.json'), masterKeyFile: path.join(dataDirGlobal, 'master.key'), lang: 'ru', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  await app.start(); base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  r = await get('/agents'); assert.equal(r.status, 302); assert.match(r.headers.get('location'), /^\/totp/);
  r = await post('/agents', { name: 'evil' }); assert.equal(r.status, 302);
});

test('другой: приватный адрес отклоняется', async () => {
  // отдельное приложение не нужно — проверяем валидатор напрямую через форму в новой сессии невозможно (блокировка), поэтому модуль
  const { buildInjection, loadCatalog } = await import('../src/catalog.js');
  const cat = loadCatalog(app.ctx.config.catalogPath);
  assert.throws(() => buildInjection(cat.get('other'), { host: 'http://169.254.169.254/', header: 'x-api-key', key: 'abcd1234' }));
  assert.throws(() => buildInjection(cat.get('other'), { host: 'https://10.0.0.1/', header: 'x-api-key', key: 'abcd1234' }));
});

test('вход: пароль + код, блокировка после 5 ошибок, одноразовая ссылка', async () => {
  await post('/logout', {});
  let r = await get('/'); assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/login');
  for (let i = 0; i < 5; i++) await post('/login', { password: 'wrong-password-123' });
  r = await post('/login', { password: 'correct-horse-battery' }); assert.equal(r.status, 302);
  r = await get('/login'); assert.match(await r.text(), /подождите|Слишком много/i);
});
