// П-30: сбои сейфа и базы дают 503 централизованно; П-36: заголовки запроса и ответа фильтруются по префиксу и Connection
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
import { isInfraError, markInfra } from '../src/core/infra.js';
import { filterRequestHeaders, filterResponseHeaders, connectionTokens } from '../src/core/proxy.js';

initI18n('en');

const HOST = 'test.bitrix24.ru';
const HOOK = 'abcdef123456';
let app, base, mock, grant, hits = 0, lastHeaders = {};
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
let csrfTok = '';
async function grabCsrf(r) { if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; } }
async function get(p) { const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r); await grabCsrf(r); return r; }
async function post(p, fields) {
  const body = new URLSearchParams({ _csrf: csrfTok });
  for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r);
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}
const call = (p, opts = {}) => fetch(`${base}/v1/proxy/bitrix24/${p}`, { ...opts, headers: { authorization: `Bearer ${grant}`, ...(opts.headers || {}) } });

// ошибка, какой её даёт better-sqlite3
const sqliteErr = (code = 'SQLITE_BUSY') => Object.assign(new Error('database is locked'), { name: 'SqliteError', code });

before(async () => {
  mock = http.createServer((req, res) => {
    hits++; lastHeaders = req.headers;
    res.setHeader('content-type', 'application/json');
    // ответ с заголовком, названным в Connection сервиса
    res.setHeader('x-resp-hop', 'secret-hop'); res.setHeader('x-resp-keep', 'ok');
    res.setHeader('connection', 'close, x-resp-hop');
    res.end(JSON.stringify({ headers: req.headers }));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-infra-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` } });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  const secret = (await (await get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>/)[1];
  await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
  const r = await post('/keys/new/bitrix24', { webhook_url: `https://${HOST}/rest/1/${HOOK}/`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '1', protect_form: '1' }); // protect_form без галочек: readOnly выключен
  assert.equal(r.status, 302);
  const agentToken = (await (await post('/agents', { name: 'tester' })).text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  const a = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 600, calls: 50, reason: 'test' }) });
  const { request_id } = await a.json();
  await post(`/requests/${request_id}/approve`, {});
  grant = (await (await fetch(`${base}/v1/grants/${request_id}`, { headers: { authorization: `Bearer ${agentToken}` } })).json()).token;
  assert.ok(grant, 'пропуск выдан');
});
after(async () => { await app.stop(); mock.close(); });

test('isInfraError: sqlite, помеченные, AWS; обычные и upstream-ошибки нет', () => {
  assert.equal(isInfraError(sqliteErr()), true);
  assert.equal(isInfraError(Object.assign(new Error('x'), { code: 'SQLITE_IOERR' })), true);
  assert.equal(isInfraError(markInfra(new Error('vault down'), 'vault')), true);
  assert.equal(isInfraError(Object.assign(new Error('x'), { name: 'CredentialsProviderError', $metadata: {} })), true);
  assert.equal(isInfraError(Object.assign(new Error('x'), { name: 'ParameterNotFound', $metadata: { httpStatusCode: 400 } })), false);
  assert.equal(isInfraError(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })), false);
  assert.equal(isInfraError(new Error('boom')), false);
  assert.equal(isInfraError(null), false);
});

test('П-30: сейф упал на get: 503 service_unavailable + Retry-After, сервис не вызван, слот свободен', async () => {
  const vault = app.ctx.vault; const orig = vault.get;
  const g = app.repo.listActiveGrants()[0].id;
  const before = hits;
  vault.get = async () => { throw new Error('vault is down'); };
  try {
    const r = await call('crm.deal.list.json');
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: 'service_unavailable' });
    assert.ok(Number(r.headers.get('retry-after')) > 0);
    assert.equal(hits, before, 'до сервиса не дошло');
    await new Promise((ok) => setTimeout(ok, 30));
    assert.equal(app.repo.getGrant(g).inflight, 0, 'lease освобождён');
  } finally { vault.get = orig; }
  // сейф восстановился: при max_parallel=1 вызов проходит
  const ok = await call('crm.deal.list.json');
  assert.equal(ok.status, 200);
  await ok.text();
});

test('П-30: сейф упал со статусом SDK (не ParameterNotFound): тоже 503', async () => {
  const vault = app.ctx.vault; const orig = vault.get;
  vault.get = async () => { throw Object.assign(new Error('no creds'), { name: 'CredentialsProviderError', $metadata: {} }); };
  try { assert.equal((await call('x.json')).status, 503); } finally { vault.get = orig; }
});

test('П-30: ошибка базы на /v1: 503, а не 500', async () => {
  const orig = app.repo.getCredential;
  app.repo.getCredential = () => { throw sqliteErr('SQLITE_BUSY'); };
  try {
    const r = await call('crm.deal.list.json');
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: 'service_unavailable' });
    assert.ok(r.headers.get('retry-after'));
  } finally { app.repo.getCredential = orig; }
});

test('П-30: ошибка базы на странице сайта: 503 с текстом из словаря', async () => {
  const orig = app.repo.listAudit;
  app.repo.listAudit = () => { throw sqliteErr('SQLITE_IOERR'); };
  try {
    const r = await get('/audit');
    assert.equal(r.status, 503);
    assert.ok(r.headers.get('retry-after'));
    assert.match(await r.text(), /temporarily unavailable/);
  } finally { app.repo.listAudit = orig; }
  assert.equal((await get('/audit')).status, 200, 'после восстановления страница открывается');
});

test('П-30: сейф упал при «Заменить ключ»: страница 503, текст ошибки сейфа владельцу не показывается', async () => {
  const cred = app.repo.listCredentials().find((c) => c.host === HOST);
  const vault = app.ctx.vault; const orig = vault.put;
  vault.put = async () => { throw markInfra(new Error('ssm internal detail'), 'vault'); };
  try {
    await get(`/keys/${cred.id}`);
    const r = await post(`/keys/${cred.id}/replace`, { webhook_url: `https://${HOST}/rest/1/zyxwvu987654/` });
    assert.equal(r.status, 503);
    assert.doesNotMatch(await r.text(), /ssm internal detail/);
  } finally { vault.put = orig; }
  assert.equal(app.repo.getCredential(cred.id).last4, cred.last4, 'ключ не изменён');
});

test('П-30: ошибка не из инфраструктуры остаётся 500 internal', async () => {
  const orig = app.repo.getCredential;
  app.repo.getCredential = () => { throw new Error('bug'); };
  try {
    const r = await call('crm.deal.list.json');
    assert.equal(r.status, 500);
    assert.deepEqual(await r.json(), { error: 'internal' });
  } finally { app.repo.getCredential = orig; }
});

test('П-36: чистая функция filterRequestHeaders', () => {
  const out = filterRequestHeaders({
    accept: 'application/json', 'content-type': 'application/json', 'x-custom': '1',
    'X-Forwarded-Whatever': 'a', 'cf-foo': 'b', 'x-real-ip': 'c', 'x-envoy-x': 'd', 'x-amzn-trace-id': 'e', forwarded: 'f', via: 'g',
    connection: 'keep-alive, X-Secret-Hop', 'x-secret-hop': '1', authorization: 'Bearer gwt_x', 'x-extra': 'drop-me',
  }, ['x-extra']);
  assert.deepEqual(out, { accept: 'application/json', 'content-type': 'application/json', 'x-custom': '1' });
  assert.deepEqual([...connectionTokens([' Close ,X-A', 'x-b'])].sort(), ['close', 'x-a', 'x-b']);
  assert.deepEqual(filterResponseHeaders({ connection: 'close, X-Hop', 'x-hop': '1', 'x-ok': '2', 'set-cookie': 'a=b' }), { 'x-ok': '2' });
});

test('П-36: до сервиса не доходят x-forwarded-*, cf-*, названные в Connection; обычные доходят', async () => {
  const r = await fetch(`${base}/v1/proxy/bitrix24/crm.deal.list.json`, {
    headers: {
      authorization: `Bearer ${grant}`, accept: 'application/json', 'x-custom': 'yes',
      'X-Forwarded-Whatever': 'a', 'Cf-Foo': 'b', 'x-real-ip': '1.2.3.4', 'x-envoy-foo': 'e', 'x-amzn-trace-id': 't',
      // undici fetch запрещает ставить Connection, поэтому проверяем сырым http ниже
    },
  });
  assert.equal(r.status, 200); await r.text();
  assert.equal(lastHeaders['x-custom'], 'yes'); assert.equal(lastHeaders.accept, 'application/json');
  for (const h of ['x-forwarded-whatever', 'cf-foo', 'x-real-ip', 'x-envoy-foo', 'x-amzn-trace-id', 'authorization']) assert.equal(lastHeaders[h], undefined, h);

  const u = new URL(base);
  const res = await new Promise((ok, fail) => {
    http.get({ host: u.hostname, port: u.port, path: '/v1/proxy/bitrix24/crm.deal.list.json', headers: { authorization: `Bearer ${grant}`, connection: 'keep-alive, X-Secret-Hop', 'x-secret-hop': '1', 'content-type': 'application/json', 'x-custom': 'ok' } }, (x) => { x.resume(); x.on('end', () => ok(x)); }).on('error', fail);
  });
  assert.equal(res.statusCode, 200);
  assert.equal(lastHeaders['x-secret-hop'], undefined, 'заголовок из Connection не доходит');
  assert.equal(lastHeaders['content-type'], 'application/json'); assert.equal(lastHeaders['x-custom'], 'ok');
});

test('П-36: заголовок, названный в Connection сервиса, не доходит до агента', async () => {
  const r = await call('crm.deal.list.json');
  assert.equal(r.status, 200); await r.text();
  assert.equal(r.headers.get('x-resp-hop'), null);
  assert.equal(r.headers.get('x-resp-keep'), 'ok');
});
