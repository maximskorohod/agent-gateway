// П-33 (маскирование URL в логах, Н-12, Н-4) и П-34 (лимит прокси на агента, агрегация отказов)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { maskUrl } from '../src/logger.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const HOST = 'test.bitrix24.ru';
const HOOK = 'abcdef123456';
const PASSWORD = 'correct-horse-battery';
const NEW_PASSWORD = 'another-long-passphrase';
const LIMIT = 12;
const DEALS = { result: [{ ID: '1', TITLE: 'deal' }], total: 1 };
const DEAL_FORM = { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID', 'result.TITLE'] };

let app, base, mock, seen = [];
let clock = 1_000_000;
const logLines = [];
const logText = () => logLines.join('');

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
    const body = new URLSearchParams({ _csrf: c.token });
    for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
    store(r);
    if (r.status === 302 && r.headers.getSetCookie().length) await c.get(r.headers.get('location'));
    return r;
  };
  return c;
}

/** Полная сессия по ссылке мастера. */
async function fullSession() {
  const c = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  const r = await c.get(`/setup/${token}`);
  assert.equal(r.status, 302);
  await c.get('/');
  return c;
}

let owner, credId;
async function newAgentGrant(name) {
  const r = await owner.post('/agents', { name });
  const agentToken = (await r.text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  const a = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 3000, calls: 90, reason: 'test' }) });
  const { request_id } = await a.json();
  await owner.post(`/requests/${request_id}/approve`, {});
  const g = await (await fetch(`${base}/v1/grants/${request_id}`, { headers: { authorization: `Bearer ${agentToken}` } })).json();
  return g.token;
}
const call = (grant, p) => fetch(`${base}/v1/proxy/bitrix24/${p}`, { headers: { authorization: `Bearer ${grant}` } });
const auditRows = (action) => app.repo.listAudit({ limit: 500 }).filter((x) => x.action === action);

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push(req.url);
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(DEALS));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-logs-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'info',
    logStream: { write: (s) => { logLines.push(s); } },
    proxyRatePerMin: LIMIT, now: () => clock,
    testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` },
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  // мастер: пароль, код, без Telegram
  const c = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await c.get(`/setup/${token}`); await c.get('/setup');
  await c.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  const secret = (await (await c.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>/)[1];
  await c.post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await c.post('/setup', { step: '3', mode: 'skip' });
  owner = c;
  const r = await owner.post('/keys/new/bitrix24', { webhook_url: `https://${HOST}/rest/1/${HOOK}/`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' });
  assert.equal(r.status, 302);
  credId = app.repo.listCredentials()[0].id;
  // фильтр «только сделки»: остальные методы закрыты (источник proxy.denied)
  assert.equal((await owner.post(`/keys/${credId}/filter`, DEAL_FORM)).status, 302);
});
after(async () => { await app.stop(); mock.close(); });

test('maskUrl: query отбрасывается, токены ссылок заменяются', () => {
  assert.equal(maskUrl('/l/abcDEF123?x=1'), '/l/****');
  assert.equal(maskUrl('/setup/abcDEF123'), '/setup/****');
  assert.equal(maskUrl('/setup'), '/setup');
  assert.equal(maskUrl('/setup/backup-codes.txt'), '/setup/backup-codes.txt');
  assert.equal(maskUrl('/keys?token=abc&x=1#frag'), '/keys');
  assert.equal(maskUrl('/v1/proxy/bitrix24/crm.deal.list.json?auth=zzz'), '/v1/proxy/bitrix24/crm.deal.list.json');
});

test('П-33: access-log не содержит токенов /l/* и /setup/*, query и значений из неё', async () => {
  const open = makeLink(app.repo, 'open', 900, base);
  const setup = makeLink(app.repo, 'setup', 900, base);
  logLines.length = 0;
  assert.equal((await fetch(`${base}/l/${open.token}`, { redirect: 'manual' })).status, 302);
  assert.equal((await fetch(`${base}/setup/${setup.token}`, { redirect: 'manual' })).status, 302);
  // недействительная ссылка с query: тоже без токена
  await fetch(`${base}/l/BADTOKENVALUE123?token=abc999&x=1`, { redirect: 'manual' });
  await fetch(`${base}/keys?token=abc999&x=1`, { redirect: 'manual' });
  const text = logText();
  assert.ok(text.includes('/l/****'), 'путь с маской есть');
  assert.ok(text.includes('/setup/****'));
  for (const secret of [open.token, setup.token, 'BADTOKENVALUE123', 'abc999', 'token=', 'x=1']) assert.ok(!text.includes(secret), `в логе нет: ${secret}`);
});

test('П-33 (Н-12): журнал ошибок без query — и для сайта, и для /v1/*', async () => {
  logLines.length = 0;
  // битый JSON даёт 400 в корневом обработчике и в обработчике плагина /v1
  const r1 = await fetch(`${base}/login?token=SECRETQ1&x=1`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  const r2 = await fetch(`${base}/v1/grants?token=SECRETQ2&x=1`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  assert.ok(r1.status >= 400 && r2.status >= 400);
  const text = logText();
  assert.ok(/request error/.test(text), 'ошибка запроса записана');
  assert.ok(!/unhandled/.test(text), 'ошибка запроса не считается сбоем');
  assert.ok(!text.includes('SECRETQ1') && !text.includes('SECRETQ2') && !text.includes('x=1'));
});

test('П-34: лимит прокси на агента: N+1-й вызов — 429, сервис, сейф и audit не затронуты', async () => {
  const grant = await newAgentGrant('limited');
  for (let i = 0; i < LIMIT; i++) assert.equal((await call(grant, 'crm.deal.list.json')).status, 200, `вызов ${i + 1}`);
  const calls0 = auditRows('proxy.call').length; const denied0 = auditRows('proxy.denied').length;
  const upstream0 = seen.length;
  let vaultGets = 0;
  const realGet = app.ctx.vault.get;
  app.ctx.vault.get = async (...a) => { vaultGets++; return realGet(...a); };
  try {
    for (let i = 0; i < 3; i++) {
      const r = await call(grant, i === 1 ? 'crm.contact.get.json' : 'crm.deal.list.json');
      assert.equal(r.status, 429);
      assert.deepEqual(await r.json(), { error: 'rate_limited' });
    }
  } finally { app.ctx.vault.get = realGet; }
  assert.equal(seen.length, upstream0, 'сервис не вызван');
  assert.equal(vaultGets, 0, 'сейф не читался');
  assert.equal(auditRows('proxy.call').length, calls0);
  assert.equal(auditRows('proxy.denied').length, denied0, 'фильтр до лимита не доходит');
  assert.equal(auditRows('proxy.rate_limited').length, 1, 'один агрегированный отказ в минуту');
});

test('П-34: повторные proxy.denied — одна запись в минуту, следующая со счётчиком', async () => {
  const grant = await newAgentGrant('denied');
  const before = auditRows('proxy.denied').length;
  for (let i = 0; i < 10; i++) assert.equal((await call(grant, 'crm.contact.get.json')).status, 403);
  assert.equal(auditRows('proxy.denied').length - before, 1);
  const first = auditRows('proxy.denied')[0];
  assert.equal(JSON.parse(first.meta_json).count, undefined);
  clock += 61_000;
  assert.equal((await call(grant, 'crm.contact.get.json')).status, 403);
  assert.equal(auditRows('proxy.denied').length - before, 2);
  assert.equal(JSON.parse(auditRows('proxy.denied')[0].meta_json).count, 9);
});

test('Н-4: смена пароля закрывает остальные сессии, текущая остаётся', async () => {
  const other = await fullSession();
  assert.equal((await other.get('/settings')).status, 200);
  const me = await fullSession();
  await me.get('/settings');
  const r = await me.post('/settings/password', { password_old: PASSWORD, password_new: NEW_PASSWORD, password_repeat: NEW_PASSWORD });
  assert.equal(r.status, 302);
  assert.ok(auditRows('password.change').length >= 1);
  const gone = await other.get('/settings');
  assert.equal(gone.status, 302);
  assert.match(gone.headers.get('location'), /^\/login/);
  assert.equal((await me.get('/settings')).status, 200, 'текущая сессия жива');
});
