// И-4: потоковые тела. chunked без Content-Length, лимит maxBody на лету, рассогласование длины, ответ чанками с маскированием
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const HOST = 'test.bitrix24.ru';
const HOOK = 'abcdef123456';
const PASSWORD = 'correct-horse-battery';
const MAX_BODY = 2097152; // maxBody bitrix24 из providers.yaml
const DEAL_FORM = { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID', 'result.TITLE'] };

let app, base, mock, owner, credId, grant;
let seen = []; // что увидел сервис: { url, headers, body, aborted }

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

/** Отправка через http.request (не fetch): parts пишутся отдельными чанками; length задаёт Content-Length, иначе chunked. */
function send(p, { method = 'POST', parts = [], length = null, headers = {} } = {}) {
  return new Promise((resolve) => {
    const u = new URL(base);
    const h = { authorization: `Bearer ${grant}`, 'content-type': 'application/octet-stream', ...headers };
    if (length !== null) h['content-length'] = String(length); else h['transfer-encoding'] = 'chunked';
    const req = http.request({ host: u.hostname, port: u.port, method, path: `/v1/proxy/bitrix24/${p}`, headers: h, agent: false }, (res) => {
      const bufs = [];
      res.on('data', (c) => bufs.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(bufs).toString('utf8') }));
      res.on('error', (error) => resolve({ error }));
    });
    req.on('error', (error) => resolve({ error }));
    (async () => {
      for (const part of parts) {
        if (req.destroyed) return;
        if (!req.write(part)) await new Promise((r) => req.once('drain', r).once('close', r));
      }
      req.end();
    })();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lastCall = () => app.repo.listAudit({ limit: 50 }).find((x) => x.action === 'proxy.call');

async function newAgentGrant() {
  const r = await owner.post('/agents', { name: 'chunk-agent' });
  const agentToken = (await r.text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  const a = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 3000, calls: 90, reason: 'test' }) });
  const { request_id } = await a.json();
  await owner.post(`/requests/${request_id}/approve`, {});
  const g = await (await fetch(`${base}/v1/grants/${request_id}`, { headers: { authorization: `Bearer ${agentToken}` } })).json();
  return g.token;
}

before(async () => {
  mock = http.createServer((req, res) => {
    const rec = { url: req.url, headers: req.headers, chunks: [], aborted: false, ended: false };
    seen.push(rec);
    req.on('data', (c) => rec.chunks.push(c));
    req.on('aborted', () => { rec.aborted = true; });
    req.on('close', () => { if (!req.complete) rec.aborted = true; });
    req.on('end', async () => {
      rec.ended = true;
      rec.body = Buffer.concat(rec.chunks);
      if (req.url.includes('/split')) {
        // ответ без длины (chunked): ключ из пути разрезан между двумя записями
        res.setHeader('content-type', 'text/plain');
        res.write('start 1/abc');
        await sleep(40);
        res.write('def123456 end');
        res.end();
        return;
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ result: [{ ID: '1', TITLE: 'deal', SECRET: 'x' }], total: 1, len: rec.body.length }));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-chunked-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` },
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const c = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await c.get(`/setup/${token}`); await c.get('/setup');
  await c.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  const secret = (await (await c.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>/)[1];
  await c.post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await c.post('/setup', { step: '3', mode: 'skip' });
  owner = c;
  const r = await owner.post('/keys/new/bitrix24', { webhook_url: `https://${HOST}/rest/1/${HOOK}/`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2', protect_form: '1' }); // protect_form без галочек: readOnly выключен (тест пишет)
  assert.equal(r.status, 302);
  credId = app.repo.listCredentials()[0].id;
  grant = await newAgentGrant();
});
after(async () => { await app.stop(); mock.close(); });

test('chunked без Content-Length: сервис получает всё тело целиком, длина не искажена', async () => {
  seen = [];
  const r = await send('crm.deal.add', { parts: ['hello ', 'chunked ', 'world'] });
  assert.equal(r.status, 200);
  const s = seen[0];
  assert.equal(s.body.toString(), 'hello chunked world');
  const cl = s.headers['content-length'];
  assert.ok(cl === undefined ? /chunked/i.test(s.headers['transfer-encoding'] || '') : Number(cl) === 19, 'либо chunked, либо верная длина');
  assert.ok(!(cl !== undefined && s.headers['transfer-encoding']), 'нельзя оба заголовка сразу');
});

test('Content-Length сервис получает верный, когда агент его задал', async () => {
  seen = [];
  const r = await send('crm.deal.add', { parts: ['0123456789'], length: 10 });
  assert.equal(r.status, 200);
  assert.equal(seen[0].body.toString(), '0123456789');
  const cl = seen[0].headers['content-length'];
  assert.ok(cl === undefined ? /chunked/i.test(seen[0].headers['transfer-encoding'] || '') : Number(cl) === 10);
});

test('chunked больше maxBody: 413 body_too_large, сервис обрывается, слот свободен, audit записан', async () => {
  seen = [];
  const block = Buffer.alloc(64 * 1024, 97);
  const parts = Array.from({ length: Math.ceil(MAX_BODY / block.length) + 4 }, () => block);
  const r = await send('crm.deal.add', { parts });
  // сервер может закрыть соединение раньше, чем клиент допишет тело: тогда статуса нет, но ответ 413 успевает прийти в типичном случае
  if (r.status !== undefined) { assert.equal(r.status, 413); assert.equal(JSON.parse(r.body).error, 'body_too_large'); }
  else assert.ok(r.error, 'обрыв соединения');
  await sleep(300);
  // сервис не получил полного тела
  const total = seen.reduce((n, s) => n + (s.body ? s.body.length : s.chunks.reduce((a, c) => a + c.length, 0)), 0);
  assert.ok(total <= MAX_BODY + 64 * 1024, `к сервису ушло ${total} байт`);
  assert.ok(seen.every((s) => s.aborted || !s.ended || (s.body && s.body.length <= MAX_BODY)), 'запрос к сервису оборван');
  // слот освобождён: два параллельных вызова (max_parallel = 2) проходят
  const [a, b] = await Promise.all([send('crm.deal.add', { parts: ['a'] }), send('crm.deal.add', { parts: ['b'] })]);
  assert.equal(a.status, 200); assert.equal(b.status, 200);
  assert.ok(lastCall());
  assert.ok(app.repo.listAudit({ limit: 50 }).some((x) => x.action === 'proxy.call' && JSON.parse(x.meta_json || '{}').status === 413), 'audit со статусом 413');
});

test('Content-Length больше maxBody отклоняется до чтения тела', async () => {
  seen = [];
  const r = await send('crm.deal.add', { parts: [], length: MAX_BODY + 1 });
  assert.equal(r.status, 413);
  assert.equal(JSON.parse(r.body).error, 'body_too_large');
  assert.equal(seen.length, 0);
});

test('Content-Length меньше фактического тела: лишние байты не доходят до сервиса', async () => {
  seen = [];
  const raw = await new Promise((resolve) => {
    const u = new URL(base);
    const sock = net.connect(Number(u.port), u.hostname, () => {
      sock.write(`POST /v1/proxy/bitrix24/crm.deal.add HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${grant}\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhelloEXTRA-BYTES`);
    });
    const bufs = [];
    sock.on('data', (c) => bufs.push(c));
    sock.on('close', () => resolve(Buffer.concat(bufs).toString('utf8')));
    sock.on('error', () => resolve(Buffer.concat(bufs).toString('utf8')));
  });
  await sleep(100);
  // парсер Node либо отклоняет склеенный запрос целиком (400), либо отдаёт ровно 5 байт; лишнее до сервиса не доходит
  assert.match(raw, /^HTTP\/1\.1 /);
  for (const s of seen) assert.ok(s.body.toString() === 'hello', 'сервис видит только hello');
  assert.ok(!seen.some((s) => s.body.toString().includes('EXTRA')));
});

test('ответ сервиса chunked без длины: поток идёт агенту, ключ, разрезанный между чанками, маскируется', async () => {
  const r = await send('split', { method: 'GET' });
  assert.equal(r.status, 200);
  assert.ok(!r.headers['content-length'], 'длины у потока нет');
  assert.ok(!r.body.includes(HOOK));
  assert.equal(r.body, 'start **** end');
});

test('фильтр данных: chunked-тело читается целиком и уходит с верной длиной', async () => {
  assert.equal((await owner.post(`/keys/${credId}/filter`, DEAL_FORM)).status, 302);
  seen = [];
  const json = JSON.stringify({ filter: { ID: 1 }, select: ['*'] });
  const h = Math.floor(json.length / 2);
  const r = await send('crm.deal.list', { parts: [json.slice(0, h), json.slice(h)], headers: { 'content-type': 'application/json' } });
  assert.equal(r.status, 200);
  const s = seen[0];
  const parsed = JSON.parse(s.body.toString());
  assert.deepEqual(parsed.filter, { ID: 1 });
  const cl = s.headers['content-length'];
  assert.ok(cl !== undefined && Number(cl) === s.body.length, 'Content-Length соответствует телу');
  assert.ok(!s.headers['transfer-encoding']);
  // лишнее поле SECRET из ответа сервиса фильтр убирает
  assert.ok(!r.body.includes('SECRET'));
});

test('фильтр данных: chunked больше maxBody даёт 413', async () => {
  const block = Buffer.alloc(64 * 1024, 97);
  const parts = Array.from({ length: Math.ceil(MAX_BODY / block.length) + 4 }, () => block);
  const r = await send('crm.deal.list', { parts, headers: { 'content-type': 'application/json' } });
  if (r.status !== undefined) { assert.equal(r.status, 413); assert.equal(JSON.parse(r.body).error, 'body_too_large'); }
  else assert.ok(r.error);
  await sleep(200);
  const [a, b] = await Promise.all([send('crm.deal.list', { parts: ['{}'], headers: { 'content-type': 'application/json' } }), send('crm.deal.list', { parts: ['{}'], headers: { 'content-type': 'application/json' } })]);
  assert.equal(a.status, 200); assert.equal(b.status, 200);
});
