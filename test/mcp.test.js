// mcp/server.js: сессии, токены пропусков в памяти, Bearer на каждом запросе (контракт access-mcp.md, тесты 11-26)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const HOST_B = 'test.bitrix24.ru';
const HOST_O = 'api.openai.com';
const MAX_RESP = 4096;
const ORIGIN_OK = 'http://allowed.example';
const FILTER = { enabled: true, entities: { deals: ['result.ID', 'result.TITLE'] }, methods: [], fields: [] };

let app, base, app2, base2, mock, seq = 0;
let clock = 1_700_000_000_000; // подменяемые часы app2 (простой и срок жизни сессий)
const seen = [];
const holds = []; // открытые «медленные» ответы сервиса
const logs = []; // все строки логов обоих приложений
const captured = []; // все тела ответов /mcp (тест 21)
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const releaseAll = () => { while (holds.length) holds.pop().end(); };
const audits = (a, action) => a.repo.listAudit({ limit: 5000 }).filter((x) => x.action === action).map((x) => ({ ...x, meta: x.meta_json ? JSON.parse(x.meta_json) : null }));
async function waitFor(fn, ms = 4000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 15)); }
  throw new Error('waitFor timeout');
}

async function startApp(over = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-mcp-'));
  const a = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'debug', logStream: { write: (s) => logs.push(String(s)) },
    mcpMaxResponse: MAX_RESP, mcpSweepSec: 3600,
    testUpstream: { [HOST_B]: `http://127.0.0.1:${mock.address().port}`, [HOST_O]: `http://127.0.0.1:${mock.address().port}` },
    ...over,
  });
  await a.start();
  return [a, `http://127.0.0.1:${a.fastify.server.address().port}`];
}

before(async () => {
  mock = http.createServer((req, res) => {
    const rec = { url: req.url, headers: req.headers, method: req.method, bytes: 0, cancelled: false };
    seen.push(rec);
    rec.closed = new Promise((r) => res.on('close', () => { rec.cancelled = !res.writableFinished; r(); }));
    req.on('data', (c) => { rec.bytes += c.length; });
    req.on('end', () => {
      const mode = req.headers['x-mode'] || 'json';
      if (mode === 'slow') { res.writeHead(200, { 'content-type': 'text/plain' }); res.write('first-' + 'x'.repeat(40)); holds.push(res); return; }
      if (mode === 'big') {
        // ~3,6 МБ кусками с учётом backpressure: пока клиент не читает, ответ не дописан и обрыв виден как cancelled
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        const chunk = '€'.repeat(30000);
        let i = 0;
        const pump = () => {
          while (i < 40) { i += 1; if (!res.write(chunk)) { res.once('drain', pump); return; } }
          res.end();
        };
        pump();
        return;
      }
      if (mode === 'bin') { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(Buffer.alloc(3000, 0xff)); return; }
      if (mode === 'edge') {
        // секрет ключа лежит в пути /rest/<секрет>/crm.edge; кладём его так, чтобы граница обрезки пришлась на середину
        const secret = req.url.slice('/rest/'.length, req.url.indexOf('/crm.'));
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('x'.repeat(MAX_RESP - 5) + secret + 'y'.repeat(300));
        return;
      }
      if (mode === 'deals') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ result: [{ ID: '1', TITLE: 't', SECRET: 'x' }], total: 1 })); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, url: req.url }));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  [app, base] = await startApp({ mcpOrigins: [ORIGIN_OK] });
  [app2, base2] = await startApp({ proxyRatePerMin: 4, mcpNow: () => clock, mcpMaxLifetimeSec: 1000 });
});
after(async () => {
  releaseAll();
  await app.stop(); await app2.stop();
  mock.close(); mock.closeAllConnections?.();
});

// ---- мир теста: агенты, ключи, привязки ----

function mkAgent(a) {
  const n = ++seq;
  const token = `gwa_t${n}_${crypto.randomBytes(8).toString('hex')}`;
  a.repo.createAgent({ id: `ag${n}`, name: `agent${n}`, token_hash: sha(token), enabled: 1, all_credentials: 0 });
  return { id: `ag${n}`, token };
}
async function mkKey(a, { provider = 'bitrix24', mode = 'always', filter = null } = {}) {
  const n = ++seq;
  const id = `kc${n}`;
  const bx = provider === 'bitrix24';
  const secret = bx ? `S${n}/abcdef${String(n).padStart(6, '0')}` : `sk-test-${n}-xxxxxxxxxxxxxxxx`;
  a.repo.createCredential({
    id, provider, label: `key${n}`, kind: bx ? 'path' : 'static', host: bx ? HOST_B : HOST_O,
    injection: bx ? { type: 'path', template: '/rest/{secret}' } : { type: 'header', name: 'authorization', prefix: 'Bearer ' },
    vault_param: `cred/${id}`, last4: '0000', mode, max_ttl: 3600, max_calls: 1000, max_parallel: 4,
  });
  if (filter) a.repo.updateCredentialFilter(id, filter);
  await a.ctx.vault.put(`cred/${id}`, secret);
  return { id, secret, provider, label: `key${n}` };
}
const bind = (a, agent, keys) => a.repo.setAgentCredentials(agent.id, { all: false, ids: keys.map((k) => k.id) });
const grantOf = (a, agent, key) => a.repo.listActiveGrants().find((g) => g.agent_id === agent.id && g.credential_id === key.id);

// ---- HTTP-клиент (http.request: Host и Origin задаются как нужно) ----

function httpReq(baseUrl, method, { headers = {}, body, early = false } = {}) {
  let req;
  const p = new Promise((resolve, reject) => {
    const u = new URL(baseUrl);
    const payload = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (payload) h['content-length'] = String(payload.length);
    req = http.request({ host: u.hostname, port: u.port, method, path: '/mcp', headers: h, agent: false }, (res) => {
      const done = (text) => {
        captured.push(text);
        let json = null; try { json = JSON.parse(text); } catch { /* не JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      };
      if (early) { res.destroy(); return done(''); }
      const bufs = [];
      res.on('data', (c) => bufs.push(c));
      res.on('end', () => done(Buffer.concat(bufs).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(payload);
  });
  p.abort = () => req?.destroy();
  return p;
}
const hdr = (token, sid, extra = {}) => ({
  accept: 'application/json, text/event-stream', 'content-type': 'application/json',
  ...(token && { authorization: `Bearer ${token}` }), ...(sid && { 'mcp-session-id': sid }), ...extra,
});
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0' } } };

async function open(baseUrl, agent) {
  const r = await httpReq(baseUrl, 'POST', { headers: hdr(agent.token), body: INIT });
  assert.equal(r.status, 200, r.text);
  const sid = r.headers['mcp-session-id'];
  assert.match(sid, /^[0-9a-f]{32}$/);
  const n = await httpReq(baseUrl, 'POST', { headers: hdr(agent.token, sid), body: { jsonrpc: '2.0', method: 'notifications/initialized' } });
  assert.equal(n.status, 202);
  let rid = 1;
  const s = {
    sid, agent, baseUrl,
    rpc: (method, params) => httpReq(baseUrl, 'POST', { headers: hdr(agent.token, sid), body: { jsonrpc: '2.0', id: ++rid, method, params } }),
    del: () => httpReq(baseUrl, 'DELETE', { headers: hdr(agent.token, sid) }),
    async tool(name, args = {}) {
      const r2 = await s.rpc('tools/call', { name, arguments: args });
      const res = r2.json?.result;
      assert.ok(res, `нет result: ${r2.text}`);
      return { isError: !!res.isError, data: JSON.parse(res.content[0].text), raw: res };
    },
    start(name, args) { // вызов без ожидания; abort() рвёт соединение
      const p = httpReq(baseUrl, 'POST', { headers: hdr(agent.token, sid), body: { jsonrpc: '2.0', id: ++rid, method: 'tools/call', params: { name, arguments: args } } });
      p.result = p.then((r2) => ({ isError: !!r2.json?.result?.isError, data: JSON.parse(r2.json.result.content[0].text) }));
      p.result.catch(() => {});
      return p;
    },
  };
  return s;
}
const callB = (s, p, extra = {}) => s.tool('call', { service: 'bitrix24', method: 'GET', path: p, ...extra });
const access = (s, key) => s.tool('request_access', { service: key.provider, credential_id: key.id, reason: 'test' });

async function world(a, baseUrl, { keys = 1, ...keyOpts } = {}) {
  const agent = mkAgent(a);
  const ks = [];
  for (let i = 0; i < keys; i++) ks.push(await mkKey(a, keyOpts));
  bind(a, agent, ks);
  const s = await open(baseUrl, agent);
  return { agent, keys: ks, key: ks[0], s };
}

// ---- 11. Bearer на каждом запросе ----

test('11: Bearer проверяется на каждом запросе: POST/GET/DELETE без токена, с неверным gwa_ и без префикса -> 401', async () => {
  const { agent, s } = await world(app, base);
  const sid = s.sid;
  const calls = [
    ['POST', { body: { jsonrpc: '2.0', id: 9, method: 'tools/list' } }],
    ['GET', { early: true }],
    ['DELETE', {}],
  ];
  for (const [method, opt] of calls) {
    for (const token of [null, 'gwa_' + 'z'.repeat(40), 'abc', agent.token.replace('gwa_', 'gwx_')]) {
      const r = await httpReq(base, method, { ...opt, headers: hdr(token, sid) });
      assert.equal(r.status, 401, `${method} ${token}`);
      assert.equal(r.headers['www-authenticate'], 'Bearer');
      if (r.json) assert.equal(r.json.error, 'unauthorized');
    }
  }
  // сессия жива, с верным токеном работает; initialize без токена тоже 401
  const list = await s.rpc('tools/list');
  assert.deepEqual(list.json.result.tools.map((t) => t.name), ['list_services', 'request_access', 'check_request', 'call']);
  assert.equal((await httpReq(base, 'POST', { headers: hdr(null), body: INIT })).status, 401);
});

// ---- 12. чужая сессия ----

test('12: агент B с чужим session id получает 404 session_not_found, сессия A жива, audit mcp.denied', async () => {
  const a = await world(app, base);
  const b = await world(app, base);
  for (const [method, opt] of [['POST', { body: { jsonrpc: '2.0', id: 5, method: 'tools/list' } }], ['GET', {}], ['DELETE', {}]]) {
    const r = await httpReq(base, method, { ...opt, headers: hdr(b.agent.token, a.s.sid) });
    assert.equal(r.status, 404, method);
    assert.equal(r.json.error, 'session_not_found');
  }
  // несуществующий id неотличим
  const ghost = await httpReq(base, 'POST', { headers: hdr(b.agent.token, 'f'.repeat(32)), body: { jsonrpc: '2.0', id: 5, method: 'tools/list' } });
  assert.deepEqual([ghost.status, ghost.json.error], [404, 'session_not_found']);
  // сессия A работает
  assert.equal((await a.s.tool('list_services')).isError, false);
  const row = audits(app, 'mcp.denied').find((x) => x.actor === `agent:${b.agent.id}` && x.meta.reason === 'session_mismatch');
  assert.ok(row, 'audit mcp.denied session_mismatch');
  assert.equal(row.meta.via, 'mcp');
});

// ---- 13. два агента x две сессии x два ключа ----

test('13: два агента x две сессии x два ключа: токены не смешиваются, upstream видит нужный секрет', async () => {
  const K1 = await mkKey(app); const K2 = await mkKey(app);
  const A = mkAgent(app); const B = mkAgent(app);
  bind(app, A, [K1, K2]); bind(app, B, [K2]);
  const a1 = await open(base, A); const a2 = await open(base, A);
  const b1 = await open(base, B); const b2 = await open(base, B);
  const lastUrl = () => seen[seen.length - 1].url;

  // без credential_id при двух доступных ключах - список {id,label}
  const need = await a1.tool('request_access', { service: 'bitrix24', reason: 'r' });
  assert.equal(need.isError, true);
  assert.equal(need.data.error, 'credential_id_required');
  assert.deepEqual(need.data.credentials.map((c) => Object.keys(c).sort()), [['id', 'label'], ['id', 'label']]);

  assert.equal((await access(a1, K1)).data.status, 'approved');
  assert.equal((await access(a2, K2)).data.status, 'approved');
  // A, сессия 1: единственный токен - K1
  assert.equal((await callB(a1, '/crm.x')).data.status, 200);
  assert.ok(lastUrl().startsWith(`/rest/${K1.secret}/crm.x`), 'сессия 1 -> K1');
  assert.equal((await callB(a2, '/crm.y')).data.status, 200);
  assert.ok(lastUrl().startsWith(`/rest/${K2.secret}/crm.y`), 'сессия 2 -> K2');
  // токен чужой сессии недоступен
  assert.equal((await callB(a1, '/crm.z', { credential_id: K2.id })).data.error, 'no_grant');
  const svc2 = (await a2.tool('list_services')).data.services[0].credentials;
  assert.equal(svc2.find((c) => c.id === K1.id).access.state, 'none');
  assert.equal(svc2.find((c) => c.id === K2.id).access.state, 'active');
  assert.equal(svc2.find((c) => c.id === K2.id).usable, true);

  // токены на оба ключа в одной сессии и без credential_id
  assert.equal((await access(a1, K2)).data.status, 'approved');
  const both = await callB(a1, '/crm.w');
  assert.equal(both.data.error, 'credential_id_required');
  assert.deepEqual(both.data.credentials.map((c) => c.id).sort(), [K1.id, K2.id].sort());
  const n = seen.length;
  assert.equal((await callB(a1, '/crm.w', { credential_id: K2.id })).data.status, 200);
  assert.equal(seen.length, n + 1);
  assert.ok(lastUrl().startsWith(`/rest/${K2.secret}/`));

  // B: только K2
  const bl = (await b1.tool('list_services')).data.services;
  assert.deepEqual(bl.map((s) => s.slug), ['bitrix24']);
  assert.deepEqual(bl[0].credentials.map((c) => c.id), [K2.id]);
  assert.equal((await access(b1, K1)).data.error, 'no_credential');
  assert.equal((await b1.tool('request_access', { service: 'bitrix24', reason: 'r' })).data.status, 'approved');
  assert.equal((await callB(b1, '/crm.b')).data.status, 200);
  assert.ok(lastUrl().startsWith(`/rest/${K2.secret}/crm.b`));
  // вторая сессия B без токена
  assert.equal((await callB(b2, '/crm.b')).data.error, 'no_grant');
  // никогда чужой секрет
  for (const rec of seen) assert.ok(!(rec.url.includes(K1.secret) && rec.url.includes(K2.secret)));
  assert.equal(seen.filter((r) => r.url.includes(K1.secret)).length, 1);
});

// ---- 14. check_request ----

test('14: check_request: чужая и несуществующая заявки неотличимы, своя из другой сессии привязывает токен к текущей', async () => {
  const K3 = await mkKey(app, { provider: 'openai', mode: 'ask' });
  const A = mkAgent(app); const B = mkAgent(app);
  bind(app, A, [K3]); bind(app, B, [K3]);
  const a1 = await open(base, A); const a2 = await open(base, A);
  // заявка B создаётся ядром напрямую
  const rb = app.ctx.requests.submit({ agent: app.repo.getAgent(B.id), credential: app.repo.getCredential(K3.id), reason: 'b', via: 'mcp' });
  assert.equal(rb.kind, 'pending');
  const foreign = await a1.tool('check_request', { request_id: rb.requestId });
  const ghost = await a1.tool('check_request', { request_id: 'nope-nope-nope' });
  assert.deepEqual([foreign.isError, foreign.data], [true, { error: 'not_found' }]);
  assert.deepEqual([ghost.isError, ghost.data], [true, { error: 'not_found' }]);

  const req = await a1.tool('request_access', { service: 'openai', reason: 'need' });
  assert.equal(req.data.status, 'pending');
  assert.equal(req.data.poll_after, 5);
  assert.equal((await a2.tool('check_request', { request_id: req.data.request_id })).data.status, 'pending');
  assert.equal((await a2.tool('call', { service: 'openai', method: 'GET', path: '/v1/models' })).data.error, 'no_grant');
  assert.equal((await app.ctx.requests.decide({ requestId: req.data.request_id, approve: true, via: 'web' })).ok, true);
  // заявка читается из другой сессии того же агента; токен привязывается к ней
  const ok2 = await a2.tool('check_request', { request_id: req.data.request_id });
  assert.equal(ok2.data.status, 'approved');
  assert.equal(ok2.data.credential_id, K3.id);
  const n = seen.length;
  const c2 = await a2.tool('call', { service: 'openai', method: 'GET', path: '/v1/models' });
  assert.equal(c2.data.status, 200);
  assert.equal(seen[n].headers.authorization, `Bearer ${K3.secret}`);
  // первая сессия токена не получала
  assert.equal((await a1.tool('call', { service: 'openai', method: 'GET', path: '/v1/models' })).data.error, 'no_grant');
  assert.ok(audits(app, 'mcp.token.bind').some((r) => r.meta.request === req.data.request_id));
});

// ---- 15. отзыв посреди сессии ----

for (const [name, revoke] of [
  ['revokeGrant', (w, g) => app.repo.revokeGrant(g.id)],
  ['softDeleteCredential', (w) => app.repo.softDeleteCredential(w.key.id)],
  ['смена привязки', (w) => app.repo.setAgentCredentials(w.agent.id, { all: false, ids: [] })],
]) {
  test(`15: отзыв (${name}): следующий call -> invalid_grant, запись удалена (-> no_grant), upstream не вызван, inflight 0`, async () => {
    const w = await world(app, base);
    assert.equal((await access(w.s, w.key)).data.status, 'approved');
    assert.equal((await callB(w.s, '/crm.ok')).data.status, 200);
    const g = grantOf(app, w.agent, w.key);
    revoke(w, g);
    const n = seen.length;
    const r = await callB(w.s, '/crm.after');
    assert.deepEqual([r.isError, r.data.error, r.data.status], [true, 'invalid_grant', 401]);
    assert.equal((await callB(w.s, '/crm.after')).data.error, 'no_grant');
    assert.equal(seen.length, n, 'upstream не получил вызов');
    assert.equal(app.repo.getGrant(g.id).inflight, 0);
  });
}

// ---- 16. отзыв и закрытие сессии во время call ----

test('16: отзыв во время идущего call не рвёт его, следующий отклонён; закрытие сессии во время call абортит upstream', async () => {
  const w = await world(app, base);
  await access(w.s, w.key);
  const g = grantOf(app, w.agent, w.key);
  const n0 = seen.length;
  const slow = w.s.start('call', { service: 'bitrix24', method: 'GET', path: '/crm.slow', headers: { 'x-mode': 'slow' } });
  await waitFor(() => seen.length > n0);
  assert.equal(app.repo.getGrant(g.id).inflight, 1);
  app.repo.revokeGrant(g.id);
  releaseAll();
  const r = await slow.result;
  assert.equal(r.isError, false);
  assert.equal(r.data.status, 200);
  assert.ok(r.data.body.startsWith('first-'));
  assert.equal((await callB(w.s, '/crm.next')).data.error, 'invalid_grant');
  await waitFor(() => app.repo.getGrant(g.id).inflight === 0);

  // закрытие сессии во время call
  const w2 = await world(app, base);
  await access(w2.s, w2.key);
  const g2 = grantOf(app, w2.agent, w2.key);
  const n1 = seen.length;
  const slow2 = w2.s.start('call', { service: 'bitrix24', method: 'GET', path: '/crm.slow', headers: { 'x-mode': 'slow' } });
  await waitFor(() => seen.length > n1);
  assert.equal((await w2.s.del()).status, 200);
  await waitFor(() => app.repo.getGrant(g2.id).inflight === 0);
  await seen[n1].closed;
  assert.equal(seen[n1].cancelled, true, 'upstream получил отмену');
  assert.equal((await httpReq(base, 'POST', { headers: hdr(w2.agent.token, w2.s.sid), body: { jsonrpc: '2.0', id: 3, method: 'tools/list' } })).status, 404);
  slow2.abort();
  const closeRow = audits(app, 'mcp.session.close').find((x) => x.actor === `agent:${w2.agent.id}`);
  assert.equal(closeRow.meta.reason, 'client');
  assert.equal(closeRow.meta.tokens, 1);
});

// ---- 17. агент выключен ----

test('17: агент выключен (setAgentEnabled и прямой UPDATE): следующий запрос 401, сессия закрыта с reason agent_disabled', async () => {
  const w = await world(app, base);
  await access(w.s, w.key);
  app.repo.setAgentEnabled(w.agent.id, false);
  const r = await httpReq(base, 'POST', { headers: hdr(w.agent.token, w.s.sid), body: { jsonrpc: '2.0', id: 3, method: 'tools/list' } });
  assert.equal(r.status, 401);
  const row = audits(app, 'mcp.session.close').find((x) => x.actor === `agent:${w.agent.id}`);
  assert.equal(row.meta.reason, 'agent_disabled');
  assert.equal(row.meta.tokens, 1);

  // прямой UPDATE при ещё активном grant
  const w2 = await world(app, base);
  await access(w2.s, w2.key);
  app.db.prepare('UPDATE agents SET enabled = 0 WHERE id = ?').run(w2.agent.id);
  assert.ok(grantOf(app, w2.agent, w2.key), 'grant ещё активен');
  assert.equal((await httpReq(base, 'POST', { headers: hdr(w2.agent.token, w2.s.sid), body: { jsonrpc: '2.0', id: 3, method: 'tools/list' } })).status, 401);
  assert.equal(audits(app, 'mcp.session.close').find((x) => x.actor === `agent:${w2.agent.id}`).meta.reason, 'agent_disabled');

  // таймер: выключенного агента ловит и проверка раз в 30 с, без запросов от него
  const w3 = await world(app, base);
  const before = app.mcp.count();
  app.db.prepare('UPDATE agents SET enabled = 0 WHERE id = ?').run(w3.agent.id);
  app.mcp.sweep();
  assert.equal(app.mcp.count(), before - 1);
  assert.equal(audits(app, 'mcp.session.close').find((x) => x.actor === `agent:${w3.agent.id}`).meta.reason, 'agent_disabled');
});

// ---- 18. Origin и Host ----

test('18: Origin вне списка -> 403 до разбора тела; Origin из mcpOrigins и без Origin проходят; чужой Host -> 403', async () => {
  const agent = mkAgent(app);
  const evil = await httpReq(base, 'POST', { headers: hdr(agent.token, null, { origin: 'http://evil.example' }), body: 'это не JSON' });
  assert.deepEqual([evil.status, evil.json.error], [403, 'origin_not_allowed']);
  const host = await httpReq(base, 'POST', { headers: hdr(agent.token, null, { host: 'evil.example' }), body: INIT });
  assert.deepEqual([host.status, host.json.error], [403, 'host_not_allowed']);
  const allowed = await httpReq(base, 'POST', { headers: hdr(agent.token, null, { origin: ORIGIN_OK }), body: INIT });
  assert.equal(allowed.status, 200);
  const none = await httpReq(base, 'POST', { headers: hdr(agent.token), body: INIT });
  assert.equal(none.status, 200);
  assert.ok(audits(app, 'mcp.denied').some((r) => r.meta.reason === 'origin'));
  assert.ok(audits(app, 'mcp.denied').some((r) => r.meta.reason === 'host'));
});

// ---- 19. размеры тела ----

test('19: тело POST больше mcpBodyLimit -> 413 payload_too_large; GET с body отвергается; крупное допустимое тело доходит', async () => {
  const w = await world(app, base);
  await access(w.s, w.key);
  const g = grantOf(app, w.agent, w.key);
  const n = seen.length;
  const big = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'call', arguments: { service: 'bitrix24', method: 'POST', path: '/crm.add', body: 'a'.repeat(262144) } } }));
  assert.ok(big.length > app.ctx.config.mcpBodyLimit);
  const r = await httpReq(base, 'POST', { headers: hdr(w.agent.token, w.s.sid), body: big });
  assert.deepEqual([r.status, r.json.error], [413, 'payload_too_large']);
  assert.equal(seen.length, n);
  assert.equal(app.repo.getGrant(g.id).calls_used, 0);
  // GET с телом недопустим
  assert.equal((await callB(w.s, '/crm.get', { body: 'x' })).data.error, 'bad_request');
  // 200 КиБ проходят
  const ok = await w.s.tool('call', { service: 'bitrix24', method: 'POST', path: '/crm.add', body: 'a'.repeat(200000) });
  assert.equal(ok.data.status, 200);
  assert.equal(seen[n].bytes, 200000);
});

// ---- 20. обрезка ответа ----

test('20: ответ 1 МБ обрезается по mcpMaxResponse без разрыва UTF-8, бинарный -> body:null, секрет на границе не течёт', async () => {
  const w = await world(app, base);
  await access(w.s, w.key);
  const g = grantOf(app, w.agent, w.key);
  const n = seen.length;
  const big = await callB(w.s, '/crm.big', { headers: { 'x-mode': 'big' } });
  assert.equal(big.isError, false);
  assert.equal(big.data.truncated, true);
  assert.equal(big.data.bytes, MAX_RESP);
  assert.equal(big.data.body, '€'.repeat(1365), '4096 байт = 1365 символов по 3 байта + обрубок, обрубок отброшен');
  assert.ok(!big.data.body.includes('�'));
  await waitFor(() => app.repo.getGrant(g.id).inflight === 0);
  await seen[n].closed;
  assert.equal(seen[n].cancelled, true, 'после обрезки поток разрушен, upstream отменён');

  const bin = await callB(w.s, '/crm.bin', { headers: { 'x-mode': 'bin' } });
  assert.deepEqual([bin.data.body, bin.data.binary, bin.data.bytes, bin.data.truncated], [null, true, 3000, false]);

  const edge = await callB(w.s, '/crm.edge', { headers: { 'x-mode': 'edge' } });
  assert.equal(edge.data.truncated, true);
  assert.ok(!edge.data.body.includes(w.key.secret), 'секрет не в ответе');
  assert.ok(!edge.data.body.includes(w.key.secret.slice(0, 6)), 'ни его начало');
  assert.ok(edge.data.body.includes('****'));
  assert.equal(edge.data.headers['content-type'], 'text/plain');
  await waitFor(() => app.repo.getGrant(g.id).inflight === 0);
});

// ---- 22. лимиты ----

test('22a: шестая сессия агента -> 429 too_many_sessions; после DELETE место освобождается', async () => {
  const w = await world(app2, base2);
  const extra = [];
  for (let i = 0; i < 4; i++) extra.push(await open(base2, w.agent));
  const r = await httpReq(base2, 'POST', { headers: hdr(w.agent.token), body: INIT });
  assert.deepEqual([r.status, r.json.error], [429, 'too_many_sessions']);
  const other = mkAgent(app2);
  assert.equal((await open(base2, other)).sid.length, 32, 'другой агент не затронут');
  assert.equal((await extra[0].del()).status, 200);
  assert.equal((await httpReq(base2, 'POST', { headers: hdr(w.agent.token), body: INIT })).status, 200);
  assert.ok(audits(app2, 'mcp.denied').some((x) => x.meta.reason === 'too_many_sessions' && x.actor === `agent:${w.agent.id}`));
});

test('22b: простой дольше mcpIdleSec и срок жизни закрывают сессию, токены очищены', async () => {
  const w = await world(app2, base2);
  await access(w.s, w.key);
  clock += 901_000;
  app2.mcp.sweep();
  const r = await httpReq(base2, 'POST', { headers: hdr(w.agent.token, w.s.sid), body: { jsonrpc: '2.0', id: 3, method: 'tools/list' } });
  assert.deepEqual([r.status, r.json.error], [404, 'session_not_found']);
  const row = audits(app2, 'mcp.session.close').find((x) => x.actor === `agent:${w.agent.id}`);
  assert.deepEqual([row.meta.reason, row.meta.tokens], ['idle', 1]);
  // новая сессия не видит старый токен
  const s2 = await open(base2, w.agent);
  assert.equal((await callB(s2, '/crm.x')).data.error, 'no_grant');

  // срок жизни 1000 с: сессия не простаивает, но живёт дольше
  const w2 = await world(app2, base2);
  clock += 800_000; assert.equal((await w2.s.rpc('tools/list')).status, 200);
  app2.mcp.sweep();
  clock += 800_000; app2.mcp.sweep();
  const row2 = audits(app2, 'mcp.session.close').find((x) => x.actor === `agent:${w2.agent.id}`);
  assert.equal(row2.meta.reason, 'lifetime');
});

test('22c: общий limits.proxy исчерпывается суммой REST и MCP вызовов одного агента', async () => {
  const w = await world(app2, base2);
  const g = await fetch(`${base2}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${w.agent.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', credential_id: w.key.id, reason: 't' }) }).then((r) => r.json());
  assert.equal(g.status, 'approved');
  const rest = () => fetch(`${base2}/v1/proxy/bitrix24/crm.x`, { headers: { authorization: `Bearer ${g.token}` } }).then(async (r) => { await r.text(); return r.status; });
  assert.equal(await rest(), 200);
  assert.equal(await rest(), 200);
  // MCP подхватывает тот же действующий grant
  assert.equal((await access(w.s, w.key)).data.status, 'approved');
  assert.equal((await callB(w.s, '/crm.m1')).data.status, 200);
  assert.equal((await callB(w.s, '/crm.m2')).data.status, 200);
  const over = await callB(w.s, '/crm.m3');
  assert.deepEqual([over.isError, over.data.error, over.data.status], [true, 'rate_limited', 429]);
  assert.equal(await rest(), 429);
  assert.ok(audits(app2, 'mcp.token.bind').some((x) => x.meta.reuse === true));
});

test('22d: request_access делит лимит 30/мин с REST', async () => {
  const w = await world(app2, base2);
  for (let i = 0; i < 30; i++) {
    const r = await fetch(`${base2}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${w.agent.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'nope' }) });
    assert.equal(r.status, 400);
    await r.text();
  }
  const r = await access(w.s, w.key);
  assert.deepEqual([r.isError, r.data.error], [true, 'rate_limited']);
});

// ---- 23. повтор id и ротация токена ----

test('23: id после DELETE -> 404; ротация gwa_ токена -> старый 401, новый работает с той же сессией', async () => {
  const w = await world(app, base);
  assert.equal((await w.s.del()).status, 200);
  assert.equal((await w.s.rpc('tools/list')).status, 404);
  assert.equal((await w.s.del()).status, 404);

  const w2 = await world(app, base);
  const fresh = `gwa_rot_${crypto.randomBytes(8).toString('hex')}`;
  app.db.prepare('UPDATE agents SET token_hash = ? WHERE id = ?').run(sha(fresh), w2.agent.id);
  const old = await httpReq(base, 'POST', { headers: hdr(w2.agent.token, w2.s.sid), body: { jsonrpc: '2.0', id: 3, method: 'tools/list' } });
  assert.equal(old.status, 401);
  const neu = await httpReq(base, 'POST', { headers: hdr(fresh, w2.s.sid), body: { jsonrpc: '2.0', id: 4, method: 'tools/list' } });
  assert.equal(neu.status, 200);
});

// ---- 24. методы, пути, заголовки ----

test('24: только GET|POST|PUT|PATCH|DELETE; плохие пути -> bad_path; Authorization из headers не доходит до сервиса', async () => {
  const w = await world(app, base);
  await access(w.s, w.key);
  const n = seen.length;
  for (const method of ['HEAD', 'OPTIONS', 'TRACE', 'CONNECT', '']) assert.equal((await callB(w.s, '/crm.x', { method })).data.error, 'bad_method', method);
  for (const p of ['/a#frag', '/a/../b', '/a/%2e%2e/b', '/a/%252e/b', 'no-slash', '/./x']) {
    const r = await callB(w.s, p);
    assert.deepEqual([r.isError, r.data.error], [true, 'bad_path'], p);
  }
  assert.equal((await callB(w.s, '/crm.x', { headers: { 'bad header': 'x' } })).data.error, 'bad_headers');
  assert.equal((await callB(w.s, '/crm.x', { headers: { a: 'x\r\ny' } })).data.error, 'bad_headers');
  assert.equal(seen.length, n, 'ни один плохой вызов не дошёл до сервиса');

  const ok = await callB(w.s, '/crm.h?select=1', { headers: { authorization: 'Bearer evil', 'x-custom': '1' } });
  assert.equal(ok.data.status, 200);
  const rec = seen[seen.length - 1];
  assert.equal(rec.headers.authorization, undefined);
  assert.equal(rec.headers['x-custom'], '1');
  assert.ok(rec.url.endsWith('/crm.h?select=1'));
  // ответ: только белый список заголовков
  assert.deepEqual(Object.keys(ok.data.headers), ['content-type']);
});

// ---- 25. фильтр ----

test('25: закрытый фильтром метод -> method_not_allowed + allowed, квота не тратится, audit proxy.denied с via mcp', async () => {
  const w = await world(app, base, { filter: FILTER });
  await access(w.s, w.key);
  const g = grantOf(app, w.agent, w.key);
  const n = seen.length;
  const r = await callB(w.s, '/crm.lead.list.json');
  assert.equal(r.isError, true);
  assert.equal(r.data.error, 'method_not_allowed');
  assert.equal(r.data.status, 403);
  assert.ok(Array.isArray(r.data.allowed) && r.data.allowed.length > 0);
  assert.equal(app.repo.getGrant(g.id).calls_used, 0);
  assert.equal(seen.length, n);
  const row = audits(app, 'proxy.denied').find((x) => x.meta.agent === w.agent.id);
  assert.equal(row.meta.via, 'mcp');
  assert.match(row.meta.session, /^[0-9a-f]{8}$/);
  // разрешённый метод проходит, лишние поля убраны
  const ok = await callB(w.s, '/crm.deal.list.json', { headers: { 'x-mode': 'deals' } });
  assert.equal(ok.data.status, 200);
  assert.ok(!ok.data.body.includes('SECRET'));
  // list_services показывает шаблоны фильтра, без значений
  const f = (await w.s.tool('list_services')).data.services[0].credentials[0].filter;
  assert.ok(f.methods.length > 0 && Array.isArray(f.fields));
});

// ---- 26. автопропуск ----

test('26: auto-grant: request_access отвечает approved без токена и call сразу работает; audit с via mcp', async () => {
  const w = await world(app, base);
  const r = await w.s.tool('request_access', { service: 'bitrix24', reason: 'auto' });
  assert.equal(r.isError, false);
  assert.deepEqual(Object.keys(r.data).sort(), ['credential_id', 'expires_at', 'max_calls', 'status']);
  assert.equal(r.data.status, 'approved');
  assert.equal(r.data.credential_id, w.key.id);
  assert.equal((await callB(w.s, '/crm.auto')).data.status, 200);
  assert.ok(audits(app, 'grant.auto').some((x) => x.meta.via === 'mcp' && x.actor === `agent:${w.agent.id}`));
  const open = audits(app, 'mcp.session.open').find((x) => x.actor === `agent:${w.agent.id}`);
  assert.equal(open.meta.client, 'test-client 1.0');
  assert.match(open.target, /^[0-9a-f]{8}$/);
});

// ---- совместимость с клиентом SDK ----

test('клиент SDK по Streamable HTTP: initialize, tools/list, list_services, закрытие сессии', async () => {
  const w = await world(app, base);
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${w.agent.token}` } } });
  const client = new Client({ name: 'sdk-client', version: '2.0' });
  await client.connect(transport);
  const tools = await client.listTools();
  assert.deepEqual(tools.tools.map((t) => t.name), ['list_services', 'request_access', 'check_request', 'call']);
  const res = await client.callTool({ name: 'request_access', arguments: { service: 'bitrix24', reason: 'sdk' } });
  assert.equal(JSON.parse(res.content[0].text).status, 'approved');
  const c = await client.callTool({ name: 'call', arguments: { service: 'bitrix24', method: 'GET', path: '/crm.sdk' } });
  assert.equal(JSON.parse(c.content[0].text).status, 200);
  await transport.terminateSession();
  await client.close();
  assert.ok(audits(app, 'mcp.session.close').some((x) => x.actor === `agent:${w.agent.id}` && x.meta.reason === 'client'));
});

// ---- 21. токены gwt_ нигде не видны (последним: сканирует всё накопленное) ----

test('21: gwt_ токен не встречается в ответах, audit и логах', async () => {
  assert.ok(captured.length > 50, 'есть что сканировать');
  // токен детерминирован (HMAC от grant и срока): воспроизводим выданные и ищем их в перехваченном
  const tokens = [app, app2].flatMap((a) => a.repo.listActiveGrants().map((g) => a.ctx.grants.reissueToken(g).token));
  assert.ok(tokens.length > 5);
  const corpus = [
    ['ответы', captured.join('\n')],
    ['audit', JSON.stringify(app.repo.listAudit({ limit: 100000 })) + JSON.stringify(app2.repo.listAudit({ limit: 100000 }))],
    ['логи', logs.join('\n')],
  ];
  for (const [what, text] of corpus) {
    assert.ok(!text.includes('gwt_'), `${what}: подстрока gwt_`);
    for (const t of tokens) assert.ok(!text.includes(t.slice(4, 40)), `${what}: часть токена`);
  }
  // session id целиком в аудит и логи не попадает
  const sids = audits(app, 'mcp.session.open').map((r) => r.target);
  assert.ok(sids.every((t) => t.length === 8));
});
