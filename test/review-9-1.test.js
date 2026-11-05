// Регрессии по независимому ревью безопасности (пункты 9.1a-9.1d): # в пути, method override,
// «*» через «/» в rpc, потолок pending-заявок. Без сети: mock-апстрим на localhost.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { compileFilter } from '../src/core/filter.js';
import { validateAgentPath } from '../src/core/ssrf.js';
import { filterRequestHeaders } from '../src/core/proxy.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
const HOST = 'test.bitrix24.ru';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const RO = { enabled: false, entities: {}, methods: [], fields: [], readOnly: true };

let app, base, mock, seq = 0;
const seen = [];

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ url: req.url, method: req.method, headers: req.headers });
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"result":[]}');
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-r91-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` },
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
after(async () => { await app.stop(); mock.close(); mock.closeAllConnections?.(); });

// ---- мир теста ----
function mkAgent() {
  const n = ++seq;
  const token = `gwa_r${n}_${crypto.randomBytes(8).toString('hex')}`;
  app.repo.createAgent({ id: `ag${n}`, name: `agent${n}`, token_hash: sha(token), enabled: 1, all_credentials: 0 });
  return { id: `ag${n}`, token };
}
async function mkKey({ mode = 'always', filter = RO } = {}) {
  const n = ++seq;
  const id = `kc${n}`;
  app.repo.createCredential({
    id, provider: 'bitrix24', label: `key${n}`, kind: 'path', host: HOST,
    injection: { type: 'path', template: '/rest/{secret}' }, vault_param: `cred/${id}`, last4: '0000',
    mode, approval: 'web_button', max_ttl: 3600, max_calls: 1000, max_parallel: 4,
  });
  if (filter) app.repo.updateCredentialFilter(id, filter);
  await app.ctx.vault.put(`cred/${id}`, `S${n}/${crypto.randomBytes(6).toString('hex')}`);
  return { id };
}
const bindKeys = (agent, keys) => app.repo.setAgentCredentials(agent.id, { all: false, ids: keys.map((k) => k.id) });
async function restGrant(agent, key) {
  const r = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', credential_id: key.id, ttl: 600, calls: 50 }) });
  const j = await r.json();
  return { status: r.status, ...j };
}
/** Сырой запрос: fetch/URL схлопывает «#», агенту никто не мешает слать request-target как есть. */
function raw(token, method, p, headers = {}) {
  return new Promise((ok, fail) => {
    const u = new URL(base);
    const req = http.request({ host: u.hostname, port: u.port, method, path: p, headers: { authorization: `Bearer ${token}`, ...headers }, agent: false }, (res) => {
      const bufs = []; res.on('data', (c) => bufs.push(c)); res.on('end', () => ok({ status: res.statusCode, text: Buffer.concat(bufs).toString('utf8') }));
    });
    req.on('error', fail); req.end();
  });
}

// ---- MCP ----
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'r91', version: '1.0' } } };
function mcpPost(token, sid, body) {
  return new Promise((ok, fail) => {
    const u = new URL(base);
    const payload = Buffer.from(JSON.stringify(body));
    const h = { accept: 'application/json, text/event-stream', 'content-type': 'application/json', authorization: `Bearer ${token}`, 'content-length': String(payload.length), ...(sid && { 'mcp-session-id': sid }) };
    const req = http.request({ host: u.hostname, port: u.port, method: 'POST', path: '/mcp', headers: h, agent: false }, (res) => {
      const bufs = []; res.on('data', (c) => bufs.push(c));
      res.on('end', () => { const text = Buffer.concat(bufs).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch { /* пусто */ } ok({ status: res.statusCode, headers: res.headers, json }); });
    });
    req.on('error', fail); req.end(payload);
  });
}
async function mcpOpen(agent) {
  const r = await mcpPost(agent.token, null, INIT);
  const sid = r.headers['mcp-session-id'];
  await mcpPost(agent.token, sid, { jsonrpc: '2.0', method: 'notifications/initialized' });
  let rid = 1;
  return async (name, args) => {
    const x = await mcpPost(agent.token, sid, { jsonrpc: '2.0', id: ++rid, method: 'tools/call', params: { name, arguments: args } });
    return { isError: !!x.json.result.isError, data: JSON.parse(x.json.result.content[0].text) };
  };
}

// ---- 9.1a ----

test('9.1a: validateAgentPath отклоняет «#» и «?» внутри пути', () => {
  for (const p of ['/crm.deal.delete#.list.json', '/a#', '/a?b=1', '/a/b?']) assert.equal(validateAgentPath(p), false, p);
  assert.equal(validateAgentPath('/crm.deal.list.json'), true);
});

test('9.1a REST: «#» и «%23» в пути Bitrix24 с readOnly -> 400 bad_path, портал не вызван', async () => {
  const agent = mkAgent(); const key = await mkKey(); bindKeys(agent, [key]);
  const g = await restGrant(agent, key);
  assert.equal(g.status, 'approved', JSON.stringify(g));
  seen.length = 0;
  for (const p of ['crm.deal.delete#.list.json', 'crm.deal.delete%23.list.json', 'crm.deal.delete%2523.list.json', 'crm.deal.delete%3F.list.json']) {
    const r = await raw(g.token, 'POST', `/v1/proxy/bitrix24/${p}`);
    assert.equal(r.status, 400, p);
    assert.match(r.text, /bad_path/, p);
  }
  // «#» в query тоже не уходит к сервису
  const q = await raw(g.token, 'GET', '/v1/proxy/bitrix24/crm.deal.list.json?a=1#x');
  assert.equal(q.status, 400);
  assert.equal(seen.length, 0, 'портал не вызывался');
  // чтение по-прежнему работает, и сервис видит ровно тот путь, что проверил фильтр
  const ok = await raw(g.token, 'GET', '/v1/proxy/bitrix24/crm.deal.list.json?select=ID');
  assert.equal(ok.status, 200);
  assert.match(seen.at(-1).url, /^\/rest\/S\d+\/[0-9a-f]+\/crm\.deal\.list\.json\?select=ID$/);
});

test('9.1a MCP: «#» и «%23» в path -> bad_path, портал не вызван', async () => {
  const agent = mkAgent(); const key = await mkKey(); bindKeys(agent, [key]);
  const tool = await mcpOpen(agent);
  const acc = await tool('request_access', { service: 'bitrix24', credential_id: key.id, reason: 't' });
  assert.equal(acc.data.status, 'approved', JSON.stringify(acc.data));
  seen.length = 0;
  for (const p of ['/crm.deal.delete#.list.json', '/crm.deal.delete%23.list.json', '/crm.deal.delete%2523.list.json']) {
    const r = await tool('call', { service: 'bitrix24', method: 'POST', path: p });
    assert.equal(r.isError, true, p);
    assert.equal(r.data.error, 'bad_path', p);
  }
  assert.equal(seen.length, 0);
  const ok = await tool('call', { service: 'bitrix24', method: 'GET', path: '/crm.deal.list.json?select=ID' });
  assert.equal(ok.isError, false, JSON.stringify(ok.data));
  assert.equal(seen.length, 1);
});

// ---- 9.1b ----

test('9.1b: заголовки подмены метода не доходят до сервиса (любой регистр)', async () => {
  const out = filterRequestHeaders({ 'X-HTTP-Method-Override': 'DELETE', 'x-method-override': 'DELETE', 'X-Http-Method': 'DELETE', 'x-custom': 'ok' });
  assert.deepEqual(out, { 'x-custom': 'ok' });
  const agent = mkAgent(); const key = await mkKey(); bindKeys(agent, [key]);
  const g = await restGrant(agent, key);
  seen.length = 0;
  const r = await raw(g.token, 'GET', '/v1/proxy/bitrix24/crm.deal.list.json', { 'X-HTTP-Method-Override': 'DELETE', 'X-Method-Override': 'DELETE', 'X-HTTP-Method': 'DELETE', 'x-custom': 'ok' });
  assert.equal(r.status, 200);
  assert.equal(seen.length, 1);
  for (const h of ['x-http-method-override', 'x-method-override', 'x-http-method']) assert.equal(seen[0].headers[h], undefined, h);
  assert.equal(seen[0].headers['x-custom'], 'ok');
});

// ---- 9.1c ----

test('9.1c: в rpc «*» не пересекает «/»: /crm.deal.add/x.list не проходит ни readOnly, ни правило crm.*.list', () => {
  const ro = compileFilter({ ...RO }, bitrix);
  assert.equal(ro.allowMethod('POST', '/crm.deal.add/x.list'), false);
  assert.equal(ro.allowMethod('POST', '/crm.deal.add/x.list.json'), false);
  assert.equal(ro.allowMethod('POST', '/crm.deal.list.json'), true);
  const rule = compileFilter({ enabled: true, entities: {}, methods: ['crm.*.list'], fields: ['result'] }, bitrix);
  assert.equal(rule.allowMethod('/crm.deal.add/x.list'), false);
  assert.equal(rule.allowMethod('/crm.deal.list.json'), true);
  const both = compileFilter({ enabled: true, entities: {}, methods: ['crm.*.list'], fields: ['result'], readOnly: true }, bitrix);
  assert.equal(both.allowMethod('/crm.deal.add/x.list'), false);
  assert.equal(both.allowMethod('/crm.deal.list.json'), true);
  // Telegram: readMethods без изменений
  const tg = compileFilter({ ...RO }, loadCatalog(path.join(root, 'providers.yaml')).get('telegram'));
  assert.equal(tg.allowMethod('POST', '/getMe'), true);
  assert.equal(tg.allowMethod('POST', '/sendMessage'), false);
  assert.equal(tg.allowMethod('POST', '/getMe/x'), false);
});

test('9.1c REST: /crm.deal.add/x.list.json при readOnly -> 403, портал не вызван', async () => {
  const agent = mkAgent(); const key = await mkKey(); bindKeys(agent, [key]);
  const g = await restGrant(agent, key);
  seen.length = 0;
  const r = await raw(g.token, 'POST', '/v1/proxy/bitrix24/crm.deal.add/x.list.json');
  assert.equal(r.status, 403);
  assert.equal(seen.length, 0);
});

// ---- 9.1d ----

test('9.1d: не более 3 ожидающих на пару агент+ключ и 10 на агента, REST и MCP одинаково', async () => {
  const agent = mkAgent();
  const keys = [];
  for (let i = 0; i < 5; i++) keys.push(await mkKey({ mode: 'ask' }));
  bindKeys(agent, keys);
  const submit = (k) => restGrant(agent, k);
  for (let i = 0; i < 3; i++) assert.equal((await submit(keys[0])).status, 'pending');
  const over = await submit(keys[0]);
  assert.equal(over.status, 429);
  assert.equal(over.error, 'too_many_pending');
  // MCP: та же пара — тот же отказ
  const tool = await mcpOpen(agent);
  const m = await tool('request_access', { service: 'bitrix24', credential_id: keys[0].id, reason: 't' });
  assert.equal(m.isError, true);
  assert.equal(m.data.error, 'too_many_pending');
  // другой ключ: пока в пределах 10 на агента
  for (let i = 0; i < 3; i++) assert.equal((await submit(keys[1])).status, 'pending');
  for (let i = 0; i < 3; i++) assert.equal((await submit(keys[2])).status, 'pending');
  const mOk = await tool('request_access', { service: 'bitrix24', credential_id: keys[3].id, reason: 't' });
  assert.equal(mOk.data.status, 'pending');
  // 10 есть: любой ключ — отказ
  const cap = await submit(keys[4]);
  assert.equal(cap.status, 429);
  assert.equal(cap.error, 'too_many_pending');
  // другой агент не затронут
  const other = mkAgent(); bindKeys(other, [keys[0]]);
  assert.equal((await restGrant(other, keys[0])).status, 'pending');
  // решённая заявка освобождает место
  const first = app.repo.listPending().find((r) => r.agent_id === agent.id && r.credential_id === keys[0].id);
  app.repo.decideRequest(first.id, 'denied', 'web');
  assert.equal((await submit(keys[0])).status, 'pending');
});
