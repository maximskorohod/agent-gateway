// Фильтр, этап B (п. 7.3): предпросмотр «Проверить на одном вызове», строка «Агент увидит: …» в заявке,
// filter в ответах API и MCP. Mock-портал Bitrix24 на localhost, сети нет.
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
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n, t } from '../src/i18n.js';
import { filterLine, describeFilter, previewRoute, fieldNames } from '../src/core/filter.js';
import { createNotifier } from '../src/notify.js';
import { buildText } from '../src/tg/bot.js';
import { requestPage, keyForm } from '../src/web/views/keys.js';

initI18n('en');

const HOST = 'test.bitrix24.ru';
// «секреты» и значения данных собираются в рантайме: в тексте теста их нет
const HOOK = ['wh', 'k9', 'x7f2', 'q81m'].join('');
const PHONE = ['+7 999 ', '777-', '01-02'].join('');
const CLIENT = ['Ivan', 'Petrov', 'Secret'].join('');
const DEALS = { result: [{ ID: '1', TITLE: 'DealTitleValue1', COMMENTS: 'call back', NAME: CLIENT, PHONE: [{ VALUE: PHONE }], 5: 'x' }], total: 1, time: { start: 1 } };
const FILTER = { enabled: true, entities: { deals: ['result.ID', 'result.TITLE'] }, methods: [], fields: [] };
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

let app, base, mock;
const seen = [];
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
let csrfTok = '';
async function grabCsrf(r) { if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; } }
async function get(p) { const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r); await grabCsrf(r); return r; }
async function post(p, fields = {}, { csrf = csrfTok, cookie = true } = {}) {
  const body = new URLSearchParams({ _csrf: csrf });
  for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
  const r = await fetch(base + p, { method: 'POST', headers: { ...(cookie && { cookie: cookieHeader() }), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r);
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}

let seq = 0;
async function mkKey({ mode = 'always', filter = null } = {}) {
  const n = ++seq;
  const id = `pk${n}`;
  app.repo.createCredential({
    id, provider: 'bitrix24', label: `crm${n}`, kind: 'path', host: HOST,
    injection: { type: 'path', template: '/rest/{secret}' }, vault_param: `cred/${id}`, last4: '0000', mode, max_ttl: 3600, max_calls: 100, max_parallel: 4,
  });
  if (filter) app.repo.updateCredentialFilter(id, filter);
  await app.ctx.vault.put(`cred/${id}`, `1/${HOOK}`);
  return id;
}
function mkAgent(keyIds) {
  const n = ++seq;
  const token = `gwa_p${n}_${crypto.randomBytes(8).toString('hex')}`;
  app.repo.createAgent({ id: `pa${n}`, name: `bot${n}`, token_hash: sha(token), enabled: 1, all_credentials: 0 });
  app.repo.setAgentCredentials(`pa${n}`, { all: false, ids: keyIds });
  return { id: `pa${n}`, token };
}
const grantReq = (agent, body) => fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 600, calls: 5, reason: 'check', ...body }) });
const audits = (action) => app.repo.listAudit({ limit: 5000 }).filter((x) => x.action === action);

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ url: req.url, method: req.method });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(DEALS));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-prev-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` } });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  const pass = ['correct', 'horse', 'battery'].join('-');
  await post('/setup', { step: '1', password: pass, password_repeat: pass });
  const secret = (await (await get('/setup')).text()).match(/<code>([A-Z2-7]{16,})<\/code>/)[1];
  await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); mock.close(); mock.closeAllConnections?.(); });

// ---- 1. предпросмотр ----

test('предпросмотр: один вызов с limit=1 от владельца, в ответе только имена полей, значений нет нигде', async () => {
  const id = await mkKey({ filter: FILTER });
  await get(`/keys/${id}`);
  const n = seen.length;
  const r = await post(`/keys/${id}/preview`);
  assert.equal(r.status, 200);
  const page = await r.text();
  assert.equal(seen.length, n + 1, 'ровно один вызов сервиса');
  assert.match(seen.at(-1).url, new RegExp(`^/rest/1/${HOOK}/crm\\.deal\\.list\\.json\\?limit=1$`));
  assert.match(page, /Fields: 8 → 4/);
  for (const name of ['result.ID', 'result.TITLE', 'result.PHONE.VALUE', 'result.NAME', 'result.COMMENTS', 'result.*']) assert.ok(page.includes(name), name);
  for (const secretValue of [PHONE, CLIENT, HOOK, 'call back', 'DealTitleValue1']) assert.ok(!page.includes(secretValue), 'в ответе нет значений и секретов');
  // «скрыто»: поля, которых агент не увидит
  const hidden = page.split('Hidden from the agent')[1];
  assert.ok(hidden.includes('result.PHONE.VALUE') && !hidden.includes('result.ID'));
  // audit: действие владельца, без агентского proxy.call, без значений
  const a = audits('proxy.preview');
  assert.equal(a.length, 1);
  assert.equal(a[0].actor, 'owner');
  assert.equal(audits('proxy.call').length, 0);
  const all = JSON.stringify(app.repo.listAudit({ limit: 5000 }));
  for (const v of [PHONE, CLIENT, HOOK]) assert.ok(!all.includes(v), 'значений нет в журнале');
});

test('предпросмотр не трогает квоты агентов и требует владельца и CSRF', async () => {
  const id = await mkKey({ filter: FILTER });
  const n = seen.length;
  // без сессии
  let r = await post(`/keys/${id}/preview`, {}, { cookie: false });
  assert.notEqual(r.status, 200);
  // с сессией, но неверный CSRF
  r = await post(`/keys/${id}/preview`, {}, { csrf: 'bad' });
  assert.ok([400, 403].includes(r.status), `csrf: ${r.status}`);
  assert.equal(seen.length, n, 'до сервиса не дошло');
  // чужой ключ
  await get('/');
  r = await post('/keys/nope/preview');
  assert.equal(r.status, 404);
  // квоты: активных пропусков нет и не появилось
  assert.equal(app.repo.listActiveGrants().length, 0);
});

test('proxy.call снаружи не принимает ownerCredentialId: без пропуска — 401, до сервиса не дошло', async () => {
  const id = await mkKey({ filter: FILTER });
  const n = seen.length;
  const r = await app.ctx.proxy.call({ ownerCredentialId: id, provider: 'bitrix24', method: 'GET', path: '/crm.deal.list', query: '' });
  assert.equal(r.ok, false);
  assert.equal(r.status, 401);
  assert.equal(seen.length, n);
});

test('предпросмотр без фильтра полей берёт первый тип каталога и честно показывает «ничего не скрыто»', async () => {
  const id = await mkKey({});
  await get(`/keys/${id}`);
  const page = await (await post(`/keys/${id}/preview`)).text();
  assert.match(page, /Fields: 8 → 8/);
});

test('previewRoute и fieldNames: маршрут без параметров, имена без значений', () => {
  const prov = { filter: { style: 'rest', entities: { a: { name: 'A', routes: ['GET /v1/items/:id', 'POST /v1/search', 'GET /Crm/Items'], fields: [] } } } };
  assert.deepEqual(previewRoute(null, prov), { method: 'GET', path: '/Crm/Items', query: '?limit=1' });
  assert.equal(previewRoute(null, { filter: { style: 'rest', entities: { a: { name: 'A', routes: ['GET /v1/items/:id'], fields: [] } } } }), null);
  assert.equal(previewRoute(null, { slug: 'x' }), null);
  const names = fieldNames({ list: [{ a: 1, b: { c: 'secret-value' } }], 12345: 'v', 'weird key!': 1, nul: null });
  assert.deepEqual(names, ['*', '?', 'list.a', 'list.b.c', 'nul']);
});

// ---- 2. «Агент увидит: …» ----

test('filterLine: типы и поля, только чтение, личные данные; одна строка, обрезка, без управляющих символов', () => {
  const prov = app.ctx.catalog.get('bitrix24');
  assert.equal(filterLine(null, prov), t('filter.line', { what: t('filter.line.all') }));
  const line = filterLine({ ...FILTER, readOnly: true, mask: true }, prov);
  assert.match(line, /^Agent will see: Deals \(ID, Title\); read-only; personal data hidden$/);
  // много полей: «+N»
  const many = filterLine({ enabled: true, entities: { deals: prov.filter.entities.deals.fields.map((x) => x.path) }, methods: [], fields: [] }, prov);
  assert.match(many, /\+11\)/);
  // чужое название типа с управляющими символами и длиной: одна строка не длиннее 400
  const evil = { filter: { entities: { x: { name: `A\n‮${'z'.repeat(900)}\r\n<b>`, methods: ['m'], fields: [{ path: 'result.A', label: 'L\tL\n' }] } } } };
  const l2 = filterLine({ enabled: true, entities: { x: ['result.A'] }, methods: [], fields: [] }, evil);
  assert.ok(!/[\r\n\t‮]/.test(l2) && Array.from(l2).length <= 400);
});

test('уведомление о заявке: строка «Агент увидит» есть в тексте всех каналов', async () => {
  const id = await mkKey({ mode: 'ask', filter: { ...FILTER, readOnly: true } });
  const agent = mkAgent([id]);
  const got = [];
  const ch = { id: 'mock', buttons: false, enabled: () => true, events: () => ['request.created'], send: async (m) => { got.push(m); } };
  const n = createNotifier({ repo: app.repo, vault: app.ctx.vault, logger: { error() {}, warn() {} }, catalog: app.ctx.catalog, publicUrl: 'https://gw.example.org', channels: [ch] });
  const cred = app.repo.getCredential(id);
  const req = { id: 'r1', ttl: 600, calls: 5, reason: 'check' };
  await n.requestCreated(req, cred, app.repo.getAgent(agent.id));
  assert.equal(got.length, 1);
  assert.match(got[0].text, /\nAgent will see: Deals \(ID, Title\); read-only$/);
  // без каталога строки нет, заявка уходит
  const n2 = createNotifier({ repo: app.repo, vault: app.ctx.vault, logger: { error() {}, warn() {} }, publicUrl: '', channels: [ch] });
  await n2.requestCreated(req, cred, app.repo.getAgent(agent.id));
  assert.ok(!got[1].text.includes('Agent will see'));
});

test('Telegram: текст заявки несёт строку фильтра; сбой описания заявку не ломает', () => {
  const cred = { provider: 'bitrix24', label: 'crm', approval: 'tg_button', filter: FILTER };
  const req = { id: 'r', ttl: 600, calls: 5, reason: 'x' };
  const text = buildText(req, cred, { name: 'bot' }, (c) => filterLine(c.filter, app.ctx.catalog.get(c.provider)));
  assert.match(text, /\nAgent will see: Deals \(ID, Title\)$/m);
  assert.ok(!buildText(req, cred, { name: 'bot' }, () => { throw new Error('boom'); }).includes('Agent will see'));
});

test('сайт: у ожидающей заявки видна строка фильтра, разметка в ней экранируется', async () => {
  const id = await mkKey({ mode: 'ask', filter: { ...FILTER, mask: true } });
  const agent = mkAgent([id]);
  const r = await grantReq(agent, {});
  assert.equal(r.status, 202);
  const { request_id } = await r.json();
  const page = await (await get(`/requests/${request_id}`)).text();
  assert.match(page, /Agent will see: Deals \(ID, Title\); personal data hidden/);
  // шаблон экранирует любую строку
  const html = requestPage({ csrf: 'x', request: { id: 'q1', agent_name: 'a', provider: 'bitrix24', credential_label: 'c', ttl: 600, calls: 1, reason: '' }, providers: [], filterLine: '<script>alert(1)</script>' }).toString();
  assert.ok(!html.includes('<script>alert') && html.includes('&lt;script&gt;'));
});

// ---- 3. filter в API и MCP ----

test('POST /v1/grants и GET /v1/grants/:id отдают filter без секретов; ключ без фильтра — без поля', async () => {
  const keyed = await mkKey({ mode: 'always', filter: { ...FILTER, readOnly: true, mask: true } });
  const a1 = mkAgent([keyed]);
  const r1 = await grantReq(a1, {});
  assert.equal(r1.status, 200);
  const j1 = await r1.json();
  assert.match(j1.token, /^gwt_/);
  assert.deepEqual(j1.filter.types, [{ id: 'deals', name: 'Deals', fields: ['result.ID', 'result.TITLE'] }]);
  assert.equal(j1.filter.read_only, true); assert.equal(j1.filter.mask, true);
  assert.ok(j1.filter.methods.includes('crm.deal.list'));
  assert.ok(!JSON.stringify(j1.filter).includes(HOOK));

  const plain = await mkKey({ mode: 'always' });
  const j2 = await (await grantReq(mkAgent([plain]), {})).json();
  assert.equal(j2.status, 'approved'); assert.ok(!('filter' in j2));

  // через ожидание: одобрение владельцем, затем GET
  const asked = await mkKey({ mode: 'ask', filter: FILTER });
  const a3 = mkAgent([asked]);
  const p = await (await grantReq(a3, {})).json();
  assert.equal(p.status, 'pending');
  const dec = await app.ctx.requests.decide({ requestId: p.request_id, approve: true, via: 'web' });
  assert.equal(dec.ok, true);
  const g = await fetch(`${base}/v1/grants/${p.request_id}`, { headers: { authorization: `Bearer ${a3.token}` } });
  assert.equal(g.status, 200);
  const jg = await g.json();
  assert.deepEqual(jg.filter.types, [{ id: 'deals', name: 'Deals', fields: ['result.ID', 'result.TITLE'] }]);
});

test('MCP: request_access и check_request возвращают filter', async () => {
  const k1 = await mkKey({ mode: 'always', filter: { ...FILTER, readOnly: true } });
  const agent = mkAgent([k1]);
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${agent.token}` } } });
  const client = new Client({ name: 'prev', version: '1.0' });
  await client.connect(transport);
  const res = JSON.parse((await client.callTool({ name: 'request_access', arguments: { service: 'bitrix24', reason: 'x' } })).content[0].text);
  assert.equal(res.status, 'approved');
  assert.deepEqual(res.filter.types, [{ id: 'deals', name: 'Deals', fields: ['result.ID', 'result.TITLE'] }]);
  assert.equal(res.filter.read_only, true);
  assert.ok(!JSON.stringify(res).includes('gwt_'));
  await transport.terminateSession(); await client.close();

  const k2 = await mkKey({ mode: 'ask', filter: FILTER });
  const a2 = mkAgent([k2]);
  const tr2 = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${a2.token}` } } });
  const c2 = new Client({ name: 'prev2', version: '1.0' });
  await c2.connect(tr2);
  const pend = JSON.parse((await c2.callTool({ name: 'request_access', arguments: { service: 'bitrix24', reason: 'x' } })).content[0].text);
  assert.equal(pend.status, 'pending');
  await app.ctx.requests.decide({ requestId: pend.request_id, approve: true, via: 'web' });
  const chk = JSON.parse((await c2.callTool({ name: 'check_request', arguments: { request_id: pend.request_id } })).content[0].text);
  assert.equal(chk.status, 'approved');
  assert.deepEqual(chk.filter.types, [{ id: 'deals', name: 'Deals', fields: ['result.ID', 'result.TITLE'] }]);
  await tr2.terminateSession(); await c2.close();
});

test('describeFilter: нет фильтра — null; только readOnly — без types', () => {
  const prov = app.ctx.catalog.get('bitrix24');
  assert.equal(describeFilter(null, prov), null);
  const d = describeFilter({ enabled: false, readOnly: true, entities: {}, methods: [], fields: [] }, prov);
  assert.equal(d.read_only, true); assert.ok(!('types' in d)); assert.ok(d.methods.includes('crm.*.list'));
});

// ---- 5. пометка unverified ----

test('форма ключа: пометка «поля не проверены» только у провайдера с filter.unverified', () => {
  const prov = app.ctx.catalog.get('bitrix24');
  const plain = app.ctx.catalog.get('bitrix24').filter ? { ...prov } : prov;
  const marked = { ...prov, filter: { ...prov.filter, unverified: true } };
  const pageMarked = String(keysFormHtml(marked));
  const pagePlain = String(keysFormHtml(plain));
  assert.ok(pageMarked.includes(t('filter.unverified')));
  assert.ok(!pagePlain.includes(t('filter.unverified')));
});

function keysFormHtml(provider) { return keyForm({ csrf: 'x', provider, values: {}, errors: [] }); }
