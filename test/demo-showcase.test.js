// Витрина демо: показывает весь каталог и настройки, но ничего не открывает. Без внешней сети.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { buildApp } from '../src/app.js';
import { sha256hex } from '../src/core/access.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';
import { KINDS } from '../src/web/onboarding.js';
import { DEMO_AGENT_ID } from '../src/demo/reset.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const YAML = path.join(root, 'providers.yaml');
const BANNER = 'Preview: this is how the screen looks in your own install.';
const regular = loadCatalog(YAML);
const SLUGS = regular.list().map((p) => p.slug);
const PAGES = ['/showcase/connect', '/showcase/settings', ...KINDS.map((k) => `/showcase/connect/${k}`), ...SLUGS.map((s) => `/showcase/services/${s}`)];

const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) { try { await f(); } catch { /* уборка */ } } });

async function boot({ demo = true } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-showcase-'));
  cleanup.push(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    vault: 'file', ...(demo && { demo: true, dataDirExplicit: true, prodHosts: [] }), env: {},
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const jar = new Map();
  const c = { app, base, token: '', ip: `10.8.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}` };
  const store = (r) => { for (const s of r.headers.getSetCookie?.() || []) { const [kv] = s.split(';'); const [k, v] = kv.split('='); jar.set(k, v); } };
  const headers = (more = {}) => ({ cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'x-forwarded-for': c.ip, ...more });
  const keep = async (r) => { store(r); r.text2 = await r.text(); const m = r.text2.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1]; return r; };
  c.get = async (p) => keep(await fetch(base + p, { headers: headers(), redirect: 'manual' }));
  c.post = async (p, fields = {}) => keep(await fetch(base + p, { method: 'POST', headers: headers({ 'content-type': 'application/x-www-form-urlencoded' }), body: new URLSearchParams({ _csrf: c.token, ...fields }), redirect: 'manual' }));
  c.api = (method, p, { token, body } = {}) => fetch(base + p, { method, headers: { 'x-forwarded-for': c.ip, ...(token && { authorization: `Bearer ${token}` }), ...(body !== undefined && { 'content-type': 'application/json' }) }, body: body === undefined ? undefined : JSON.stringify(body) });
  c.login = async () => { await c.get('/login'); return c.get('/'); };
  return c;
}

function mkAgent(app) {
  const id = 't-' + crypto.randomBytes(3).toString('hex');
  const token = 'gwa_' + crypto.randomBytes(24).toString('base64url');
  app.repo.createAgent({ id, name: id, token_hash: sha256hex(token), enabled: 1, all_credentials: 1 });
  return { id, token };
}

test('catalog.showcase: тот же состав, что в обычной установке, CRM первыми, «Другой» последним; get в демо знает только Demo CRM', () => {
  const demo = loadCatalog(YAML, { demo: true });
  const shown = demo.showcase().map((p) => p.slug);
  assert.deepEqual([...shown].sort(), [...SLUGS].sort());
  assert.ok(!shown.includes('demo'));
  assert.deepEqual(shown.slice(0, 5), ['bitrix24', 'bitrix24-box', 'amocrm', 'hubspot', 'pipedrive']);
  assert.equal(shown.at(-1), 'other');
  assert.deepEqual(demo.list().map((p) => p.slug), ['demo']);
  for (const s of shown) assert.equal(demo.get(s), undefined, s);
});

test('все экраны витрины: 200, плашка, нет форм, токенов, адреса демо', async () => {
  const c = await boot();
  await c.login();
  for (const p of PAGES) {
    const r = await c.get(p);
    assert.equal(r.status, 200, p);
    assert.ok(r.text2.includes(BANNER), `${p}: плашка`);
    assert.doesNotMatch(r.text2, /<form/, `${p}: форма`);
    assert.doesNotMatch(r.text2, /name="_csrf"/, `${p}: CSRF`);
    assert.doesNotMatch(r.text2, /gw[at]_[A-Za-z0-9]/, `${p}: токен`);
    assert.ok(!r.text2.includes(c.base), `${p}: адрес демо`);
    assert.ok(!r.text2.includes('127.0.0.1'), `${p}: адрес демо`);
  }
});

test('поля витрины отключены: все input, select, textarea и кнопки внутри fieldset disabled', async () => {
  const c = await boot();
  await c.login();
  for (const p of ['/showcase/settings', ...SLUGS.map((s) => `/showcase/services/${s}`)]) {
    const page = (await c.get(p)).text2;
    const main = page.slice(page.indexOf('<main'), page.indexOf('</main>'));
    const start = main.indexOf('<fieldset disabled>');
    assert.ok(start >= 0, `${p}: нет fieldset disabled`);
    const first = main.search(/<(input|select|textarea|button)\b/);
    assert.ok(first > start, `${p}: поле вне отключённого блока`);
    const last = Math.max(...['</select>', '<textarea', '<input', '<button'].map((x) => main.lastIndexOf(x)));
    assert.ok(last < main.lastIndexOf('</fieldset>'), `${p}: поле после отключённого блока`);
  }
});

test('запись в витрину: POST с настоящим CSRF и PUT дают 404', async () => {
  const c = await boot();
  await c.login();
  for (const p of PAGES) assert.equal((await c.post(p, { label: 'x' })).status, 404, p);
  const r = await fetch(`${c.base}/showcase/settings`, { method: 'PUT', headers: { 'x-forwarded-for': c.ip } });
  assert.equal(r.status, 404);
});

test('настоящие экраны остаются закрытыми', async () => {
  const c = await boot();
  await c.login();
  for (const p of ['/settings', '/settings/password', '/welcome', `/welcome/check/${DEMO_AGENT_ID}`, '/keys/new/bitrix24', '/keys/new/openai', '/keys/new/other', '/showcase', '/showcase/', '/showcase/services', '/showcase/connect/x/y']) {
    assert.equal((await c.get(p)).status, 404, p);
  }
  for (const p of ['/welcome/notify/telegram', '/welcome/notify/check', '/welcome/notify/slack']) {
    assert.equal((await c.post(p, { webhook: 'x' })).status, 404, `POST ${p}`);
  }
  for (const p of ['/showcase/services/demo', '/showcase/services/nope', '/showcase/connect/nope', '/showcase/connect/UPPER']) {
    assert.equal((await c.get(p)).status, 404, p);
  }
});

test('анонимный посетитель не видит витрину без автовхода', async () => {
  const c = await boot();
  const r = await c.get('/showcase/settings');
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/login');
});

test('заявка и вызов к сервису витрины отклоняются: REST и MCP', async () => {
  const c = await boot();
  const agent = mkAgent(c.app);
  const before = c.app.repo.listCredentials().length;
  const grant = await c.api('POST', '/v1/grants', { token: agent.token, body: { provider: 'bitrix24', reason: 'x' } });
  assert.ok(![200, 202].includes(grant.status), `заявка: ${grant.status}`);
  assert.equal((await c.api('GET', '/v1/proxy/bitrix24/crm.deal.list', { token: 'gwt_x' })).status, 404);
  assert.equal((await c.api('POST', '/v1/proxy/bitrix24/crm.deal.list', { token: 'gwt_x', body: {} })).status, 404);

  const transport = new StreamableHTTPClientTransport(new URL(`${c.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${agent.token}`, 'x-forwarded-for': c.ip } } });
  const client = new Client({ name: 'showcase-test', version: '1.0' });
  await client.connect(transport);
  cleanup.push(() => client.close());
  const tool = (name, args) => client.callTool({ name, arguments: args });
  const ls = await tool('list_services', {});
  const text = ls.content[0].text;
  assert.match(text, /demo/);
  assert.doesNotMatch(text, /bitrix24|amocrm|hubspot/);
  assert.equal((await tool('request_access', { service: 'bitrix24', reason: 'x' })).isError, true);
  assert.equal((await tool('call', { service: 'bitrix24', method: 'GET', path: 'crm.deal.list' })).isError, true);
  assert.equal(c.app.repo.listCredentials().length, before, 'ключей не прибавилось');
});

test('настоящие сессии посетителей не попадают на витрину настроек', async () => {
  const c = await boot();
  await c.login();
  const marker = 'VisitorBrowser/' + crypto.randomBytes(4).toString('hex');
  await fetch(`${c.base}/login`, { headers: { 'user-agent': marker, 'x-forwarded-for': c.ip }, redirect: 'manual' });
  assert.ok(c.app.repo.listSessions().some((s) => s.ua === marker), 'сессия с такой меткой реально есть');
  const page = (await c.get('/showcase/settings')).text2;
  assert.ok(!page.includes(marker));
  assert.match(page, /Firefox on Windows/);
});

test('/keys/new в демо: Demo CRM настоящий, остальные ведут на витрину', async () => {
  const c = await boot();
  await c.login();
  const page = (await c.get('/keys/new')).text2;
  assert.match(page, /href="\/keys\/new\/demo"/);
  assert.match(page, /Try it/);
  for (const s of SLUGS) assert.ok(page.includes(`href="/showcase/services/${s}"`), s);
  assert.doesNotMatch(page, /href="\/keys\/new\/(?!demo")/);
  assert.equal((page.match(/class="tile"/g) || []).length, SLUGS.length + 1);
});

test('меню демо ведёт на витрину, а не на настоящие экраны', async () => {
  const c = await boot();
  await c.login();
  const page = (await c.get('/')).text2;
  assert.match(page, /href="\/showcase\/connect"/);
  assert.match(page, /href="\/showcase\/settings"/);
  assert.doesNotMatch(page, /href="\/settings"/);
  assert.doesNotMatch(page, /action="\/logout"/);
});

test('витрина сервиса показывает весь набор настроек', async () => {
  const c = await boot();
  await c.login();
  const bx = (await c.get('/showcase/services/bitrix24')).text2;
  assert.match(bx, /name="webhook_url"/);
  for (const a of ['tg_button', 'tg_code', 'web_button', 'web_code']) assert.ok(bx.includes(`value="${a}"`), a);
  assert.match(bx, /name="ent_deals"/);
  assert.match(bx, /name="read_only"/);
  const amo = (await c.get('/showcase/services/amocrm')).text2;
  assert.match(amo, /name="account"/);
  assert.match(amo, /name="key"/);
  const other = (await c.get('/showcase/services/other')).text2;
  assert.match(other, /name="host"/);
  assert.match(other, /name="header"/);
});

test('витрина агента: заглушки адреса и токена, переменная, что сказать агенту, копирование', async () => {
  const c = await boot();
  await c.login();
  const code = (await c.get('/showcase/connect/claude-code')).text2;
  assert.match(code, /gateway\.example\.com\/mcp/);
  assert.match(code, /read -rs AGENTKEYGATE_TOKEN/);
  assert.match(code, /data-copy="#snippet"/);
  assert.match(code, /data-copy="#say"/);
  assert.match(code, /github\.com\/maximskorohod\/agentkeygate#connect-an-agent/);
  const desk = (await c.get('/showcase/connect/claude-desktop')).text2;
  assert.match(desk, /YOUR_AGENT_TOKEN/);
  const list = (await c.get('/showcase/connect')).text2;
  for (const k of KINDS) assert.ok(list.includes(`href="/showcase/connect/${k}"`), k);
});

test('вне демо витрины нет', async () => {
  const c = await boot({ demo: false });
  for (const p of PAGES) assert.equal((await c.get(p)).status, 404, p);
});
