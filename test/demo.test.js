// Демо-режим GW_DEMO=1 (П-20, пункт 6.6): изоляция при запуске, сеть, allowlist, MCP, лимиты, сброс, фоновые циклы.
// Без внешней сети. Сетевой guard ставится process-wide, поэтому проверяется в дочернем процессе.
// Фальшивые секреты собираются в рантайме из кусков, токены берутся из ответов сервера.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { buildApp } from '../src/app.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { createVault } from '../src/vault/index.js';
import { sha256hex } from '../src/core/access.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';
import { assertDemoIsolation, assertDemoDataDirFresh, createDemoTransport, createDemoMock, DEMO_MARKER } from '../src/demo/guard.js';
import { DEMO_KEY, DEMO_KEY_PATTERN } from '../src/demo/reset.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BANNER = 'Shared demo. Data resets hourly. Do not enter real data.';
const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) { try { await f(); } catch { /* уборка */ } } });

const tmpDir = (prefix) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};
const paths = (dataDir) => ({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key') });
const demoCfg = (dataDir, extra = {}) => ({ ...paths(dataDir), vault: 'file', demo: true, dataDirExplicit: true, prodHosts: [], publicUrl: 'http://127.0.0.1', ...extra });

/** Демо-приложение с листенером; клиент с cookie-банкой и IP через X-Forwarded-For (loopback доверенный прокси). */
async function boot(extra = {}) {
  const dataDir = tmpDir('gw-demo-');
  const app = await buildApp({
    ...paths(dataDir), demo: true, dataDirExplicit: true, prodHosts: [], env: {},
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', ...extra,
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const jar = new Map();
  const c = { app, base, dataDir, token: '', ip: `10.9.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}` };
  const store = (res) => { for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); } };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const headers = (more = {}) => ({ cookie: cookie(), 'x-forwarded-for': c.ip, ...more });
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: headers(), redirect: 'manual' }); store(r);
    r.text2 = await r.clone().text(); const m = r.text2.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    return r;
  };
  c.post = async (p, fields = {}) => {
    const r = await fetch(base + p, { method: 'POST', headers: headers({ 'content-type': 'application/x-www-form-urlencoded' }), body: new URLSearchParams({ _csrf: c.token, ...fields }), redirect: 'manual' }); store(r);
    r.text2 = await r.clone().text(); const m = r.text2.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    return r;
  };
  /** Автовход демо-владельца: /login выдаёт сессию без пароля, затем страница даёт CSRF-токен. */
  c.login = async () => { await c.get('/login'); return c.get('/'); };
  c.api = (method, p, { token, body, ip } = {}) => fetch(base + p, {
    method,
    headers: { 'x-forwarded-for': ip || c.ip, ...(token && { authorization: `Bearer ${token}` }), ...(body !== undefined && { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return c;
}

/** Агент с токеном напрямую в базе (токен в тестах не пишется литералом). */
function mkAgent(app, id = 't-' + crypto.randomBytes(3).toString('hex')) {
  const token = 'gwa_' + crypto.randomBytes(24).toString('base64url');
  app.repo.createAgent({ id, name: id, token_hash: sha256hex(token), enabled: 1, all_credentials: 1 });
  return { id, token };
}
/** Пропуск к демо-ключу: режим «без вопросов», выдача через REST. */
async function grantFor(c, agent) {
  c.app.repo.updateCredentialPolicy('demo', { mode: 'always', always_until: null });
  const r = await c.api('POST', '/v1/grants', { token: agent.token, body: { provider: 'demo', ttl: 600, calls: 20, reason: 'test' } });
  assert.equal(r.status, 200);
  return (await r.json()).token;
}

// ---- 1. assertDemoIsolation ----

/** Пустой каталог данных + база + file-сейф; setup(ctx) готовит «грязное» состояние, затем вызывается проверка. */
async function isolation(setup = () => {}, cfgExtra = {}, env = {}) {
  const dataDir = tmpDir('gw-iso-');
  const cfg = demoCfg(dataDir, cfgExtra);
  const db = openDb(cfg.dbPath);
  cleanup.push(() => { try { db.close(); } catch { /* уже закрыта */ } });
  const vault = createVault(cfg);
  const repo = createRepo(db, { demo: true });
  const ctx = { cfg, db, vault, repo, dataDir };
  await setup(ctx);
  const run = () => assertDemoIsolation({ cfg, db, vault, env });
  return { ctx, run };
}
const addCred = (repo, id, provider) => repo.createCredential({ id, provider, label: 'x', kind: 'static', host: 'api.example.com', injection: { type: 'header', name: 'authorization' }, vault_param: `cred/${id}`, last4: '1234' });

test('1. изоляция: пустой каталог проходит и создаёт .demo-data; повторный запуск тоже', async () => {
  const { ctx, run } = await isolation();
  await run();
  assert.ok(fs.existsSync(path.join(ctx.dataDir, DEMO_MARKER)));
  await run();
});

test('1. изоляция: чужой ключ в сейфе → отказ, в тексте cred/<id> и нет значения секрета', async () => {
  const secret = ['sk', 'live', crypto.randomBytes(6).toString('hex')].join('_');
  const { run } = await isolation(async ({ vault }) => { await vault.put('cred/abc', secret); });
  await assert.rejects(run, (e) => {
    assert.match(e.message, /^demo_isolation: vault_foreign_name cred\/abc$/);
    assert.ok(!e.message.includes(secret));
    return true;
  });
});

test('1. изоляция: ключ другого провайдера в базе (в том числе удалённый) → отказ', async () => {
  const live = await isolation(({ repo }) => addCred(repo, 'bx1', 'bitrix24'));
  await assert.rejects(live.run, /demo_isolation: db_foreign_credential cred\/bx1$/);
  const deleted = await isolation(({ repo }) => { addCred(repo, 'bx2', 'bitrix24'); repo.softDeleteCredential('bx2'); });
  await assert.rejects(deleted.run, /demo_isolation: db_foreign_credential cred\/bx2$/);
  const demoOnly = await isolation(({ repo }) => addCred(repo, 'demo', 'demo'));
  await demoOnly.run(); // ключ провайдера demo — не повод для отказа
});

test('1. изоляция: ключ посетителя проходит только с записью demo в базе и значением формата demo-…', async () => {
  const value = 'demo-' + crypto.randomBytes(5).toString('hex');
  const visitor = await isolation(async ({ repo, vault }) => { addCred(repo, 'v1', 'demo'); await vault.put('cred/v1', value); });
  await visitor.run();
  // запись demo есть, но значение похоже на настоящий ключ: отказ, значения в тексте нет
  const secret = ['sk', 'live', crypto.randomBytes(6).toString('hex')].join('_');
  const real = await isolation(async ({ repo, vault }) => { addCred(repo, 'v2', 'demo'); await vault.put('cred/v2', secret); });
  await assert.rejects(real.run, (e) => { assert.match(e.message, /^demo_isolation: vault_foreign_name cred\/v2$/); assert.ok(!e.message.includes(secret)); return true; });
  // значение верного формата без записи в базе: отказ
  const orphan = await isolation(async ({ vault }) => { await vault.put('cred/v3', value); });
  await assert.rejects(orphan.run, /demo_isolation: vault_foreign_name cred\/v3$/);
});

test('1. перезапуск после ключа посетителя: демо стартует, сброс убирает ключ', async () => {
  const c = await boot(); await c.login();
  await c.get('/keys/new/demo');
  const added = await c.post('/keys/new/demo', { key: 'demo-' + crypto.randomBytes(5).toString('hex'), mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' });
  assert.equal(added.status, 302);
  assert.equal(c.app.repo.listCredentials().length, 2);
  await c.app.stop();
  const again = await buildApp({ ...paths(c.dataDir), demo: true, dataDirExplicit: true, prodHosts: [], env: {}, lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  cleanup.push(() => again.stop());
  assert.deepEqual(again.repo.listCredentials().map((x) => x.id), ['demo']);
});

test('3. сценарий демо: Simulate, Approve, curl с рабочим пропуском', async () => {
  const c = await boot(); await c.login();
  let home = await c.get('/');
  assert.match(home.text2, /Try it in 3 steps/);
  assert.match(home.text2, /action="\/demo\/simulate"/);
  assert.doesNotMatch(home.text2, /id="demo-curl"/);
  assert.equal((await c.post('/demo/simulate')).status, 302);
  home = await c.get('/');
  const id = home.text2.match(/class="btn primary" href="\/requests\/([^"]+)"/)?.[1];
  assert.ok(id, 'шаг 2: ссылка на свою заявку');
  assert.doesNotMatch(home.text2, /id="demo-curl"/, 'до одобрения пропуска нет');
  await c.get(`/requests/${id}`);
  assert.equal((await c.post(`/requests/${id}/approve`)).status, 302);
  home = await c.get('/');
  const code = home.text2.match(/<code id="demo-curl">([^<]+)<\/code>/)?.[1];
  assert.ok(code, 'шаг 3: команда curl на главной');
  const cmd = code.replace(/&quot;/g, '"');
  assert.ok(cmd.includes('http://127.0.0.1/v1/proxy/demo/deals'), 'адрес из publicUrl');
  const token = cmd.match(/Bearer (gwt_[^"]+)"/)?.[1];
  assert.ok(token, 'в команде пропуск');
  assert.ok(!cmd.includes('demo-public01'), 'ключа в команде нет');
  const r = await c.api('GET', '/v1/proxy/demo/deals', { token });
  assert.equal(r.status, 200);
  assert.ok((await r.json()).result.length > 0);
  // другая сессия чужого пропуска не видит
  const other = await boot(); await other.login();
  assert.doesNotMatch((await other.get('/')).text2, /id="demo-curl"/);
  // отказ возвращает к шагу 1
  await c.post('/demo/simulate');
  home = await c.get('/');
  const id2 = home.text2.match(/class="btn primary" href="\/requests\/([^"]+)"/)?.[1];
  await c.get(`/requests/${id2}`);
  await c.post(`/requests/${id2}/deny`);
  assert.doesNotMatch((await c.get('/')).text2, /id="demo-curl"/);
});

test('3. экраны демо без кнопок, закрытых allowlist-ом, и без текстов про код', async () => {
  const c = await boot(); await c.login();
  const key = (await c.get('/keys/demo')).text2;
  for (const a of ['/keys/demo/preview', '/keys/demo/replace', '/keys/demo/delete']) assert.ok(!key.includes(`action="${a}"`), a);
  assert.doesNotMatch(key, /fresh code/);
  assert.doesNotMatch(key, /you get a notification/);
  assert.doesNotMatch(key, /value="web_code"/);
  assert.match(key, /<input type="hidden" name="approval" value="web_button">/);
  const agents = (await c.get('/agents')).text2;
  for (const a of ['disable', 'enable', 'delete']) assert.ok(!agents.includes(`/agents/demo-agent/${a}"`), a);
  assert.match(agents, /action="\/agents\/demo-agent\/keys"/, 'привязка ключей остаётся');
  assert.doesNotMatch((await c.get('/audit')).text2, /href="\/settings"/);
  assert.doesNotMatch((await c.get('/keys/new/demo')).text2, /value="web_code"/);
  // все оставшиеся формы и ссылки экранов не ведут в 404
  for (const p of ['/', '/keys/demo', '/keys/new/demo', '/agents', '/audit', '/stats']) {
    const page = (await c.get(p)).text2;
    for (const m of page.matchAll(/<a [^>]*href="(\/[^"#]*)"/g)) assert.notEqual((await c.get(m[1].replace(/&amp;/g, '&'))).status, 404, `${p} → ${m[1]}`);
  }
});

test('1. формат ключа посетителя совпадает с каталогом', () => {
  const demo = loadCatalog(path.join(root, 'providers.yaml'), { demo: true }).get('demo');
  assert.equal(String(demo.keyPattern.source ?? demo.keyPattern), DEMO_KEY_PATTERN.source);
});

test('1. изоляция: sys/smtp, sys/slack_webhook, sys/tg_bot в сейфе → отказ без значений', async () => {
  for (const name of ['sys/smtp', 'sys/slack_webhook', 'sys/tg_bot']) {
    const value = 'v-' + crypto.randomBytes(6).toString('hex');
    const { run } = await isolation(async ({ vault }) => { await vault.put(name, value); });
    await assert.rejects(run, (e) => { assert.match(e.message, /^demo_isolation: vault_channel_secret$/); assert.ok(!e.message.includes(value)); return true; }, name);
  }
  const ok = await isolation(async ({ vault }) => { await vault.put('sys/signing', 'a'.repeat(64)); await vault.put('cred/demo', 'demo-public01'); });
  await ok.run(); // sys/* и cred/demo разрешены
});

test('1. изоляция: GW_VAULT=ssm, AWS_*, чужой публичный адрес, каталог не задан явно → отказ', async () => {
  await assert.rejects((await isolation(() => {}, { vault: 'ssm' })).run, /demo_isolation: vault_not_file/);
  await assert.rejects((await isolation(() => {}, {}, { AWS_REGION: 'eu-west-1' })).run, /demo_isolation: cloud_env/);
  await assert.rejects((await isolation(() => {}, {}, { GW_SSM_REGION: 'x' })).run, /demo_isolation: cloud_env/);
  await assert.rejects((await isolation(() => {}, {}, { GW_VAULT_PREFIX: '/gateway' })).run, /demo_isolation: cloud_env/);
  await assert.rejects((await isolation(() => {}, { prodHosts: ['gw.prod.example'], publicUrl: 'https://gw.prod.example' })).run, /demo_isolation: public_url_is_prod/);
  await assert.rejects((await isolation(() => {}, { dataDirExplicit: false })).run, /demo_isolation: data_dir_not_explicit/);
});

test('1. изоляция: непустой каталог без маркера → отказ; с маркером проходит', async () => {
  const stray = await isolation(({ dataDir }) => fs.writeFileSync(path.join(dataDir, 'notes.txt'), 'x'));
  await assert.rejects(stray.run, /demo_isolation: data_dir_not_empty/);
  assert.ok(!fs.existsSync(path.join(stray.ctx.dataDir, DEMO_MARKER)), 'маркер при отказе не создаётся');
  const marked = await isolation(({ dataDir }) => { fs.writeFileSync(path.join(dataDir, 'notes.txt'), 'x'); fs.writeFileSync(path.join(dataDir, DEMO_MARKER), 'demo\n'); });
  await marked.run();
  // предпроверка buildApp: до создания файлов шлюзом
  const pre = tmpDir('gw-pre-');
  assertDemoDataDirFresh(pre);
  fs.writeFileSync(path.join(pre, 'x'), '1');
  assert.throws(() => assertDemoDataDirFresh(pre), /data_dir_not_empty/);
  fs.writeFileSync(path.join(pre, DEMO_MARKER), 'demo\n');
  assertDemoDataDirFresh(pre);
});

test('1. изоляция: Telegram владельца, настройки каналов, пароль владельца → отказ', async () => {
  const tg = await isolation(({ repo }) => repo.setTg(12345, 'sys/tg_bot'));
  await assert.rejects(tg.run, /demo_isolation: db_owner_telegram$/);
  const ch = await isolation(({ repo }) => repo.setMeta('notify.slack', '{"enabled":true}'));
  await assert.rejects(ch.run, /demo_isolation: db_notify_settings$/);
  const pw = await isolation(({ repo }) => repo.setPasswordHash('$argon2id$x'));
  await assert.rejects(pw.run, /demo_isolation: db_owner_password$/);
});

test('1. buildApp в демо отказывается стартовать при чужом ключе и закрывает базу', async () => {
  const dataDir = tmpDir('gw-bad-');
  const cfg = demoCfg(dataDir);
  fs.writeFileSync(path.join(dataDir, DEMO_MARKER), 'demo\n');
  const vault = createVault(cfg);
  await vault.put('cred/real', 'x');
  await assert.rejects(buildApp({ ...paths(dataDir), demo: true, dataDirExplicit: true, prodHosts: [], env: {}, lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' }), /demo_isolation: vault_foreign_name cred\/real/);
});

// ---- 2. сеть ----

test('2. сетевой guard (дочерний процесс): connect, fetch, undici, dns, loopback → demo_network_disabled; listen работает; мок без Socket.connect', async () => {
  const u = (p) => pathToFileURL(path.join(root, p)).href;
  const script = `
import net from 'node:net';
import dns from 'node:dns';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { request } from 'undici';
const { installNetworkGuard } = await import(${JSON.stringify(u('src/demo/guard.js'))});
const guard = installNetworkGuard();
const out = {};
const code = (e) => e?.code ?? e?.cause?.code ?? e?.message ?? 'none';
const tryConnect = (port, host) => new Promise((res) => { const s = net.connect(port, host); s.on('error', (e) => res(code(e))); s.on('connect', () => { s.destroy(); res('connected'); }); });
out.connect = await tryConnect(443, '1.1.1.1');
out.fetch = await fetch('https://example.com').then(() => 'ok', code);
out.undici = await request('https://example.com').then(() => 'ok', code);
out.dns = await dns.promises.lookup('example.com').then(() => 'ok', code);
const srv = net.createServer((s) => s.end());
await new Promise((r) => srv.listen(0, '127.0.0.1', r));
out.listening = srv.listening;
out.loopback = await tryConnect(srv.address().port, '127.0.0.1');
srv.close();
out.again = installNetworkGuard() === guard;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-child-'));
const { buildApp } = await import(${JSON.stringify(u('src/app.js'))});
const app = await buildApp({ dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'),
  demo: true, dataDirExplicit: true, prodHosts: [], env: {}, lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
await app.start();
out.appListening = app.fastify.server.listening;
const token = 'gwa_' + crypto.randomBytes(24).toString('base64url');
app.repo.createAgent({ id: 'a1', name: 'a1', token_hash: crypto.createHash('sha256').update(token).digest('hex'), enabled: 1, all_credentials: 1 });
app.repo.updateCredentialPolicy('demo', { mode: 'always', always_until: null });
const before = guard.attempts();
const g = await app.fastify.inject({ method: 'POST', url: '/v1/grants', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, payload: { provider: 'demo', ttl: 600, calls: 5, reason: 'x' } });
const p = await app.fastify.inject({ method: 'GET', url: '/v1/proxy/demo/ping', headers: { authorization: 'Bearer ' + g.json().token } });
out.grantStatus = g.statusCode; out.proxyStatus = p.statusCode; out.proxyBody = p.body;
out.attemptsDuringProxy = guard.attempts() - before;
await app.stop();
fs.rmSync(dir, { recursive: true, force: true });
console.log('RESULT ' + JSON.stringify(out));
process.exit(0);
`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: root, encoding: 'utf8', timeout: 90_000, env: { ...process.env, NODE_NO_WARNINGS: '1' } });
  const line = r.stdout.split('\n').find((l) => l.startsWith('RESULT '));
  assert.ok(line, `дочерний процесс не вернул результат: ${r.stderr.slice(0, 800)}`);
  const out = JSON.parse(line.slice(7));
  assert.equal(out.connect, 'demo_network_disabled', 'net.connect(443, 1.1.1.1)');
  assert.equal(out.fetch, 'demo_network_disabled', 'fetch');
  assert.equal(out.undici, 'demo_network_disabled', 'undici.request');
  assert.equal(out.dns, 'demo_network_disabled', 'dns.lookup');
  assert.equal(out.loopback, 'demo_network_disabled', 'loopback тоже закрыт');
  assert.equal(out.listening, true, 'входящий listen не затронут');
  assert.equal(out.appListening, true);
  assert.equal(out.again, true, 'повторная установка идемпотентна');
  assert.equal(out.grantStatus, 200);
  assert.equal(out.proxyStatus, 200);
  assert.equal(JSON.parse(out.proxyBody).ok, true, 'ответ из мока');
  assert.equal(out.attemptsDuringProxy, 0, 'ни одного вызова Socket.connect при вызове через прокси');
});

test('2. транспорт: demo.invalid обслуживает мок, любой другой хост → demo_network_disabled', async () => {
  const tr = createDemoTransport();
  const ok = await tr('https://demo.invalid/ping', { method: 'GET', headers: { 'x-demo-key': DEMO_KEY } });
  assert.equal(ok.statusCode, 200);
  assert.equal(JSON.parse(await ok.body.text?.() ?? Buffer.concat(await ok.body.toArray()).toString()).ok, true);
  const noKey = await tr('https://demo.invalid/ping', { method: 'GET', headers: {} });
  assert.equal(noKey.statusCode, 401);
  await assert.rejects(tr('https://example.com/x', {}), { code: 'demo_network_disabled' });
  await assert.rejects(tr('http://127.0.0.1:9/x', {}), { code: 'demo_network_disabled' });
  // мок вычитывает тело и сам режет его по размеру
  const m = createDemoMock();
  const r = await m.handle({ method: 'POST', path: '/deals', headers: { 'x-demo-key': DEMO_KEY }, body: Buffer.from('x') });
  assert.equal(r.status, 201);
});

test('2. прокси в демо: вызов идёт в мок, ключ в ответ не попадает, фильтр полей и методов работает', async () => {
  const c = await boot();
  const agent = mkAgent(c.app);
  const token = await grantFor(c, agent);
  const ping = await c.api('GET', '/v1/proxy/demo/ping', { token });
  assert.equal(ping.status, 200);
  assert.ok(!(await ping.text()).includes(DEMO_KEY), 'ключ не возвращается');
  // без фильтра видны все поля
  const all = await (await c.api('GET', '/v1/proxy/demo/deals', { token })).json();
  assert.ok('COMMENTS' in all.result[0]);
  c.app.repo.updateCredentialFilter('demo', { enabled: true, entities: { deals: ['result.ID', 'result.TITLE'] }, methods: [], fields: [] });
  const f = await (await c.api('GET', '/v1/proxy/demo/deals', { token })).json();
  assert.deepEqual(Object.keys(f.result[0]).sort(), ['ID', 'TITLE']);
  assert.equal(f.total, 4);
  const denied = await c.api('GET', '/v1/proxy/demo/contacts', { token });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error, 'method_not_allowed');
  const audit = c.app.repo.listAudit({ limit: 50 }).filter((r) => r.action === 'proxy.call');
  assert.ok(audit.length >= 3);
});

// ---- 3. allowlist ----

test('3. allowlist: закрытые маршруты → 404, разрешённые работают, /login = автовход, noindex и баннер', async () => {
  const c = await boot();
  c.app.repo.createCredential({ id: 'foreign1', provider: 'openai', label: 'x', kind: 'static', host: 'api.openai.com', injection: { type: 'header', name: 'authorization' }, vault_param: 'cred/foreign1', last4: '1234' });
  // без сессии корень ведёт на /login, /login выдаёт сессию без пароля
  assert.equal((await c.get('/')).headers.get('location'), '/login');
  const lg = await c.get('/login');
  assert.equal(lg.status, 302); assert.equal(lg.headers.get('location'), '/');
  assert.equal(c.app.repo.listSessions().length, 1);
  assert.equal(c.app.repo.listSessions()[0].totp_ok, 1, 'сессия сразу полная: ни пароля, ни 2FA');
  const home = await c.get('/');
  assert.equal(home.status, 200);
  assert.ok(home.text2.includes(BANNER), 'баннер на каждой странице');
  assert.equal(home.headers.get('x-robots-tag'), 'noindex');
  assert.match(home.text2, /Simulate agent request/);
  assert.doesNotMatch(home.text2, /href="\/settings"/, 'ссылки на настройки в демо нет');
  for (const p of ['/keys/demo', '/agents', '/stats', '/audit', '/keys/new', '/keys/new/demo']) assert.equal((await c.get(p)).status, 200, p);
  assert.equal((await c.get('/healthz')).status, 200);
  assert.equal((await c.get('/public/style.css')).status, 200);
  assert.equal((await c.get('/public/favicon.svg')).status, 200);
  // закрыто целиком
  for (const p of ['/settings', '/settings/password', '/settings/notify/slack', '/setup', '/setup/x', '/l/x', '/totp', '/welcome', '/pending/x', '/keys/new/openai', '/robots.txt', '/v1/proxy/openai/x']) {
    const r = await c.get(p);
    assert.equal(r.status, 404, `GET ${p}`);
    assert.equal(r.headers.get('x-robots-tag'), 'noindex');
  }
  for (const p of ['/keys/demo/delete', '/keys/demo/replace', '/keys/new/openai', '/settings/password', '/settings/revoke-all', '/settings/sessions/revoke', '/logout', '/totp', '/setup', '/login', '/agents/demo-agent/delete', '/agents/demo-agent/disable', '/keys/foreign1/policy', '/keys/foreign1/filter']) {
    assert.equal((await c.post(p, { label: 'x' })).status, 404, `POST ${p}`);
  }
  // политика ключа демо открыта, чужого — нет; ключ не удалился
  assert.equal((await c.post('/keys/demo/policy', { label: 'My demo', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '10', max_parallel: '2' })).status, 302);
  assert.equal(c.app.repo.getCredential('demo').label, 'My demo');
  assert.ok(c.app.repo.getCredential('demo'));
  // REST: чужой провайдер недоступен
  assert.equal((await c.api('GET', '/v1/proxy/openai/x', { token: 'gwt_x' })).status, 404);
  assert.equal((await c.api('POST', '/v1/grants', { token: 'gwa_x', body: { provider: 'openai' } })).status, 401);
  const err404 = await c.api('GET', '/v1/other');
  assert.equal(err404.status, 404);
  assert.deepEqual(await err404.json(), { error: 'not_found' });
});

test('3. демо-владелец: действия со «свежим кодом» проходят без 2FA (агент создаётся сразу)', async () => {
  const c = await boot();
  await c.login();
  const r = await c.post('/agents', { name: 'visitor-agent', keys_all: '1' });
  assert.equal(r.status, 200, 'страница с токеном, а не переход на /totp');
  assert.match(r.text2, /gwa_/);
  assert.ok(c.app.repo.listAgents().some((a) => a.name === 'visitor-agent'));
});

// ---- 4. MCP ----

test('4. MCP в демо: list_services только demo, call с service:github → unknown_service, demo через мок работает', async () => {
  const c = await boot();
  const agent = mkAgent(c.app);
  c.app.repo.updateCredentialPolicy('demo', { mode: 'always', always_until: null });
  const transport = new StreamableHTTPClientTransport(new URL(`${c.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${agent.token}`, 'x-forwarded-for': c.ip } } });
  const client = new Client({ name: 'demo-test', version: '1.0' });
  await client.connect(transport);
  cleanup.push(() => client.close());
  const tool = async (name, args) => { const r = await client.callTool({ name, arguments: args }); return { isError: !!r.isError, data: JSON.parse(r.content[0].text) }; };
  const ls = await tool('list_services', {});
  assert.deepEqual(ls.data.services.map((s) => s.slug), ['demo']);
  const gh = await tool('call', { service: 'github', method: 'GET', path: '/user' });
  assert.deepEqual([gh.isError, gh.data.error], [true, 'unknown_service']);
  assert.equal((await tool('request_access', { service: 'github', reason: 'x' })).isError, true);
  const acc = await tool('request_access', { service: 'demo', reason: 'demo' });
  assert.equal(acc.data.status, 'approved');
  const ping = await tool('call', { service: 'demo', method: 'GET', path: '/ping' });
  assert.equal(ping.isError, false);
  assert.equal(ping.data.status, 200);
  assert.equal(JSON.parse(ping.data.body).ok, true);
});

// ---- 5. лимиты ----

test('5. лимиты: 7-й simulate за минуту → 429, шестой агент и четвёртый ключ → отказ, длинные поля → 400', async () => {
  const c = await boot();
  await c.login();
  for (let i = 1; i <= 6; i++) assert.equal((await c.post('/demo/simulate')).status, 302, `simulate ${i}`);
  assert.equal((await c.post('/demo/simulate')).status, 429);
  // другой IP не задет
  const other = await boot();
  await other.login();
  assert.equal((await other.post('/demo/simulate')).status, 302);
  // заявки созданы настоящим requests.submit
  // потолок Н-6: на пару агент+ключ не больше 3 ожидающих, остальные simulate получают too_many_pending
  assert.equal(c.app.repo.listPending().length, 3);
  assert.equal(c.app.repo.listPending()[0].agent_id, 'demo-agent');

  // агенты: демо-агент уже есть, до пяти ещё четыре; шестой отклоняется
  for (let i = 1; i <= 4; i++) assert.equal((await c.post('/agents', { name: `a${i}`, keys_all: '1' })).status, 200, `agent ${i}`);
  assert.equal(c.app.repo.listAgents().length, 5);
  assert.equal((await c.post('/agents', { name: 'a5', keys_all: '1' })).status, 403);
  assert.equal(c.app.repo.listAgents().length, 5);
  assert.equal((await other.post('/agents', { name: 'x'.repeat(41), keys_all: '1' })).status, 400, 'имя до 40 символов');

  // ключи: не больше трёх
  const key = (n) => ({ key: `demo-${n}abcdefgh`, label: `k${n}`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '5', max_parallel: '1' });
  await other.get('/keys/new/demo');
  assert.equal((await other.post('/keys/new/demo', key(1))).status, 302);
  assert.equal((await other.post('/keys/new/demo', key(2))).status, 302);
  assert.equal(other.app.repo.listCredentials().length, 3);
  assert.equal((await other.post('/keys/new/demo', key(3))).status, 403);
  assert.equal((await other.post('/keys/new/demo', { ...key(4), label: 'L'.repeat(41) })).status, 403);
  // подтверждение «кодом» в демо недоступно (кода нет)
  assert.equal((await c.post('/keys/demo/policy', { label: 'x', mode: 'ask', approval: 'web_code', max_ttl: '3600', max_calls: '5', max_parallel: '1' })).status, 400);
  assert.equal((await c.post('/keys/demo/policy', { label: 'L'.repeat(41), mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '5', max_parallel: '1' })).status, 400);
});

test('5. лимиты по IP: заявки 10/мин, API 60/мин; тело больше 64 KiB → 413; IP берётся из X-Forwarded-For доверенного прокси', async () => {
  const c = await boot();
  for (let i = 1; i <= 10; i++) assert.equal((await c.api('POST', '/v1/grants', { token: 'gwa_none', body: {} })).status, 401, `grants ${i}`);
  const limited = await c.api('POST', '/v1/grants', { token: 'gwa_none', body: {} });
  assert.equal(limited.status, 429);
  assert.deepEqual(await limited.json(), { error: 'rate_limited' });
  assert.equal((await c.api('POST', '/v1/grants', { token: 'gwa_none', body: {}, ip: '10.200.0.1' })).status, 401, 'другой IP не задет');
  // API: 60 в минуту
  const ip = '10.200.0.2';
  for (let i = 0; i < 60; i++) assert.equal((await c.api('GET', '/v1/grants/x', { token: 'gwa_none', ip })).status, 401);
  assert.equal((await c.api('GET', '/v1/grants/x', { token: 'gwa_none', ip })).status, 429);
  // тело
  const big = await fetch(`${c.base}/v1/grants`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '10.200.0.3' }, body: JSON.stringify({ pad: 'x'.repeat(70_000) }) });
  assert.equal(big.status, 413);
});

// ---- 6. сброс ----

test('6. сброс: runOnce очищает audit, сессии, лишних агентов; сид на месте; во время сброса 503; изоляция проходит повторно', async () => {
  const c = await boot();
  const { app } = c;
  await c.login();
  await c.post('/agents', { name: 'extra', keys_all: '1' });
  await c.post('/demo/simulate');
  const agent = mkAgent(app);
  await grantFor(c, agent);
  assert.ok(app.repo.listAudit().length > 0);
  assert.ok(app.repo.listAgents().length >= 3);
  assert.equal(app.repo.listActiveGrants().length, 1);
  const count = (tbl) => app.db.prepare(`SELECT count(*) AS n FROM ${tbl}`).get().n;
  assert.ok(count('sessions') >= 1 && count('requests') >= 2);

  // во время сброса: 503 demo_resetting на сайте и в API, /healthz отвечает
  let release;
  const hold = new Promise((r) => { release = r; });
  const running = app.demoReset.runOnce({ hold });
  assert.equal(app.demoReset.resetting, true);
  const site = await c.get('/');
  assert.equal(site.status, 503);
  assert.equal(site.headers.get('retry-after'), '2');
  const api = await c.api('GET', '/v1/grants/x', { token: 'gwa_none' });
  assert.equal(api.status, 503);
  assert.deepEqual(await api.json(), { error: 'demo_resetting' });
  assert.equal((await c.get('/healthz')).status, 200);
  release();
  await running;
  assert.equal(app.demoReset.resetting, false);

  for (const tbl of ['audit', 'sessions', 'requests', 'grants', 'leases', 'pending_actions', 'totp_used', 'one_time_links', 'backup_codes']) assert.equal(count(tbl), 0, tbl);
  assert.deepEqual(app.repo.listAgents().map((a) => a.id), ['demo-agent']);
  assert.deepEqual(app.repo.listCredentials().map((x) => [x.id, x.provider]), [['demo', 'demo']]);
  const owner = app.repo.getOwner();
  assert.equal(owner.setup_done, 1); assert.equal(owner.password_hash, null); assert.equal(owner.tg_chat_id, null);
  assert.ok(app.repo.demoResetAge() <= 2, 'meta.demo_reset_at выставлен');
  assert.equal(await app.ctx.vault.get('cred/demo'), DEMO_KEY);
  assert.ok(await app.ctx.vault.get('sys/signing'), 'sys/* сейфа сохранены');
  assert.deepEqual((await app.ctx.vault.names()).filter((n) => n.startsWith('cred/')), ['cred/demo']);
  // старая сессия посетителя недействительна: корень снова ведёт на /login, автовход работает
  assert.equal((await c.get('/')).headers.get('location'), '/login');
  assert.equal((await c.get('/login')).headers.get('location'), '/');
  assert.equal((await c.get('/')).status, 200);
  // повторная проверка изоляции после сброса
  await assertDemoIsolation({ cfg: app.ctx.config, db: app.db, vault: app.ctx.vault, env: {} });
});

test('6. demoWipe существует только в демо-репозитории', async () => {
  const db = openDb(':memory:');
  assert.equal(createRepo(db).demoWipe, undefined);
  assert.equal(typeof createRepo(db, { demo: true }).demoWipe, 'function');
  db.close();
});

// ---- 7. фоновые циклы, каталог, лист ожидания ----

test('7. фоновые циклы: tg.current() === null, каналов уведомлений нет; настройки каналов не создаются', async () => {
  const c = await boot();
  assert.equal(c.app.ctx.tg.current(), null);
  assert.equal(c.app.ctx.notify.channels.length, 0);
  // заявка не пытается никуда писать
  await c.login();
  await c.post('/demo/simulate');
  await c.app.ctx.notify.idle();
  assert.equal(c.app.repo.getMeta('notify.slack'), null);
  assert.deepEqual(await c.app.ctx.vault.names().then((n) => n.filter((x) => x.startsWith('sys/tg') || x === 'sys/smtp' || x === 'sys/slack_webhook')), []);
});

test('каталог: в демо только demo, вне демо demo скрыт', () => {
  const file = path.join(root, 'providers.yaml');
  const demo = loadCatalog(file, { demo: true });
  assert.deepEqual(demo.list().map((p) => p.slug), ['demo']);
  assert.equal(demo.get('demo').host, 'demo.invalid');
  assert.deepEqual(Object.keys(demo.get('demo').filter.entities), ['deals', 'contacts']);
  assert.equal(demo.get('github'), undefined);
  const normal = loadCatalog(file);
  assert.equal(normal.get('demo'), undefined);
  assert.ok(normal.get('github'));
});

test('баннер: ссылка на лист ожидания только при заданном адресе', async () => {
  const withUrl = await boot({ waitlistUrl: 'https://example.org/w' });
  const page = await withUrl.get('/login').then(() => withUrl.get('/'));
  assert.ok(page.text2.includes(BANNER));
  assert.match(page.text2, /class="demo-banner"[^>]*>[^<]*<a class="waitlist" href="https:\/\/example\.org\/w"/);
  assert.doesNotMatch(page.text2, /<script(?![^>]*\ssrc="\/public\/)/i);
  const without = await boot();
  const p2 = await without.get('/login').then(() => without.get('/'));
  assert.ok(p2.text2.includes(BANNER));
  assert.doesNotMatch(p2.text2, /class="waitlist"/);
});

test('5. лимиты создания агентов и ключей считаются на посетителя (IP), а не на всех (ревью 9.1)', async () => {
  const c = await boot();
  await c.login();
  const key = (n) => ({ key: `demo-${n}abcdefgh`, label: `k${n}`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '5', max_parallel: '1' });
  await c.get('/keys/new/demo');
  const ipA = c.ip;
  // посетитель A исчерпывает свои лимиты: 4 агента и 2 ключа
  for (let i = 1; i <= 4; i++) assert.equal((await c.post('/agents', { name: `a${i}`, keys_all: '1' })).status, 200, `A agent ${i}`);
  assert.equal((await c.post('/agents', { name: 'a5', keys_all: '1' })).status, 403);
  assert.equal((await c.post('/keys/new/demo', key(1))).status, 302);
  assert.equal((await c.post('/keys/new/demo', key(2))).status, 302);
  assert.equal((await c.post('/keys/new/demo', key(3))).status, 403);
  // посетитель B (другой IP, та же демо-сессия владельца) создаёт свои
  c.ip = '10.77.1.1';
  assert.notEqual(c.ip, ipA);
  assert.equal((await c.post('/agents', { name: 'b1', keys_all: '1' })).status, 200, 'B не упёрся в лимит A');
  assert.equal((await c.post('/keys/new/demo', key(4))).status, 302, 'B создаёт ключ');
  // A по-прежнему упирается в свои лимиты
  c.ip = ipA;
  assert.equal((await c.post('/agents', { name: 'a6', keys_all: '1' })).status, 403);
  // общий потолок в базе защищает от разрастания: 30 ключей на всех, 50 агентов на всех
  assert.equal(c.app.repo.listAgents().length, 6);
});

test('5. лимиты демо (ревью M4): 12 адресов одной IPv6 /64 — один посетитель; общий лимит частоты создания на весь демо', async () => {
  const c = await boot();
  await c.login();
  // 12 адресов одной /64: упираемся в лимит одного посетителя (демо-агент + 4 новых), а не получаем 12 агентов
  const statuses = [];
  for (let i = 0; i < 12; i++) {
    c.ip = `2001:db8:1:1::${(i + 1).toString(16)}`;
    statuses.push((await c.post('/agents', { name: `v6-${i}`, keys_all: '1' })).status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 200, ...Array(8).fill(403)]);
  assert.equal(c.app.repo.listAgents().length, 5);
  // другая /64 — другой посетитель
  c.ip = '2001:db8:2:2::1';
  assert.equal((await c.post('/agents', { name: 'other-net', keys_all: '1' })).status, 200);

  // общий лимит: 20 успешных созданий за 10 минут на весь демо (уже создано 5), дальше 403 для любых адресов
  const ok = [];
  for (let i = 0; i < 20; i++) {
    c.ip = `10.50.${i}.1`;
    ok.push((await c.post('/agents', { name: `g${i}`, keys_all: '1' })).status);
  }
  assert.equal(ok.filter((s) => s === 200).length, 15, '20 в окне минус уже созданные 5');
  assert.equal(ok.filter((s) => s === 403).length, 5);
  assert.equal(c.app.repo.listAgents().length, 21, 'демо-агент + 20 созданных');
});
