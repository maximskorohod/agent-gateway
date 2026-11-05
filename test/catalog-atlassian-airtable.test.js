// Каталог 1.0: Atlassian (Jira и Confluence Cloud, HTTP Basic email:token) и Airtable (Bearer pat…).
// Без сети: сейф — файл, сервис — mock на localhost. Секреты генерируются в рантайме.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadCatalog, buildInjection, validateKeyFormat } from '../src/catalog.js';
import { compileFilter } from '../src/core/filter.js';
import { initI18n, t } from '../src/i18n.js';
import { buildApp } from '../src/app.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = loadCatalog(path.join(root, 'providers.yaml'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-atl-'));
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const TOKEN = `tok${crypto.randomBytes(12).toString('hex')}`;
const PAT = `pat${crypto.randomBytes(7).toString('hex')}.${crypto.randomBytes(32).toString('hex')}`;
const EMAIL = 'agent@acme.example';

test('Atlassian и Airtable загружаются, у обоих нет фильтра данных, readOnly включён по умолчанию', () => {
  for (const slug of ['atlassian', 'airtable']) {
    const p = catalog.get(slug);
    assert.ok(p, slug);
    assert.equal(p.filter, undefined, `${slug}: фильтра данных нет`);
    assert.equal(p.readOnly.default, true, `${slug}: readOnly по умолчанию`);
    assert.ok(fs.existsSync(path.join(root, 'assets', 'icons', `${slug}.svg`)), `${slug}: иконка`);
    assert.match(p.getKeyUrl, /^https:\/\//);
  }
  assert.equal(catalog.get('atlassian').getKeyUrl, 'https://id.atlassian.com/manage-profile/security/api-tokens');
  assert.equal(catalog.get('airtable').getKeyUrl, 'https://airtable.com/create/tokens');
  assert.equal(catalog.get('airtable').host, 'api.airtable.com');
});

test('Atlassian: хост только из шаблона, секрет email:токен, чужие адреса отклонены', () => {
  const a = catalog.get('atlassian');
  const b = buildInjection(a, { account: 'acme', email: EMAIL, key: TOKEN });
  assert.equal(b.host, 'acme.atlassian.net');
  assert.equal(b.secret, `${EMAIL}:${TOKEN}`);
  assert.equal(b.injection.encode, 'base64');
  assert.equal(buildInjection(a, { account: 'ACME.atlassian.net', email: EMAIL, key: TOKEN }).host, 'acme.atlassian.net');
  const bad = ['acme.evil.com', 'evil.com', 'acme.atlassian.net.evil.com', 'a.b', 'acme/x', 'acme@evil.com', 'https://evil.com/', 'http://acme.atlassian.net', '127.0.0.1', 'a b', 'acme.'];
  for (const account of bad) {
    assert.throws(() => buildInjection(a, { account, email: EMAIL, key: TOKEN }), undefined, account);
  }
  for (const email of ['', 'no-at', 'a:b@c.example']) {
    assert.throws(() => buildInjection(a, { account: 'acme', email, key: TOKEN }), undefined, email);
  }
  assert.ok(catalog.secretForms(a, b.secret).includes(TOKEN));
});

test('Airtable: формат personal access token', () => {
  const p = catalog.get('airtable');
  assert.equal(validateKeyFormat(p, PAT), null);
  assert.equal(typeof validateKeyFormat(p, 'keyAbc123'), 'string');
  assert.equal(typeof validateKeyFormat(p, 'sk-abcdefghijklmnop'), 'string');
});

test('Zendesk: подсказка про токены есть в словарях en и ru', () => {
  assert.match(t('catalog.getkey.zendesk'), /27 Oct 2026/);
  assert.match(catalog.get('zendesk').getKeyHint, /27 Oct 2026/);
});

test('Atlassian readOnly: GET проходит, запись режется, POST поиска JQL проходит', () => {
  const a = catalog.get('atlassian');
  const f = compileFilter({ enabled: false, readOnly: true, entities: {}, methods: [], fields: [] }, a);
  assert.equal(f.denyReason('GET', '/rest/api/3/issue/PRJ-1'), null);
  assert.equal(f.denyReason('GET', '/wiki/api/v2/pages'), null);
  assert.equal(f.denyReason('POST', '/rest/api/3/search/jql'), null);
  assert.equal(f.denyReason('POST', '/rest/api/3/issue'), 'write_not_allowed');
  assert.equal(f.denyReason('PUT', '/rest/api/3/issue/PRJ-1'), 'write_not_allowed');
  assert.equal(f.denyReason('DELETE', '/wiki/api/v2/pages/1'), 'write_not_allowed');
  assert.equal(f.denyReason('POST', '/wiki/api/v2/pages'), 'write_not_allowed');
  const g = compileFilter({ enabled: false, readOnly: true, entities: {}, methods: [], fields: [] }, catalog.get('airtable'));
  assert.equal(g.denyReason('GET', '/v0/meta/bases'), null);
  assert.equal(g.denyReason('POST', '/v0/appX/tblY'), 'write_not_allowed');
});

// ---- сквозной вызов через прокси на mock-upstream
let app, mock, appBase;
const seen = [];
before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.setHeader('content-type', 'application/json');
    res.end('{"ok":true}');
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const up = `http://127.0.0.1:${mock.address().port}`;
  const dataDir = fs.mkdtempSync(path.join(tmp, 'app-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { 'acme.atlassian.net': up, 'api.airtable.com': up },
  });
  await app.start();
  appBase = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
after(async () => {
  await app?.stop();
  mock?.closeAllConnections?.();
  mock?.close();
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* не мешаем итогу тестов */ }
});

async function callThrough(slug, input, urlPath) {
  const provider = app.ctx.catalog.get(slug);
  const built = buildInjection(provider, input);
  const id = crypto.randomBytes(6).toString('hex');
  await app.ctx.vault.put(`cred/${id}`, built.secret);
  app.repo.createCredential({ id, provider: slug, label: slug, kind: built.kind, host: built.host, injection: built.injection, vault_param: `cred/${id}`, last4: built.last4 });
  app.repo.createAgent({ id: `ag${id}`, name: 'test', token_hash: crypto.randomBytes(16).toString('hex') });
  const req = { id: `rq${id}`, agent_id: `ag${id}`, credential_id: id, ttl: 600, calls: 5, reason: '', expires_at: Math.floor(Date.now() / 1000) + 600 };
  app.repo.createRequest(req);
  const { token } = app.ctx.grants.issue(req, app.repo.getCredential(id));
  return fetch(`${appBase}/v1/proxy/${slug}${urlPath}`, { headers: { authorization: `Bearer ${token}` } });
}

test('прокси: Atlassian ставит Basic base64(email:токен) на хост сайта', async () => {
  const res = await callThrough('atlassian', { account: 'acme', email: EMAIL, key: TOKEN }, '/rest/api/3/myself');
  assert.equal(res.status, 200);
  assert.equal(seen.at(-1).url, '/rest/api/3/myself');
  assert.equal(seen.at(-1).headers.authorization, `Basic ${b64(`${EMAIL}:${TOKEN}`)}`);
});

test('прокси: Airtable ставит Bearer', async () => {
  const res = await callThrough('airtable', { key: PAT }, '/v0/meta/bases');
  assert.equal(res.status, 200);
  assert.equal(seen.at(-1).headers.authorization, `Bearer ${PAT}`);
});
