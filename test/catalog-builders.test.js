// Тесты builder'ов каталога (контракт rest-demo-notify.md → «Каталог (П-23, П-24)»). Без сети и AWS:
// сейф — файл, сервис — mock на localhost. Значения секретов явно фейковые.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadCatalog, buildInjection } from '../src/catalog.js';
import { initI18n, t } from '../src/i18n.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { buildApp } from '../src/app.js';
import * as V from '../src/web/views/index.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = loadCatalog(path.join(root, 'providers.yaml'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-builders-'));

const SID = `AC${'a1'.repeat(16)}`; // фейковый Account SID: AC + 32 hex
const TOKEN = 'fake/tok+en=12345'; // фейковый токен со спецсимволами для проверки URL-формы
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

/** Загружает временный каталог из текста yaml; возвращает сообщение ошибки или null. */
function loadError(yaml) {
  const file = path.join(tmp, `c-${crypto.randomBytes(4).toString('hex')}.yaml`);
  fs.writeFileSync(file, yaml);
  try { loadCatalog(file); return null; } catch (e) { return e.message; }
}
const base = 'defaults:\n  maxBody: 1000\n  timeout: 10\n  kind: static\n  fields: [key]\nproviders:\n';

// ---- 1. Инвариант фиксированного хоста
test('фиксированный host не меняется при любом вводе владельца', () => {
  const evil = { account: 'evil.com', host: 'evil.com', webhook_url: 'https://evil.com/rest/1/a/', header: 'x-evil', email: 'a@evil.com', key: 'fake-key-value-1234' };
  let checked = 0;
  for (const p of catalog.list()) {
    if (p.host === 'owner') continue;
    checked++;
    let built = null;
    try { built = buildInjection(p, evil); } catch { /* ошибка тоже безопасна */ }
    if (built) assert.equal(built.host, p.host, p.slug);
    // с корректным account (Twilio) хост тоже остаётся каталожным
    try { built = buildInjection(p, { ...evil, account: SID }); } catch { built = null; }
    if (built) assert.equal(built.host, p.host, p.slug);
  }
  assert.ok(checked >= 15);
  assert.throws(() => buildInjection(catalog.get('twilio'), { ...evil, key: TOKEN }));
});

test('Pipedrive: фиксированный хост и заголовок x-api-token', () => {
  const p = catalog.get('pipedrive');
  assert.equal(p.host, 'api.pipedrive.com');
  assert.deepEqual(p.injection, { type: 'header', name: 'x-api-token' });
  const b = buildInjection(p, { key: 'fake-pipedrive-token', account: 'evil.com' });
  assert.equal(b.host, 'api.pipedrive.com');
  assert.ok(catalog.redactHeaders().includes('x-api-token'));
});

// ---- 2. Twilio
test('Twilio: Account SID + токен → Basic base64(SID:токен), формат SID проверяется', () => {
  const tw = catalog.get('twilio');
  assert.equal(tw.builder, 'basic');
  const b = buildInjection(tw, { account: SID, key: TOKEN });
  assert.equal(b.host, 'api.twilio.com');
  assert.deepEqual(b.injection, { type: 'header', name: 'authorization', prefix: 'Basic ', encode: 'base64' });
  assert.equal(b.secret, `${SID}:${TOKEN}`);
  assert.equal(b.last4, TOKEN.slice(-4));
  for (const bad of ['', 'evil.com', 'AC123', `AC${'A'.repeat(32)}`, `${SID}:x`, ` ${SID}x`]) {
    assert.throws(() => buildInjection(tw, { account: bad, key: TOKEN }), undefined, bad);
  }
  const forms = catalog.secretForms(tw, b.secret);
  assert.ok(forms.includes(b64(b.secret)), 'base64-форма секрета');
  assert.ok(forms.includes(TOKEN) && forms.includes(encodeURIComponent(TOKEN)), 'ключ отдельно, сырой и URL-кодированный');
  assert.ok(forms.includes(b.secret) && forms.includes(encodeURIComponent(b.secret)));
  // длинные формы идут первыми
  assert.deepEqual(forms, [...forms].sort((a, c) => c.length - a.length));
});

test('secretForms: обычный секрет — сырая, URL и base64; короткие значения не попадают', () => {
  const p = catalog.get('openai');
  const s = 'fake key/with+chars=1'.replace(' ', '-');
  assert.deepEqual(new Set(catalog.secretForms(p, s)), new Set([s, encodeURIComponent(s), b64(s)]));
  assert.deepEqual(catalog.secretForms(p, ''), []);
  assert.deepEqual(catalog.secretForms(p, 'abc'), [b64('abc')].filter((x) => x.length >= 4));
});

// ---- 3. Zendesk
test('Zendesk: поддомен → хост по шаблону, секрет email/token:ключ, чужой домен отклонён', () => {
  const z = catalog.get('zendesk');
  assert.equal(z.builder, 'basic');
  const b = buildInjection(z, { account: 'acme', email: 'agent@acme.example', key: TOKEN });
  assert.equal(b.host, 'acme.zendesk.com');
  assert.equal(b.secret, `agent@acme.example/token:${TOKEN}`);
  assert.equal(b.injection.encode, 'base64');
  assert.equal(buildInjection(z, { account: 'ACME.zendesk.com', email: 'a@b.example', key: TOKEN }).host, 'acme.zendesk.com');
  assert.equal(buildInjection(z, { account: 'https://acme.zendesk.com/agent', email: 'a@b.example', key: TOKEN }).host, 'acme.zendesk.com');
  for (const account of ['acme.evil.com', 'evil.com', 'acme.zendesk.com.evil.com', 'https://evil.com/', '127.0.0.1', 'a b']) {
    assert.throws(() => buildInjection(z, { account, email: 'a@b.example', key: TOKEN }), undefined, account);
  }
  for (const email of ['', 'no-at', 'a:b@c.example', 'a b@c.example']) {
    assert.throws(() => buildInjection(z, { account: 'acme', email, key: TOKEN }), undefined, email);
  }
  assert.ok(catalog.secretForms(z, b.secret).includes(TOKEN), 'ключ отдельно');
});

// ---- 4. loadCatalog
test('loadCatalog падает на фиксированном хосте с полем host/webhook_url и на builder subdomain', () => {
  const inj = '    injection: { type: header, name: authorization }\n';
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    fields: [host, header, key]\n`), /fixed host/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    fields: [webhook_url]\n`), /fixed host/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n    builder: subdomain\n${inj}    fields: [account, key]\n`), /fixed host/);
  // исправный провайдер загружается
  assert.equal(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}`), null);
});

test('loadCatalog: builder other только у slug other, getKeyUrl только https, filterFrom должен существовать', () => {
  const inj = '    injection: { type: header, name: authorization }\n';
  assert.match(loadError(`${base}  a:\n    name: A\n    host: owner\n    builder: other\n${inj}    fields: [host, header, key]\n`), /other/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    getKeyUrl: 'http://a.example/keys'\n`), /getKeyUrl/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    getKeyUrl: 'javascript:alert(1)'\n`), /getKeyUrl/);
  assert.equal(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    getKeyUrl: 'https://a.example/keys'\n    getKeyHint: 'x'\n`), null);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n${inj}    filterFrom: nope\n`), /filterFrom/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n    builder: static\n${inj}    sensitive: yes-please\n`), /sensitive/);
  assert.match(loadError(`${base}  a:\n    name: A\n    host: api.a.example\n    builder: nope\n${inj}`), /builder/);
});

test('каталог: getKeyUrl везде https, sensitive только у Stripe и Twilio', () => {
  for (const p of catalog.list()) {
    if (p.getKeyUrl) assert.match(p.getKeyUrl, /^https:\/\//, p.slug);
    assert.equal(p.sensitive === true, ['stripe', 'twilio'].includes(p.slug), p.slug);
    if (p.slug !== 'other') assert.notEqual(p.builder, 'other', p.slug);
  }
  assert.equal(catalog.get('other').builder, 'other');
  assert.equal(catalog.get('amocrm').builder, 'subdomain');
});

// ---- 5. Bitrix24 и bitrix24-box
const hook = (host, extra = '') => `https://${host}${extra}/rest/17/p4m2zq9w1v5c/`;

test('bitrix24: чужой домен отклонён, облачный принят', () => {
  const b = catalog.get('bitrix24');
  assert.doesNotMatch(b.hostPattern, /\^\[a-z0-9\.-\]\+\$/);
  for (const host of ['evil.com', 'portal.corp.example', 'x.bitrix24.ru.evil.com']) {
    assert.throws(() => buildInjection(b, { webhook_url: hook(host) }), undefined, host);
  }
  const ok = buildInjection(b, { webhook_url: hook('x.bitrix24.ru') });
  assert.equal(ok.host, 'x.bitrix24.ru');
  assert.equal(ok.secret, '17/p4m2zq9w1v5c');
});

test('bitrix24-box: произвольный домен принят; localhost, IP, порт и http отклонены', () => {
  const box = catalog.get('bitrix24-box');
  assert.equal(box.host, 'owner');
  assert.equal(box.builder, 'webhook');
  assert.equal(box.warning, true);
  assert.equal(box.hostPattern, undefined);
  assert.deepEqual(box.injection, { type: 'path', template: '/rest/{secret}' });
  assert.equal(box.kind, 'path');
  const ok = buildInjection(box, { webhook_url: hook('portal.corp.example') });
  assert.equal(ok.host, 'portal.corp.example');
  assert.equal(ok.secret, '17/p4m2zq9w1v5c');
  for (const host of ['localhost', 'sub.localhost', '127.0.0.1', '10.0.0.5', '[::1]', 'portal.internal', 'portal.local', 'portal']) {
    assert.throws(() => buildInjection(box, { webhook_url: hook(host) }), undefined, host);
  }
  assert.throws(() => buildInjection(box, { webhook_url: hook('portal.corp.example:8443') }), undefined, 'порт');
  assert.throws(() => buildInjection(box, { webhook_url: hook('user:pw@portal.corp.example') }), undefined, 'логин в адресе');
  assert.throws(() => buildInjection(box, { webhook_url: hook('portal.corp.example').replace('https', 'http') }), undefined, 'http');
});

test('bitrix24-box: фильтр копируется у bitrix24 (копия, не ссылка), предупреждение на форме ключа', () => {
  const b = catalog.get('bitrix24');
  const box = catalog.get('bitrix24-box');
  assert.ok(box.filter);
  assert.deepEqual(box.filter, b.filter);
  assert.notEqual(box.filter, b.filter);
  assert.notEqual(box.filter.entities, b.filter.entities);
  const warn = t('catalog.warn.bitrix24-box');
  assert.ok(warn && !warn.startsWith('catalog.'));
  assert.ok(V.keyForm({ csrf: 'x', provider: box, values: {} }).includes(warn.slice(0, 40)));
  assert.ok(!V.keyForm({ csrf: 'x', provider: b, values: {} }).includes(warn.slice(0, 40)));
  initI18n('ru');
  try {
    const ru = t('catalog.warn.bitrix24-box');
    assert.notEqual(ru, warn);
    assert.ok(V.keyForm({ csrf: 'x', provider: box, values: {} }).includes(ru.slice(0, 20)));
  } finally { initI18n('en'); }
  assert.ok(fs.existsSync(path.join(root, 'assets', 'icons', 'bitrix24-box.svg')));
});

// ---- 6. Миграция
test('миграция: bitrix24 с чужим хостом → bitrix24-box при старте, audit catalog.migrated, облачный не тронут', async () => {
  const dataDir = fs.mkdtempSync(path.join(tmp, 'mig-'));
  const dbPath = path.join(dataDir, 'gw.db');
  const mk = (id, host) => ({ id, provider: 'bitrix24', label: id, kind: 'path', host, injection: { type: 'path', template: '/rest/{secret}' }, vault_param: `cred/${id}`, last4: 'd7ab' });
  {
    const db = openDb(dbPath);
    const repo = createRepo(db);
    repo.createCredential(mk('box1', 'portal.corp.example'));
    repo.createCredential(mk('cloud1', 'x.bitrix24.ru'));
    db.close();
  }
  for (let round = 0; round < 2; round++) { // повторный старт ничего не меняет
    const app = await buildApp({ dataDir, dbPath, vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
    try {
      assert.equal(app.repo.getCredential('box1').provider, 'bitrix24-box');
      assert.equal(app.repo.getCredential('box1').host, 'portal.corp.example');
      assert.equal(app.repo.getCredential('cloud1').provider, 'bitrix24');
      const migrated = app.repo.listAudit({ limit: 50 }).filter((a) => a.action === 'catalog.migrated');
      assert.equal(migrated.length, 1);
      assert.equal(migrated[0].target, 'box1');
      assert.deepEqual(JSON.parse(migrated[0].meta_json), { from: 'bitrix24', to: 'bitrix24-box' });
    } finally { await app.stop(); }
  }
});

// ---- 7. Прокси: Basic и редактор ответов
let app, mock, appBase;
const seen = [];

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.setHeader('content-type', 'application/json');
    // сервис «эхом» возвращает заголовок авторизации и ключ во всех формах
    res.end(JSON.stringify({ auth: req.headers.authorization, token: req.headers['x-api-token'], raw: TOKEN, url: encodeURIComponent(TOKEN) }));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const up = `http://127.0.0.1:${mock.address().port}`;
  const dataDir = fs.mkdtempSync(path.join(tmp, 'app-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { 'api.twilio.com': up, 'acme.zendesk.com': up, 'api.pipedrive.com': up },
  });
  await app.start();
  appBase = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
// временный каталог удаляем после остановки приложения (на Windows файлы базы заняты до закрытия)
after(async () => {
  await app?.stop();
  mock?.closeAllConnections?.();
  mock?.close();
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* не мешаем итогу тестов */ }
});

/** Создаёт ключ, агента и пропуск напрямую и делает один вызов через прокси. */
async function callThrough(slug, input) {
  const provider = app.ctx.catalog.get(slug);
  const built = buildInjection(provider, input);
  const id = crypto.randomBytes(6).toString('hex');
  await app.ctx.vault.put(`cred/${id}`, built.secret);
  app.repo.createCredential({ id, provider: slug, label: slug, kind: built.kind, host: built.host, injection: built.injection, vault_param: `cred/${id}`, last4: built.last4 });
  app.repo.createAgent({ id: `ag${id}`, name: 'test', token_hash: crypto.randomBytes(16).toString('hex') });
  const req = { id: `rq${id}`, agent_id: `ag${id}`, credential_id: id, ttl: 600, calls: 5, reason: '', expires_at: Math.floor(Date.now() / 1000) + 600 };
  app.repo.createRequest(req);
  const { token } = app.ctx.grants.issue(req, app.repo.getCredential(id));
  const res = await fetch(`${appBase}/v1/proxy/${slug}/ping`, { headers: { authorization: `Bearer ${token}` } });
  return { res, text: await res.text(), secret: built.secret };
}

test('прокси: Twilio ставит Basic base64(SID:токен), ответ очищен от всех форм секрета', async () => {
  const { res, text, secret } = await callThrough('twilio', { account: SID, key: TOKEN });
  assert.equal(res.status, 200);
  assert.equal(seen.at(-1).headers.authorization, `Basic ${b64(`${SID}:${TOKEN}`)}`);
  assert.equal(seen.at(-1).url, '/ping');
  for (const leak of [TOKEN, encodeURIComponent(TOKEN), b64(secret), secret]) assert.ok(!text.includes(leak), `утечка: ${leak.slice(0, 6)}…`);
  assert.ok(text.includes('****'));
});

test('прокси: Zendesk идёт на хост из поддомена, логин email/token', async () => {
  const { res, text, secret } = await callThrough('zendesk', { account: 'acme', email: 'agent@acme.example', key: TOKEN });
  assert.equal(res.status, 200);
  assert.equal(seen.at(-1).headers.authorization, `Basic ${b64(`agent@acme.example/token:${TOKEN}`)}`);
  for (const leak of [TOKEN, encodeURIComponent(TOKEN), b64(secret)]) assert.ok(!text.includes(leak));
});

test('прокси: Pipedrive кладёт токен в x-api-token', async () => {
  const { res } = await callThrough('pipedrive', { key: 'fake-pipedrive-token-9876' });
  assert.equal(res.status, 200);
  assert.equal(seen.at(-1).headers['x-api-token'], 'fake-pipedrive-token-9876');
});
