// Мелочи безопасности из ТЗ 1.0.2 (пакет 8): №10 статика и healthz не продлевают сессию,
// №11 телефоны демо-мока с "+" и не короче 10 цифр (маска срабатывает), №12 вычистка секрета
// из строковых значений ДО filterBody: обрезка длинного поля не должна разрезать секрет.
// Секреты собираются в рантайме из кусков, в файле литералов нет.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { maskText } from '../src/core/mask.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) { try { await f(); } catch { /* уборка */ } } });

// ---- №10: /public/* и /healthz не вызывают repo.touchSession ----

/** Демо-приложение: /login выдаёт сессию без пароля, cookie собираются в банку. */
async function bootDemo() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-low-'));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    demo: true, dataDirExplicit: true, prodHosts: [], env: {}, lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const jar = new Map();
  const store = (res) => { for (const s of res.headers.getSetCookie?.() || []) { const [kv] = s.split(';'); const i = kv.indexOf('='); jar.set(kv.slice(0, i), kv.slice(i + 1)); } };
  return {
    app, base,
    cookie: () => [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
    login: async () => { store(await fetch(`${base}/login`, { redirect: 'manual' })); },
  };
}

test('№10: /public/* и /healthz не вызывают repo.touchSession, обычная страница продлевает', async () => {
  const c = await bootDemo();
  await c.login();
  const realTouch = c.app.repo.touchSession;
  let touches = 0;
  c.app.repo.touchSession = (...a) => { touches += 1; return realTouch.apply(c.app.repo, a); };
  for (const p of ['/public/app.js', '/public/style.css', '/healthz']) {
    const r = await fetch(`${c.base}${p}`, { headers: { cookie: c.cookie() } });
    assert.equal(r.status, 200, p);
  }
  assert.equal(touches, 0, `статика и healthz не продлевают сессию (вызовов: ${touches})`);
  const home = await fetch(`${c.base}/`, { headers: { cookie: c.cookie() } });
  assert.equal(home.status, 200);
  assert.ok(touches > 0, 'обычная страница продлевает сессию');
});

// ---- №11: телефоны демо-мока годятся для маски ----

test('№11: телефоны в src/demo/mock.js с "+" и не короче 10 цифр, maskText их заменяет', () => {
  const mock = fs.readFileSync(path.join(root, 'src/demo/mock.js'), 'utf8');
  const phones = [...mock.matchAll(/PHONE:\s*'([^']+)'/g)].map((m) => m[1]);
  assert.ok(phones.length >= 3, `телефонов найдено: ${phones.length}`);
  for (const p of phones) {
    assert.ok(p.startsWith('+'), `с "+": ${p}`);
    assert.ok(p.replace(/\D/g, '').length >= 10, `не короче 10 цифр: ${p}`);
    assert.equal(maskText(p).n, 1, `маска персональных данных срабатывает: ${p}`);
  }
});

// ---- №12: вычистка секрета до filterBody (обрезка и маска не режут секрет) ----

test('№12: секрет в поле длиннее лимита на границе обрезки не попадает в ответ даже частично', async () => {
  const secret = ['sk', 'live', crypto.randomBytes(16).toString('hex')].join('_');
  // Поле 3990 'x', затем секрет, затем 'y': обрезка maxFieldLen (4000) приходится на секрет,
  // без вычистки до filterBody ответ унёс бы первые 10 символов секрета.
  const pad = 'x'.repeat(4000 - 10);
  const mock = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ result: [{ ID: '1', COMMENTS: pad + secret + 'y'.repeat(60) }], total: 1 }));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  cleanup.push(() => new Promise((r) => { mock.closeAllConnections?.(); mock.close(r); }));

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-low2-'));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { 'test.bitrix24.ru': `http://127.0.0.1:${mock.address().port}` },
  });
  await app.start();
  cleanup.push(() => app.stop());

  const id = 'low12';
  app.repo.createCredential({ id, provider: 'bitrix24', label: 'low12', kind: 'path', host: 'test.bitrix24.ru', injection: { type: 'path', template: '/rest/{secret}' }, vault_param: `cred/${id}`, last4: '0000', mode: 'always', max_ttl: 3600, max_calls: 100, max_parallel: 2 });
  app.repo.updateCredentialFilter(id, { enabled: true, entities: { deals: ['result.ID', 'result.COMMENTS'] }, methods: [], fields: [] });
  await app.ctx.vault.put(`cred/${id}`, secret);
  const agentToken = 'gwa_' + crypto.randomBytes(24).toString('base64url');
  app.repo.createAgent({ id: 'low-agent', name: 'low-agent', token_hash: crypto.createHash('sha256').update(agentToken).digest('hex'), enabled: 1, all_credentials: 1 });

  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const g = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 600, calls: 10, reason: 'test' }) });
  assert.equal(g.status, 200);
  const pass = (await g.json()).token;
  const r = await fetch(`${base}/v1/proxy/bitrix24/crm.deal.list.json`, { headers: { authorization: `Bearer ${pass}` } });
  assert.equal(r.status, 200);
  const text = await r.text();
  assert.ok(!text.includes(secret), 'секрета в ответе нет');
  // ни одна часть секрета длиной от 8 символов не видна
  for (let i = 0; i + 8 <= secret.length; i++) assert.ok(!text.includes(secret.slice(i, i + 8)), `часть секрета [${i}, +8) в ответе`);
  const body = JSON.parse(text);
  assert.equal(body.result[0].ID, '1', 'поле без секрета дошло');
  assert.ok(body.result[0].COMMENTS.length <= 4000, 'длинное поле обрезано лимитом');
  assert.ok(body.result[0].COMMENTS.includes('****'), 'секрет заменён звёздами до обрезки');
});
