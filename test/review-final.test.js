// Регрессии по финальному ревью (out/review-final): M1 text/plain в прокси, M6 дата срока, L1 JSON-экранирование секрета,
// L2 %-имя провайдера, L7 «*» в rpc-шаблонах, L10 Airtable listRecords. Без сети: mock-апстрим на localhost.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { buildInjection, loadCatalog } from '../src/catalog.js';
import { compileFilter } from '../src/core/filter.js';
import { parsePolicy } from '../src/web/policy.js';
import { initI18n, t } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const catalog = loadCatalog(path.join(root, 'providers.yaml'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

let app; let mock; let base; let dataDir;
let seen = [];
let n = 0;

before(async () => {
  mock = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      seen.push({ url: req.url, method: req.method, ct: req.headers['content-type'], body });
      res.writeHead(200, { 'content-type': 'application/json' });
      // эхо заголовков: секрет в JSON-строке с экранированием
      res.end(JSON.stringify({ headers: req.headers, url: req.url }));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const up = `http://127.0.0.1:${mock.address().port}`;
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-rf-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { 'x.example.org': up, 'api.hubapi.com': up },
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
});

after(async () => {
  await app.stop();
  mock.close(); mock.closeAllConnections?.();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function mkToken({ provider, input, filter = null }) {
  const p = app.ctx.catalog.get(provider);
  const built = buildInjection(p, input);
  const id = `k${++n}`;
  await app.ctx.vault.put(`cred/${id}`, built.secret);
  app.repo.createCredential({ id, provider, label: id, kind: built.kind, host: built.host, injection: built.injection, vault_param: `cred/${id}`, last4: built.last4, mode: 'always', approval: 'web_button', max_ttl: 3600, max_calls: 1000, max_parallel: 4 });
  if (filter) app.repo.updateCredentialFilter(id, filter);
  const agentToken = `gwa_${crypto.randomBytes(12).toString('hex')}`;
  const agentId = `ag${++n}`;
  app.repo.createAgent({ id: agentId, name: agentId, token_hash: sha(agentToken), enabled: 1, all_credentials: 1 });
  const g = await (await fetch(`${base}/v1/grants`, {
    method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ provider, credential_id: id, ttl: 600, calls: 100 }),
  })).json();
  return g.token;
}

test('M1: text/plain в /v1/proxy доходит до сервиса байт-в-байт (в т.ч. charset и при включённом фильтре)', async () => {
  const body = 'строка\r\nline2 {"a":1}';
  const plain = await mkToken({ provider: 'other', input: { host: 'https://x.example.org', header: 'x-token', key: `tp${crypto.randomBytes(8).toString('hex')}` } });
  for (const ct of ['text/plain', 'text/plain; charset=utf-8']) {
    seen = [];
    const r = await fetch(`${base}/v1/proxy/other/x`, { method: 'POST', headers: { authorization: `Bearer ${plain}`, 'content-type': ct }, body, signal: AbortSignal.timeout(8000) });
    await r.text();
    assert.equal(r.status, 200, ct);
    assert.equal(seen.length, 1, ct);
    assert.equal(seen[0].body.toString('utf8'), body, ct);
    assert.equal(seen[0].ct, ct);
  }
  // с включённым фильтром (HubSpot: тело POST идёт сквозь проверки)
  const filtered = await mkToken({
    provider: 'hubspot', input: { key: `pat-eu1-${crypto.randomBytes(4).toString('hex')}-bbbb-cccc` },
    filter: { enabled: true, entities: { deals: ['results[].id'] }, methods: [], fields: [] },
  });
  seen = [];
  const r2 = await fetch(`${base}/v1/proxy/hubspot/crm/v3/objects/deals/search`, { method: 'POST', headers: { authorization: `Bearer ${filtered}`, 'content-type': 'text/plain; charset=utf-8' }, body, signal: AbortSignal.timeout(8000) });
  await r2.text();
  // при фильтре тело либо доходит целиком, либо шлюз явно отказывает до сервиса — молча пустым не уходит
  if (seen.length) assert.equal(seen[0].body.toString('utf8'), body, 'с фильтром тело не теряется');
  else assert.ok(r2.status >= 400 && r2.status < 500, `с фильтром явный отказ, получено ${r2.status}`);
});

test('M6: неверная дата срока ключа даёт ошибку формы, а не исключение', () => {
  let r;
  assert.doesNotThrow(() => { r = parsePolicy({ expires_at: 'garbage' }, { telegramConnected: false }); });
  assert.ok(r.errors.includes(t('policy.err.date')));
  const ok = parsePolicy({ expires_at: '2030-01-01' }, { telegramConnected: false });
  assert.equal(ok.errors.includes(t('policy.err.date')), false);
  assert.ok(Number.isInteger(ok.policy.expires_at));
});

test('L1: секрет с " и \\ вычищается из JSON-ответа; JSON-формы и \\uXXXX есть в secretForms', async () => {
  const rnd = crypto.randomBytes(5).toString('hex');
  const key = `ab"cd\\ef${rnd}`;
  const tok = await mkToken({ provider: 'other', input: { host: 'https://x.example.org', header: 'x-token', key } });
  const txt = await (await fetch(`${base}/v1/proxy/other/echo`, { headers: { authorization: `Bearer ${tok}` } })).text();
  assert.ok(!txt.includes(JSON.stringify(key).slice(1, -1)), 'экранированная форма не утекла');
  assert.ok(!txt.includes(key), 'сырая форма не утекла');
  // не-ASCII: в заголовок такой секрет не положить, проверяем набор форм напрямую
  const forms = catalog.secretForms(catalog.get('other'), `ключ"${rnd}`);
  assert.ok(forms.includes(`ключ\\"${rnd}`));
  assert.ok(forms.includes(`\\u043a\\u043b\\u044e\\u0447\\"${rnd}`), 'нижний регистр hex');
  assert.ok(forms.includes(`\\u043A\\u043B\\u044E\\u0447\\"${rnd}`), 'верхний регистр hex');
});

test('L2: имя провайдера с «%» в /v1/proxy отклоняется 400 bad_path, запрос до сервиса не доходит', async () => {
  const tok = await mkToken({ provider: 'hubspot', input: { key: `pat-eu1-${crypto.randomBytes(4).toString('hex')}-bbbb-cccc` } });
  seen = [];
  const r = await fetch(`${base}/v1/proxy/%68ubspot/crm/v3/objects/deals?limit=1`, { method: 'POST', body: '{}', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' } });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, 'bad_path');
  assert.equal(seen.length, 0);
});

test('L7: «*» в rpc-шаблонах (Bitrix24) — только [A-Za-z0-9_]', () => {
  const bitrix = catalog.get('bitrix24');
  const ro = compileFilter({ enabled: false, entities: {}, methods: [], fields: [], readOnly: true }, bitrix);
  for (const bad of ['/crm.deal.add;.list', '/crm.deal.add%3B.list', '/crm.deal.add;.list.json', '/crm.deal.add.list', '/crm.a b.list']) {
    assert.equal(ro.allowMethod('POST', bad), false, bad);
  }
  for (const good of ['/crm.deal.list', '/crm.contact.get', '/crm.deal.list.json', '/crm.lead.fields']) {
    assert.equal(ro.allowMethod('POST', good), true, good);
  }
  const rule = compileFilter({ enabled: true, entities: {}, methods: ['crm.*.list'], fields: ['result'] }, bitrix);
  assert.equal(rule.allowMethod('/crm.deal.add;.list'), false);
  assert.equal(rule.allowMethod('/crm.deal.add%3B.list'), false);
  assert.equal(rule.allowMethod('/crm.deal.list'), true);
});

test('L10: Airtable readOnly пропускает POST listRecords и закрывает остальную запись', () => {
  const f = compileFilter({ enabled: false, entities: {}, methods: [], fields: [], readOnly: true }, catalog.get('airtable'));
  assert.equal(f.allowMethod('POST', '/v0/appAbc123/tblXyz/listRecords'), true);
  assert.equal(f.allowMethod('GET', '/v0/appAbc123/tblXyz'), true);
  assert.equal(f.allowMethod('POST', '/v0/appAbc123/tblXyz'), false);
  assert.equal(f.allowMethod('PATCH', '/v0/appAbc123/tblXyz/listRecords'), false);
  assert.equal(f.allowMethod('POST', '/v0/appAbc123/tblXyz/listRecords/extra'), false);
});
