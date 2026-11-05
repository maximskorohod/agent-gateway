// REST-провайдеры каталога (п. 7.3): HubSpot «Сделки без контактов», Pipedrive «Сделки без персон»,
// Zendesk «Тикеты без данных клиента». Реальный providers.yaml, mock-апстрим на localhost, ответы из test/fixtures.
// HubSpot и Pipedrive сверены с живыми тестовыми аккаунтами 04.11.2026; Zendesk — по документации (unverified).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { compileFilter, checkFilter, normalizeFilter } from '../src/core/filter.js';
import { loadCatalog } from '../src/catalog.js';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const fx = (name) => JSON.parse(fs.readFileSync(path.join(root, 'test', 'fixtures', name), 'utf8'));
const HS = fx('hubspot-deals.json');
const PD = fx('pipedrive-deals.json');
const ZD = fx('zendesk-tickets.json');

const catalog = loadCatalog(path.join(root, 'providers.yaml'));
const HOSTS = { hubspot: 'api.hubapi.com', pipedrive: 'api.pipedrive.com', zendesk: 'acme.zendesk.com' };

/** Фильтр с типами по умолчанию (поля defaults), включённый. */
const defaultsFilter = (slug, over = {}) => ({ ...normalizeFilter(null, catalog.get(slug)), enabled: true, ...over });

// ---- каталог и checkFilter
test('каталог: три провайдера загружаются, фильтр rest, unverified, defaults проходят checkFilter', () => {
  for (const [slug, type] of [['hubspot', 'deals'], ['pipedrive', 'deals'], ['zendesk', 'tickets']]) {
    const p = catalog.get(slug);
    assert.ok(p, slug);
    assert.equal(p.filter.style, 'rest', slug);
    assert.equal(p.filter.unverified, slug === 'zendesk', slug);
    assert.ok(p.filter.entities[type], `${slug}.${type}`);
    assert.deepEqual(checkFilter(defaultsFilter(slug), p), [], slug);
    assert.equal(p.readOnly.default, true, `${slug}: readOnly по умолчанию не сломан`);
  }
});

test('каталог: unverified должен быть boolean', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gw-rp-')), 'c.yaml');
  const yaml = fs.readFileSync(path.join(root, 'providers.yaml'), 'utf8').replace('style: rest\n      unverified: true', 'style: rest\n      unverified: maybe');
  fs.writeFileSync(file, yaml);
  assert.throws(() => loadCatalog(file), /unverified/);
});

// ---- mock-апстрим
let app, mock;
let seen = [];
let seq = 0;
const SECRET = `tok_${crypto.randomBytes(12).toString('hex')}`; // фальшивый ключ собирается в рантайме
const nowSec = () => Math.floor(Date.now() / 1000);

before(async () => {
  mock = http.createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: data });
      res.setHeader('content-type', 'application/json');
      const p = req.url.split('?')[0].replace(/\/+$/, '');
      let body = { ok: true };
      if (p.startsWith('/crm/v3/objects/deals')) body = p === '/crm/v3/objects/deals' ? HS.list : HS.single;
      else if (p === '/v1/deals' || p === '/api/v2/deals') body = PD.list;
      else if (/^\/(v1|api\/v2)\/deals\/[^/]+$/.test(p)) body = PD.single;
      else if (p === '/api/v2/tickets' || p === '/api/v2/tickets.json') body = req.url.includes('include=') ? ZD.sideload : ZD.list;
      else if (/^\/api\/v2\/tickets\/[^/]+$/.test(p)) body = ZD.single;
      res.end(JSON.stringify(body));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-rpapp-'));
  const up = `http://127.0.0.1:${mock.address().port}`;
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    catalogPath: path.join(root, 'providers.yaml'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: Object.fromEntries(Object.values(HOSTS).map((h) => [h, up])),
  });
  await app.start();
});
after(async () => { await app.stop(); mock.close(); mock.closeAllConnections?.(); });

const INJECTION = {
  hubspot: { type: 'header', name: 'authorization', prefix: 'Bearer ' },
  pipedrive: { type: 'header', name: 'x-api-token' },
  zendesk: { type: 'header', name: 'authorization', prefix: 'Basic ', encode: 'base64' },
};

/** Агент + ключ провайдера с фильтром + пропуск. */
async function mkGrant(slug, filter) {
  const n = ++seq;
  const agentId = `pa${n}`; const credId = `pc${n}`;
  app.repo.createAgent({ id: agentId, name: `a${n}`, token_hash: crypto.createHash('sha256').update(`gwa_rp_${n}`).digest('hex'), enabled: 1 });
  app.repo.createCredential({
    id: credId, provider: slug, label: `k${n}`, kind: 'static', host: HOSTS[slug], injection: INJECTION[slug],
    vault_param: `cred/${credId}`, last4: SECRET.slice(-4), max_parallel: 3,
  });
  if (filter) app.repo.updateCredentialFilter(credId, filter);
  await app.ctx.vault.put(`cred/${credId}`, SECRET);
  const req = { id: `pr${n}`, agent_id: agentId, credential_id: credId, ttl: 3000, calls: 1000, reason: '', expires_at: nowSec() + 3000 };
  app.repo.createRequest(req);
  const { grant, token } = app.ctx.grants.issue(req, app.repo.getCredential(credId));
  return { id: grant.id, token, slug };
}
const call = (g, over = {}) => app.ctx.proxy.call({ token: g.token, provider: g.slug, method: 'GET', path: '/', query: '', headers: {}, body: null, contentLength: null, via: 'rest', ...over });
const json = async (r) => { const chunks = []; for await (const c of r.body) chunks.push(c); return JSON.parse(Buffer.concat(chunks).toString('utf8')); };
const used = (g) => app.repo.getGrant(g.id).calls_used;
const dump = (o) => JSON.stringify(o);

// ---- HubSpot
test('HubSpot: список и сделка фильтруются, контакты и associations вырезаны, поля по умолчанию на месте', async () => {
  const g = await mkGrant('hubspot', defaultsFilter('hubspot'));
  seen = [];
  let r = await call(g, { path: '/crm/v3/objects/deals', query: '?properties=email,phone&limit=2' });
  assert.equal(r.ok, true);
  const list = await json(r);
  assert.deepEqual(list.results[0], { id: '501', properties: { dealstage: 'qualifiedtobuy', createdate: '2026-10-01T09:00:00.000Z' } });
  assert.equal(list.results.length, 2);
  assert.deepEqual(list.paging, { next: { after: '502' } }, 'ссылка paging.next.link вырезана');
  assert.equal(new URLSearchParams(seen.at(-1).url.split('?')[1]).get('properties'), 'dealstage,createdate');
  for (const bad of ['anna@example', 'buyer@example', '555 010', 'associations', 'contact', 'description', 'dealname']) assert.ok(!dump(list).includes(bad), bad);

  r = await call(g, { path: '/crm/v3/objects/deals/501' });
  assert.equal(r.ok, true);
  const one = await json(r);
  assert.deepEqual(one, { id: '501', properties: { dealstage: 'qualifiedtobuy', createdate: '2026-10-01T09:00:00.000Z' } });
});

test('HubSpot: отмеченные поля (название, сумма) появляются, но не email и не description', async () => {
  const f = defaultsFilter('hubspot', { entities: { deals: ['results[].id', 'results[].properties.dealname', 'results[].properties.amount'] } });
  const g = await mkGrant('hubspot', f);
  const one = await json(await call(g, { path: '/crm/v3/objects/deals/501' }));
  assert.deepEqual(one, { id: '501', properties: { dealname: 'Website redesign', amount: '1500' } });
});

test('HubSpot: deny-маршруты → 403, запись → write_not_allowed, associations → 400, лимит не тратится', async () => {
  const g = await mkGrant('hubspot', defaultsFilter('hubspot'));
  seen = [];
  const before = used(g);
  const cases = [
    { path: '/crm/v3/objects/contacts', status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/objects/contacts/9001', status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/objects/companies', status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/objects/deals/batch/read', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/objects/deals/501/associations/contacts', status: 403, error: 'method_not_allowed' },
    { path: '/crm/v4/associations/deals/contacts/batch/read', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/owners', status: 403, error: 'method_not_allowed' },
    { path: '/crm/v3/objects/deals', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/crm/v3/objects/deals/501', method: 'PATCH', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/crm/v3/objects/deals/501', method: 'DELETE', status: 403, error: 'write_not_allowed' },
    { path: '/crm/v3/objects/deals/search', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/crm/v3/objects/deals', query: '?associations=contacts', status: 400, error: 'query_not_allowed' },
    { path: '/crm/v3/objects/deals/501', query: '?Associations=contacts', status: 400, error: 'query_not_allowed' },
    { path: '/crm/v3/objects/deals/501', query: '?propertiesWithHistory=dealname', status: 400, error: 'query_not_allowed' },
    { path: '/crm/v3/objects/deals', query: '?archived=true', status: 400, error: 'query_not_allowed' },
  ];
  for (const c of cases) {
    const r = await call(g, c);
    assert.deepEqual([r.ok, r.status, r.error], [false, c.status, c.error], `${c.method || 'GET'} ${c.path}${c.query || ''}`);
  }
  assert.equal(seen.length, 0, 'до сервиса не дошло');
  assert.equal(used(g), before);
});

test('HubSpot: search открывается только флагом', async () => {
  const body = Buffer.from(JSON.stringify({ filterGroups: [] }));
  const req = { method: 'POST', path: '/crm/v3/objects/deals/search', body, contentLength: body.length, headers: { 'content-type': 'application/json' } };
  const g = await mkGrant('hubspot', defaultsFilter('hubspot', { flags: { deals: ['search'] } }));
  const r = await call(g, req);
  assert.equal(r.ok, true);
  await json(r);
  assert.equal(seen.at(-1).method, 'POST');
  const g2 = await mkGrant('hubspot', defaultsFilter('hubspot'));
  assert.equal((await call(g2, req)).error, 'write_not_allowed');
});

// ---- Pipedrive
test('Pipedrive: персоны, организации и имена вырезаны (v1 и v2), разрешённые поля на месте', async () => {
  const f = defaultsFilter('pipedrive', {
    entities: { deals: ['data[].id', 'data[].title', 'data[].status', 'data[].stage_id', 'data[].value', 'data[].user_id.id', 'data[].add_time'] },
  });
  const g = await mkGrant('pipedrive', f);
  for (const p of ['/v1/deals', '/api/v2/deals']) {
    const r = await call(g, { path: p });
    assert.equal(r.ok, true, p);
    const list = await json(r);
    assert.deepEqual(list.data[0], { id: 31, title: 'Website redesign', status: 'open', stage_id: 2, value: 1500, user_id: { id: 11 }, add_time: '2026-10-01 09:00:00' }, p);
    assert.equal(list.success, true);
    assert.deepEqual(list.additional_data, { pagination: { more_items_in_collection: true, next_start: 100 } });
    for (const bad of ['Anna', 'anna@', '555 010', 'Example Corp', 'person', 'org_', 'cc_email', 'owner@', 'Owner Example', 'abcdef01']) assert.ok(!dump(list).includes(bad), `${p}: ${bad}`);
  }
  const one = await json(await call(g, { path: '/v1/deals/31' }));
  assert.equal(one.data.id, 31);
  assert.ok(!dump(one).includes('Anna') && !dump(one).includes('Example Corp'));
  assert.ok(!('person_id' in one.data) && !('org_id' in one.data) && !('person_name' in one.data));
});

test('Pipedrive: поля по умолчанию без объектов; deny и запись → 403, filter_id/person_id → 400', async () => {
  const g = await mkGrant('pipedrive', defaultsFilter('pipedrive'));
  const list = await json(await call(g, { path: '/v1/deals' }));
  assert.deepEqual(list.data[0], { id: 31, status: 'open', stage_id: 2, add_time: '2026-10-01 09:00:00' });
  seen = [];
  const before = used(g);
  const cases = [
    { path: '/v1/persons', status: 403, error: 'method_not_allowed' },
    { path: '/v1/persons/7', status: 403, error: 'method_not_allowed' },
    { path: '/v1/organizations/5', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/persons', status: 403, error: 'method_not_allowed' },
    { path: '/v1/deals/31/participants', status: 403, error: 'method_not_allowed' },
    { path: '/v1/deals/search', status: 403, error: 'method_not_allowed' },
    { path: '/v1/deals', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/v1/deals/31', method: 'PUT', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/v1/deals/31', method: 'DELETE', status: 403, error: 'write_not_allowed' },
    { path: '/v1/deals', query: '?filter_id=3', status: 400, error: 'query_not_allowed' },
    { path: '/v1/deals', query: '?person_id=7', status: 400, error: 'query_not_allowed' },
  ];
  for (const c of cases) {
    const r = await call(g, c);
    assert.deepEqual([r.ok, r.status, r.error], [false, c.status, c.error], `${c.method || 'GET'} ${c.path}${c.query || ''}`);
  }
  assert.equal(seen.length, 0);
  assert.equal(used(g), before);
});

// ---- Zendesk
test('Zendesk: requester_id остаётся, via/теги/custom_fields/subject/description вырезаны по умолчанию', async () => {
  const g = await mkGrant('zendesk', defaultsFilter('zendesk'));
  for (const p of ['/api/v2/tickets', '/api/v2/tickets.json']) {
    const r = await call(g, { path: p });
    assert.equal(r.ok, true, p);
    const list = await json(r);
    assert.deepEqual(list.tickets[0], { id: 101, status: 'open', requester_id: 4001, created_at: '2026-10-01T09:00:00Z' }, p);
    assert.deepEqual(list.tickets[1], { id: 102, status: 'pending', requester_id: 4003, created_at: '2026-10-05T09:00:00Z' });
    assert.equal(list.count, 2);
    for (const bad of ['Anna', 'anna@', '555 010', 'subject', 'description', 'login', 'custom_fields', 'tags', 'via', 'collaborator', 'satisfaction']) assert.ok(!dump(list).includes(bad), `${p}: ${bad}`);
  }
  const one = await json(await call(g, { path: '/api/v2/tickets/101' }));
  assert.deepEqual(one, { ticket: { id: 101, status: 'open', requester_id: 4001, created_at: '2026-10-01T09:00:00Z' } });
});

test('Zendesk: канал via.channel виден, адрес отправителя из via нет; subject виден только при отметке', async () => {
  const f = defaultsFilter('zendesk', { entities: { tickets: ['tickets[].id', 'tickets[].via.channel', 'tickets[].subject'] } });
  const g = await mkGrant('zendesk', f);
  const list = await json(await call(g, { path: '/api/v2/tickets' }));
  assert.deepEqual(list.tickets[1], { id: 102, via: { channel: 'web' }, subject: 'Invoice question' });
  assert.deepEqual(list.tickets[0].via, { channel: 'email' }, 'адрес и имя из via.source вырезаны');
});

test('Zendesk: users/organizations/search/comments → 403, запись → write_not_allowed, include=users → 400', async () => {
  const g = await mkGrant('zendesk', defaultsFilter('zendesk'));
  seen = [];
  const before = used(g);
  const cases = [
    { path: '/api/v2/users', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/users/4001', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/users.json', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/organizations/2001', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/search.json', query: '?query=anna', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/requests', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/tickets/101/comments', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/tickets/101/requester', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/tickets/show_many', status: 403, error: 'method_not_allowed' },
    { path: '/api/v2/tickets', method: 'POST', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/api/v2/tickets/101', method: 'PUT', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { path: '/api/v2/tickets/101', method: 'DELETE', status: 403, error: 'write_not_allowed' },
    { path: '/api/v2/tickets', query: '?include=users', status: 400, error: 'query_not_allowed' },
  ];
  for (const c of cases) {
    const r = await call(g, c);
    assert.deepEqual([r.ok, r.status, r.error], [false, c.status, c.error], `${c.method || 'GET'} ${c.path}${c.query || ''}`);
  }
  assert.equal(seen.length, 0);
  assert.equal(used(g), before);
});

test('compileFilter: methods подсказки агенту — только чтение, ни одного маршрута контактов, персон и пользователей', () => {
  for (const slug of ['hubspot', 'pipedrive', 'zendesk']) {
    const f = compileFilter(defaultsFilter(slug), catalog.get(slug));
    assert.ok(f.methods.length >= 2, slug);
    for (const m of f.methods) {
      assert.match(m, /^GET /, `${slug}: ${m}`);
      assert.ok(!/contacts|persons|users|organizations/.test(m), `${slug}: ${m}`);
    }
  }
});
