// core/proxy.js: call(input) без Fastify, владение lease, порядок шагов (контракт access-mcp.md, тесты 5-10)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { buildApp } from '../src/app.js';
import { createProxy } from '../src/core/proxy.js';
import { createLimiter } from '../src/core/ratelimit.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const HOST = 'test.bitrix24.ru';
const DEAD_HOST = 'dead.bitrix24.ru'; // testUpstream указывает на закрытый порт: upstream_unreachable
const SECRET = '1/abcdef123456';
const MAX_BODY = 2097152; // maxBody bitrix24
const FILTER = { enabled: true, entities: { deals: ['result.ID', 'result.TITLE'] }, methods: [], fields: [] };

let app, base, mock, seq = 0;
let seen = [];
const FIRST = 'first-' + 'x'.repeat(40); // длиннее хвоста редактора, иначе он придержит байты до конца потока
const holds = []; // открытые «медленные» ответы сервиса

const silent = { warn() {}, error() {}, info() {}, debug() {} };
const nowSec = () => Math.floor(Date.now() / 1000);
const inflight = (g) => app.repo.getGrant(g.id).inflight;
const used = (g) => app.repo.getGrant(g.id).calls_used;
const audits = (action) => app.repo.listAudit({ limit: 5000 }).filter((x) => x.action === action);
const releaseAll = () => { while (holds.length) holds.pop().end(); };

/** Новый агент + ключ + пропуск (у каждого свой лимитер частоты: он на агента). */
async function mkGrant({ filter = null, maxParallel = 3, calls = 100000, host = HOST, withSecret = true } = {}) {
  const n = ++seq;
  const agentId = `ag${n}`; const credId = `kc${n}`;
  app.repo.createAgent({ id: agentId, name: `a${n}`, token_hash: crypto.createHash('sha256').update(`gwa_${n}`).digest('hex'), enabled: 1 });
  app.repo.createCredential({
    id: credId, provider: 'bitrix24', label: `k${n}`, kind: 'path', host, injection: { type: 'path', template: '/rest/{secret}' },
    vault_param: `cred/${credId}`, last4: '3456', max_parallel: maxParallel,
  });
  if (filter) app.repo.updateCredentialFilter(credId, filter);
  if (withSecret) await app.ctx.vault.put(`cred/${credId}`, SECRET);
  const req = { id: `rq${n}`, agent_id: agentId, credential_id: credId, ttl: 3000, calls, reason: '', expires_at: nowSec() + 3000 };
  app.repo.createRequest(req);
  const cred = app.repo.getCredential(credId);
  const { grant, token } = app.ctx.grants.issue(req, cred);
  return { id: grant.id, token, agentId, credId };
}

/** Прямой вызов ядра. */
const call = (g, over = {}, proxy = app.ctx.proxy) => proxy.call({
  token: g.token, provider: 'bitrix24', method: 'GET', path: '/crm.deal.list.json', query: '', headers: {}, body: null, contentLength: null, via: 'rest', ...over,
});

/** Тот же вызов по HTTP. */
// http.request, а не fetch: fetch схлопывает «/./» и «%2e» по стандарту URL, а агенту никто не мешает прислать путь как есть
const rest = (g, p, { method = 'GET', headers = {}, body } = {}) => new Promise((ok, bad) => {
  const u = new URL(base);
  const h = { authorization: `Bearer ${g.token}`, ...headers };
  if (body) h['content-length'] = String(body.length);
  const req = http.request({ host: u.hostname, port: u.port, method, path: `/v1/proxy/bitrix24${p}`, headers: h, agent: false }, (res) => {
    const bufs = [];
    res.on('data', (c) => bufs.push(c));
    res.on('end', () => { const text = Buffer.concat(bufs).toString('utf8'); ok({ status: res.statusCode, json: async () => JSON.parse(text) }); });
  });
  req.on('error', bad);
  req.end(body);
});

/** Слушатели потока тела: чтение начинается только по start(). */
function track(body) {
  const t = { chunks: [], error: null };
  t.closed = new Promise((r) => body.once('close', r));
  body.on('error', (e) => { t.error = e; });
  t.first = new Promise((r) => { t.gotFirst = r; });
  t.ended = new Promise((r) => body.once('end', r));
  t.start = () => body.on('data', (c) => { t.chunks.push(c); t.gotFirst(); });
  t.text = () => Buffer.concat(t.chunks).toString('utf8');
  return t;
}
async function drain(body) { const t = track(body); t.start(); await t.closed; return t.text(); }

before(async () => {
  mock = http.createServer((req, res) => {
    const rec = { url: req.url, headers: req.headers, cancelled: false };
    seen.push(rec);
    rec.closedP = new Promise((r) => res.on('close', () => { rec.cancelled = !res.writableFinished; r(); }));
    req.resume();
    req.on('end', async () => {
      const mode = req.headers['x-mode'] || 'json';
      if (mode === 'slow') { res.writeHead(200, { 'content-type': 'text/plain' }); res.write(FIRST); holds.push(res); return; }
      if (mode === 'encoded') { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); res.end('x'); return; }
      if (mode === 'split') { res.writeHead(200, { 'content-type': 'text/plain' }); res.write('start 1/abc'); await new Promise((r) => setTimeout(r, 30)); res.end('def123456 end'); return; }
      if (mode === 'nonjson') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('hello'); return; }
      if (mode === 'big') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"result":"' + 'a'.repeat(MAX_BODY + 100) + '"}'); return; }
      if (mode === 'deals') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ result: [{ ID: '1', TITLE: 't', SECRET: 'x' }], total: 1 })); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, url: req.url }));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-pcore-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}`, [DEAD_HOST]: 'http://127.0.0.1:1' },
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
after(async () => { releaseAll(); await app.stop(); mock.close(); mock.closeAllConnections?.(); });

// ---- 5. REST и прямой call дают одинаковые коды ----

test('таблица кейсов: REST и proxy.call возвращают один статус и один код ошибки', async () => {
  const plain = await mkGrant();
  const flt = await mkGrant({ filter: FILTER });
  const big = Buffer.alloc(MAX_BODY + 1, 97);
  const cases = [
    { name: 'нормальный вызов', g: plain, path: '/crm.deal.list.json', status: 200 },
    { name: 'битый токен', g: { ...plain, token: plain.token.slice(0, -2) + 'xx' }, path: '/crm.deal.list.json', status: 401, error: 'invalid_grant' },
    { name: '«.»-сегмент', g: plain, path: '/./batch.json', status: 400, error: 'bad_path' },
    { name: 'двойное кодирование', g: plain, path: '/%2562atch.json', status: 400, error: 'bad_path' },
    { name: '«..» закодирован', g: plain, path: '/a/%2e%2e/b.json', status: 400, error: 'bad_path' },
    { name: 'query длиннее 4096', g: plain, path: '/crm.deal.list.json', query: '?x=' + 'a'.repeat(5000), status: 400, error: 'bad_query' },
    { name: 'закрытый метод', g: flt, path: '/crm.lead.list.json', status: 403, error: 'method_not_allowed' },
    { name: 'deny-метод фильтра', g: flt, path: '/batch.json', status: 403, error: 'method_not_allowed' },
    { name: 'тело больше maxBody', g: plain, method: 'POST', path: '/crm.deal.add', body: big, status: 413, error: 'body_too_large' },
    { name: 'разрешённый метод фильтра', g: flt, path: '/crm.deal.list.json', headers: { 'x-mode': 'deals' }, status: 200 },
    { name: 'сервис отдал сжатый ответ', g: plain, path: '/crm.deal.list.json', headers: { 'x-mode': 'encoded' }, status: 502, error: 'upstream_encoded' },
    { name: 'не JSON при фильтре', g: flt, path: '/crm.deal.list.json', headers: { 'x-mode': 'nonjson' }, status: 502, error: 'filtered_non_json' },
  ];
  for (const c of cases) {
    const method = c.method || 'GET';
    const headers = { ...(c.headers || {}) };
    if (c.body) headers['content-type'] = 'application/octet-stream';
    const r = await rest(c.g, c.path + (c.query || ''), { method, headers, body: c.body });
    const restJson = await r.json().catch(() => ({}));
    const res = await call(c.g, { method, path: c.path, query: c.query || '', headers, body: c.body || null, contentLength: c.body ? c.body.length : null });
    if (res.ok) await drain(res.body);
    assert.equal(r.status, c.status, `${c.name}: REST status`);
    assert.equal(res.status, c.status, `${c.name}: call status`);
    assert.equal(res.ok, c.status < 400, `${c.name}: ok`);
    assert.equal(restJson.error, c.error, `${c.name}: REST error`);
    assert.equal(res.error, c.error, `${c.name}: call error`);
  }
  releaseAll();
});

test('call: query с управляющими символами -> bad_query, секрет и сервис не затронуты', async () => {
  const g = await mkGrant();
  const n = seen.length;
  for (const query of ['?a=\u0001', '?a=\n', '?a=\u007f']) {
    const r = await call(g, { query });
    assert.deepEqual([r.ok, r.status, r.error], [false, 400, 'bad_query']);
  }
  assert.equal(seen.length, n);
  assert.equal(used(g), 0);
});

// ---- 6. порядок шагов ----

test('порядок: bad_path раньше фильтра, закрытый метод и 413 не тратят квоту, до сервиса не доходят', async () => {
  const g = await mkGrant({ filter: FILTER });
  const n = seen.length;
  // batch закрыт фильтром, но путь с «./» отвергается раньше
  assert.equal((await call(g, { path: '/./batch.json' })).error, 'bad_path');
  assert.equal((await call(g, { path: '/crm.lead.list.json' })).status, 403);
  // длина по contentLength: тело не читается вообще
  const unread = new Readable({ read() { throw new Error('тело не должно читаться'); } });
  const r = await call(g, { method: 'POST', path: '/crm.deal.list.json', body: unread, contentLength: MAX_BODY + 1 });
  assert.deepEqual([r.ok, r.status, r.error], [false, 413, 'body_too_large']);
  assert.equal(used(g), 0, 'квота не потрачена');
  assert.equal(inflight(g), 0);
  assert.equal(seen.length, n, 'сервис не вызывался');
});

test('порядок: rate_limited раньше фильтра и audit отказа', async () => {
  const g = await mkGrant({ filter: FILTER });
  const p = createProxy({ repo: app.repo, catalog: app.ctx.catalog, vault: app.ctx.vault, grants: app.ctx.grants, access: app.ctx.access, limits: { proxy: createLimiter({ limit: 1, windowSec: 60 }) }, logger: silent, testUpstream: null });
  const before = audits('proxy.denied').length;
  const ok = await call(g, {}, p);
  assert.equal(ok.ok, true); await drain(ok.body);
  const r = await call(g, { path: '/crm.lead.list.json' }, p);
  assert.deepEqual([r.ok, r.status, r.error], [false, 429, 'rate_limited']);
  assert.equal(audits('proxy.denied').length, before, 'отказ по фильтру не дошёл до audit');
});

// ---- 7. агрегация audit ----

test('1000 отказов по закрытому методу: одна запись proxy.denied, остальные в count следующей', async () => {
  const g = await mkGrant({ filter: FILTER });
  let t = 1_000_000;
  const p = createProxy({ repo: app.repo, catalog: app.ctx.catalog, vault: app.ctx.vault, grants: app.ctx.grants, access: app.ctx.access, limits: { proxy: createLimiter({ limit: 100000, windowSec: 60 }) }, logger: silent, now: () => t });
  const rows = () => audits('proxy.denied').filter((x) => JSON.parse(x.meta_json).agent === g.agentId);
  for (let i = 0; i < 1000; i++) assert.equal((await call(g, { path: '/crm.lead.list.json' }, p)).status, 403);
  assert.equal(rows().length, 1);
  assert.equal(used(g), 0);
  t += 61_000;
  await call(g, { path: '/crm.lead.list.json' }, p);
  const all = rows();
  assert.equal(all.length, 2);
  assert.equal(JSON.parse(all[0].meta_json).count, 999, 'пропущенные записи посчитаны');
});

// ---- 8. lease ----

test('lease: inflight=1 пока тело не дочитано, после конца потока 0', async () => {
  const g = await mkGrant();
  const r = await call(g, { headers: { 'x-mode': 'slow' } });
  assert.equal(r.ok, true);
  assert.equal(inflight(g), 1, 'тело не читали');
  const t = track(r.body); t.start();
  await t.first;
  assert.equal(inflight(g), 1, 'тело читается, но не закончено');
  releaseAll();
  await t.closed;
  assert.equal(t.text(), FIRST);
  assert.equal(inflight(g), 0);
});

test('lease: body.destroy() посреди потока освобождает слот и отменяет запрос к сервису', async () => {
  const g = await mkGrant();
  const n = seen.length;
  const r = await call(g, { headers: { 'x-mode': 'slow' } });
  const t = track(r.body); t.start();
  await t.first;
  r.body.destroy();
  await t.closed;
  assert.equal(inflight(g), 0);
  await seen[n].closedP;
  assert.equal(seen[n].cancelled, true, 'сервис увидел обрыв');
});

test('lease: signal.abort() освобождает слот и отменяет запрос к сервису', async () => {
  const g = await mkGrant();
  const n = seen.length;
  const ac = new AbortController();
  const r = await call(g, { headers: { 'x-mode': 'slow' }, signal: ac.signal });
  const t = track(r.body); t.start();
  await t.first;
  ac.abort();
  await t.closed;
  assert.ok(t.error, 'поток завершился ошибкой');
  assert.equal(inflight(g), 0);
  await seen[n].closedP;
  assert.equal(seen[n].cancelled, true);
});

test('lease: тело потеряно и не прочитано - слот освобождает дедлайн provider.timeout', async () => {
  const g = await mkGrant();
  const n = seen.length;
  const prov = app.ctx.catalog.get('bitrix24');
  const orig = prov.timeout;
  prov.timeout = 0.3;
  try {
    const r = await call(g, { headers: { 'x-mode': 'slow' } });
    assert.equal(r.ok, true);
    const t = track(r.body); // тело не читаем
    assert.equal(inflight(g), 1);
    await t.closed;
    assert.equal(inflight(g), 0);
    await seen[n].closedP;
    assert.equal(seen[n].cancelled, true);
  } finally { prov.timeout = orig; }
});

test('lease: ok:false после резерва освобождает слот (нет секрета, upstream_unreachable, upstream_encoded)', async () => {
  const noSecret = await mkGrant({ withSecret: false });
  let r = await call(noSecret);
  assert.deepEqual([r.ok, r.status, r.error], [false, 401, 'invalid_grant']);
  assert.equal(used(noSecret), 1, 'квота резервировалась');
  assert.equal(inflight(noSecret), 0);
  assert.ok(audits('proxy.no_secret').length >= 1);

  const dead = await mkGrant({ host: DEAD_HOST });
  r = await call(dead);
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'upstream_unreachable']);
  assert.equal(inflight(dead), 0);

  const enc = await mkGrant();
  r = await call(enc, { headers: { 'x-mode': 'encoded' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'upstream_encoded']);
  assert.equal(inflight(enc), 0);
});

test('lease: тело-поток больше maxBody без Content-Length -> 413 и слот свободен', async () => {
  const g = await mkGrant();
  const body = Readable.from([Buffer.alloc(MAX_BODY, 97), Buffer.alloc(10, 97)]);
  const r = await call(g, { method: 'POST', path: '/crm.deal.add', body, contentLength: null });
  assert.deepEqual([r.ok, r.status, r.error], [false, 413, 'body_too_large']);
  assert.equal(inflight(g), 0);
});

test('lease через REST: обрыв клиента посреди ответа освобождает слот и отменяет запрос к сервису', async () => {
  const g = await mkGrant();
  const n = seen.length;
  const u = new URL(base);
  const req = http.get({ host: u.hostname, port: u.port, path: '/v1/proxy/bitrix24/crm.deal.list.json', headers: { authorization: `Bearer ${g.token}`, 'x-mode': 'slow' }, agent: false });
  const res = await new Promise((ok, bad) => { req.on('response', ok); req.on('error', bad); });
  await new Promise((r) => res.once('data', r));
  assert.equal(inflight(g), 1);
  res.destroy();
  await seen[n].closedP;
  assert.equal(seen[n].cancelled, true);
  // слот снимается событием close потока: ждём его через сам сервис, который вернёт слот до нового резерва
  for (let i = 0; i < 200 && inflight(g) !== 0; i++) await new Promise((r) => setImmediate(r));
  assert.equal(inflight(g), 0);
});

// ---- 9. max_parallel ----

test('max_parallel: второй вызов при незакрытом теле первого - quota_exceeded, после destroy() проходит', async () => {
  const g = await mkGrant({ maxParallel: 1 });
  const first = await call(g, { headers: { 'x-mode': 'slow' } });
  assert.equal(first.ok, true);
  const second = await call(g);
  assert.deepEqual([second.ok, second.status, second.error], [false, 429, 'quota_exceeded']);
  const t = track(first.body);
  first.body.destroy();
  await t.closed;
  const third = await call(g);
  assert.equal(third.ok, true);
  await drain(third.body);
  assert.equal(inflight(g), 0);
});

// ---- 10. П-4, фильтр, редактор секрета ----

test('аудит proxy.call: via и session из input, без токена и секрета', async () => {
  const g = await mkGrant();
  const r = await call(g, { via: 'mcp', sessionTag: 'abcd1234' });
  await drain(r.body);
  const row = audits('proxy.call').map((x) => JSON.parse(x.meta_json)).find((m) => m.grant === g.id);
  assert.equal(row.via, 'mcp');
  assert.equal(row.session, 'abcd1234');
  assert.equal(row.status, 200);
  const raw = JSON.stringify(app.repo.listAudit({ limit: 5000 }));
  assert.ok(!raw.includes(g.token) && !raw.includes('abcdef123456'));
});

test('фильтр через call: только разрешённые поля, fields_removed, JSON-ответ целиком', async () => {
  const g = await mkGrant({ filter: FILTER });
  const r = await call(g, { headers: { 'x-mode': 'deals' } });
  assert.equal(r.ok, true);
  assert.equal(r.headers['content-type'], 'application/json; charset=utf-8');
  const text = await drain(r.body);
  assert.equal(Number(r.headers['content-length']), Buffer.byteLength(text));
  assert.deepEqual(JSON.parse(text).result, [{ ID: '1', TITLE: 't' }]);
  assert.equal(inflight(g), 0);
  const row = audits('proxy.call').map((x) => JSON.parse(x.meta_json)).find((m) => m.grant === g.id);
  assert.ok(row.fields_removed >= 1);
});

test('фильтр через call: filtered_non_json и filtered_too_large, слот свободен', async () => {
  const g = await mkGrant({ filter: FILTER });
  let r = await call(g, { headers: { 'x-mode': 'nonjson' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_non_json']);
  r = await call(g, { headers: { 'x-mode': 'big' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_too_large']);
  assert.equal(inflight(g), 0);
});

test('редактор секрета на границе чанков работает через call', async () => {
  const g = await mkGrant();
  const r = await call(g, { headers: { 'x-mode': 'split' } });
  const text = await drain(r.body);
  assert.ok(text.includes('****'), text);
  assert.ok(!text.includes('abcdef123456') && !text.includes('1/abc'), text);
  assert.equal(inflight(g), 0);
});

test('Buffer в качестве тела уходит как есть (транспорты без Readable, например MCP)', async () => {
  const g = await mkGrant();
  const n = seen.length;
  const r = await call(g, { method: 'POST', path: '/crm.deal.add', headers: { 'content-type': 'application/json' }, body: Buffer.from('{"a":1}') });
  assert.equal(r.ok, true);
  await drain(r.body);
  assert.equal(seen[n].headers['content-length'], '7');
});
