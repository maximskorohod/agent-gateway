// Защита слоя 1 (п. 7.2): readOnly и mask у любого сервиса (contracts/rest-demo-notify.md «Защита для всех сервисов»)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n, t } from '../src/i18n.js';
import { maskText, maskJson } from '../src/core/mask.js';
import { checkFilter, weakensFilter, normalizeFilter, defaultFilterFor, protectionOf, compileFilter } from '../src/core/filter.js';
import { parseFilter } from '../src/web/policy.js';
import { runAction, ACTIONS } from '../src/web/actions.js';

initI18n('en');

const HOSTS = { bitrix24: 'test.bitrix24.ru', hubspot: 'api.hubapi.com', telegram: 'api.telegram.org', openai: 'api.openai.com' };
const SECRETS = { bitrix24: '1/abcdef123456', hubspot: 'pat-na1-aaaabbbbcccc', telegram: '123456:AAEhBP0av28uDMNKyZAbcdefghijklmnopq', openai: 'sk-test-0123456789abcdefghij' };
const PHONE = '+7 (999) 123-45-67';
const MAIL = 'a.b@c.example';
const CARD = '4111 1111 1111 1111';
const IBAN = 'DE89 3704 0044 0532 0130 00';
const PII = {
  phone: PHONE, mail: MAIL, card: CARD, iban: IBAN, ms: '1699000000123', dt: '2026-11-03 12:00', n: 1234567890, bare: '1234567890',
  badCard: '4111 1111 1111 1112', badIban: 'DE89 3704 0044 0532 0130 01', note: `see ${SECRETS.hubspot} end`, list: [{ '+7 999 111-22-33': 'ключ не меняется' }],
};

let app, base, mock, seq = 0;
let seen = [];
const holds = [];
const nowSec = () => Math.floor(Date.now() / 1000);
const used = (g) => app.repo.getGrant(g.id).calls_used;
const inflight = (g) => app.repo.getGrant(g.id).inflight;
const audits = (action) => app.repo.listAudit({ limit: 5000 }).filter((x) => x.action === action).map((x) => ({ ...x, meta: JSON.parse(x.meta_json) }));

/** Новый агент + ключ провайдера + пропуск. */
async function mkGrant({ provider, filter = null, host = HOSTS[provider] } = {}) {
  const n = ++seq;
  const agentId = `l1ag${n}`; const credId = `l1kc${n}`;
  const p = app.ctx.catalog.get(provider);
  app.repo.createAgent({ id: agentId, name: `a${n}`, token_hash: crypto.createHash('sha256').update(`gwa_l1${n}`).digest('hex'), enabled: 1 });
  app.repo.createCredential({ id: credId, provider, label: `k${n}`, kind: p.kind, host, injection: p.injection, vault_param: `cred/${credId}`, last4: '3456', max_parallel: 3 });
  if (filter) app.repo.updateCredentialFilter(credId, filter);
  await app.ctx.vault.put(`cred/${credId}`, SECRETS[provider]);
  const req = { id: `l1rq${n}`, agent_id: agentId, credential_id: credId, ttl: 3000, calls: 100000, reason: '', expires_at: nowSec() + 3000 };
  app.repo.createRequest(req);
  const { grant, token } = app.ctx.grants.issue(req, app.repo.getCredential(credId));
  return { id: grant.id, token, agentId, credId, provider };
}
const call = (g, over = {}) => app.ctx.proxy.call({ token: g.token, provider: g.provider, method: 'GET', path: '/x', query: '', headers: {}, body: null, contentLength: null, via: 'rest', ...over });
async function drain(body) { const c = []; for await (const x of body) c.push(x); return Buffer.concat(c).toString('utf8'); }

// ---- owner-сайт (для проверки значений по умолчанию, формы и «было → стало»)
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
let csrfTok = '';
async function get(p) {
  const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r);
  if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; }
  return r;
}
async function post(p, fields) {
  const body = new URLSearchParams({ _csrf: csrfTok });
  for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r);
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}

before(async () => {
  mock = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, host: req.headers.host });
    req.resume();
    req.on('end', () => {
      const mode = req.headers['x-mode'] || 'json';
      if (mode === 'slow') { res.writeHead(200, { 'content-type': 'text/plain' }); res.write('first-' + 'x'.repeat(60)); holds.push(res); return; }
      if (mode === 'sse') { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write('data: hi\n\n'); holds.push(res); return; }
      if (mode === 'nonjson') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('hello'); return; }
      if (mode === 'pii') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(PII)); return; }
      if (mode === 'ten') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ v: 'a'.repeat(10000) })); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, url: req.url }));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-layer1-'));
  const up = `http://127.0.0.1:${mock.address().port}`;
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: Object.fromEntries(Object.values(HOSTS).map((h) => [h, up])),
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
after(async () => { while (holds.length) holds.pop().end(); await app.stop(); mock.close(); mock.closeAllConnections?.(); });

// ---- 1. readOnly на REST

test('1. readOnly REST: GET/HEAD проходят, запись — 403 write_not_allowed, лимит не списан, audit proxy.denied', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, readOnly: true } });
  const n = seen.length;
  for (const method of ['GET', 'HEAD']) {
    const r = await call(g, { method, path: '/crm/v3/objects/deals' });
    assert.equal(r.ok, true, method); await drain(r.body);
  }
  const usedOk = used(g);
  assert.equal(usedOk, 2);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const r = await call(g, { method, path: '/crm/v3/objects/deals', body: Buffer.from('{}') });
    assert.deepEqual([r.ok, r.status, r.error], [false, 403, 'write_not_allowed'], method);
  }
  assert.equal(used(g), usedOk, 'лимит не списан'); assert.equal(inflight(g), 0);
  assert.equal(seen.length, n + 2, 'до сервиса дошли только GET и HEAD');
  const den = audits('proxy.denied').filter((x) => x.meta.grant === g.id);
  assert.equal(den.length, 1, 'audit агрегируется'); assert.equal(den[0].meta.denied_reason, 'write_not_allowed');
});

test('1b. readOnly REST: POST поиска из extraRoutes каталога проходит, другие POST — нет; ответ приходит целиком (поток)', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, readOnly: true } });
  let r = await call(g, { method: 'POST', path: '/crm/v3/objects/deals/search', body: Buffer.from('{}') });
  assert.equal(r.ok, true); assert.match(await drain(r.body), /"ok":true/);
  r = await call(g, { method: 'POST', path: '/crm/v3/objects/deals/batch/create', body: Buffer.from('{}') });
  assert.equal(r.error, 'write_not_allowed');
  r = await call(g, { method: 'OPTIONS', path: '/crm/v3/objects/deals' });
  assert.equal(r.error, 'write_not_allowed');
});

test('1c. readOnly сильнее типов данных: фильтр включён, запись не открывается ни флагом, ни типом', () => {
  const p = app.ctx.catalog.get('bitrix24');
  const flt = compileFilter({ enabled: true, entities: { deals: ['result.ID'] }, methods: ['crm.deal.add'], fields: ['result.ID'], readOnly: true }, p);
  assert.equal(flt.allowMethod('crm.deal.list'), true);
  assert.equal(flt.allowMethod('crm.deal.add'), false, 'ручное правило записи закрыто');
  assert.equal(flt.denyReason('crm.deal.add'), 'write_not_allowed');
  assert.equal(flt.denyReason('crm.contact.get'), 'method_not_allowed', 'deny остаётся первым');
  assert.equal(compileFilter({ enabled: false }, p), null);
  assert.equal(compileFilter({ enabled: false, readOnly: true }, p).needsBuffer, false);
});

// ---- 2. readOnly на RPC

test('2. readOnly RPC: Bitrix24 crm.deal.list да, add/update/batch нет; Telegram getMe да, sendMessage/getUpdates нет', async () => {
  const b = await mkGrant({ provider: 'bitrix24', filter: { enabled: false, readOnly: true } });
  for (const p of ['/crm.deal.list.json', '/crm.deal.get', '/crm.lead.fields', '/user.get.json']) {
    const r = await call(b, { path: p }); assert.equal(r.ok, true, p); await drain(r.body);
  }
  const before = used(b);
  for (const p of ['/crm.deal.add.json', '/crm.deal.update', '/CRM.Deal.Delete', '/batch.json', '/crm.contact.add', '/crm.deal.list.extra']) {
    const r = await call(b, { method: 'POST', path: p, body: Buffer.from('{}') });
    assert.deepEqual([r.ok, r.status, r.error], [false, 403, 'write_not_allowed'], p);
  }
  // Bitrix24 принимает методы и через GET: HTTP-метод в rpc не помогает
  assert.equal((await call(b, { method: 'GET', path: '/crm.deal.add.json' })).error, 'write_not_allowed');
  assert.equal((await call(b, { path: '/./crm.deal.add.json' })).error, 'bad_path');
  assert.equal(used(b), before);

  const tg = await mkGrant({ provider: 'telegram', filter: { enabled: false, readOnly: true } });
  for (const p of ['/getMe', '/getChat', '/getChatMemberCount']) {
    const r = await call(tg, { method: 'POST', path: p, body: Buffer.from('{}') }); assert.equal(r.ok, true, p); await drain(r.body);
  }
  for (const p of ['/sendMessage', '/getUpdates', '/deleteMessage']) {
    const r = await call(tg, { method: 'POST', path: p, body: Buffer.from('{}') });
    assert.deepEqual([r.ok, r.error], [false, 'write_not_allowed'], p);
  }
});

// ---- 3. readOnly недоступен там, где запись неотличима от чтения

test('3. readOnly у OpenAI недоступен: сохранение формы с readOnly:true — ошибка', () => {
  const openai = app.ctx.catalog.get('openai');
  assert.deepEqual(protectionOf(openai), { readOnly: false, mask: false });
  const errors = checkFilter({ enabled: false, entities: {}, methods: [], fields: [], readOnly: true }, openai);
  assert.deepEqual(errors, [t('filter.err.read_only_unavailable')]);
  const next = parseFilter({ protect_form: '1', read_only: '1' }, openai, null);
  assert.equal(next.readOnly, true);
  assert.ok(checkFilter(next, openai).length);
  assert.deepEqual(checkFilter({ enabled: false, readOnly: true }, app.ctx.catalog.get('bitrix24')), []);
});

test('3b. через действие key.filter: OpenAI → ошибки, форма сервиса без типов данных и без readOnly не открывается', async () => {
  const g = await mkGrant({ provider: 'openai' });
  const ctx = { repo: app.repo, catalog: app.ctx.catalog, userId: 'owner', hasRecentTotp: true, notify: null };
  const r = runAction(ctx, 'key.filter', g.credId, { protect_form: '1', read_only: '1' });
  assert.ok(r.errors?.length); assert.equal(app.repo.getCredential(g.credId).filter, null);
  // HubSpot: readOnly и mask доступны без типов данных, включаются формой
  const gh = await mkGrant({ provider: 'hubspot' });
  const ok = runAction(ctx, 'key.filter', gh.credId, { protect_form: '1', read_only: '1', mask: '1' });
  assert.equal(ok.redirect, `/keys/${gh.credId}`);
  // у HubSpot с п. 7.3 есть тип данных «Deals»: фильтр полей выключен, но типы лежат в записи с полями по умолчанию
  assert.deepEqual(app.repo.getCredential(gh.credId).filter, { enabled: false, entities: { deals: app.ctx.catalog.get('hubspot').filter.entities.deals.defaults }, methods: [], fields: [], readOnly: true, mask: true });
});

// ---- 4-5. mask

test('4. mask при выключенном фильтре: телефон, e-mail, карта, IBAN → ****; ID, время, числа и ключи не тронуты', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, mask: true } });
  const r = await call(g, { path: '/crm/v3/objects/contacts', headers: { 'x-mode': 'pii' } });
  assert.equal(r.ok, true);
  const text = await drain(r.body);
  assert.equal(Number(r.headers['content-length']), Buffer.byteLength(text));
  const j = JSON.parse(text);
  assert.deepEqual([j.phone, j.mail, j.card, j.iban], ['****', '****', '****', '****']);
  assert.deepEqual([j.ms, j.dt, j.n, j.bare], ['1699000000123', '2026-11-03 12:00', 1234567890, '1234567890']);
  assert.deepEqual(Object.keys(j), Object.keys(PII), 'ключи не меняются');
  assert.deepEqual(j.list, [{ '+7 999 111-22-33': 'ключ не меняется' }], 'ключ с телефоном остался');
  const row = audits('proxy.call').find((x) => x.meta.grant === g.id);
  assert.equal(row.meta.masked, 4); assert.ok(!('fields_removed' in row.meta), 'фильтр полей выключен');
});

test('4b. maskText: примеры контракта и границы', () => {
  const m = (s) => maskText(s).text;
  assert.deepEqual([PHONE, MAIL, CARD, IBAN].map(m), ['****', '****', '****', '****']);
  assert.equal(m('call +79991234567, mail x@y.org.'), 'call ****, mail ****.');
  assert.equal(m('999 123 45 67'), '****');
  assert.equal(m('card 4111-1111-1111-1111 ok'), 'card **** ok');
  assert.equal(m('GB82WEST12345698765432'), '****');
  assert.equal(m('4111111111111111'), '****', 'голая карта с префиксом 2–6');
  for (const s of ['1699000000123', '1234567890', '2026-11-03 12:00', '2026-11-03', '12:30:45', '3.14159', '12345678901.50', 'a@b', '@@@', 'v1.2.3', 'x'.repeat(40)]) assert.equal(m(s), s, s);
  const r = maskJson({ a: [{ b: PHONE }, 5, null, true], c: { d: MAIL } });
  assert.deepEqual(r.json, { a: [{ b: '****' }, 5, null, true], c: { d: '****' } }); assert.equal(r.n, 2);
  // ключ __proto__ из ответа остаётся обычным полем
  const evil = maskJson(JSON.parse('{"__proto__":{"x":"+7 999 111-22-33"}}')).json;
  assert.equal(Object.getPrototypeOf(evil), Object.prototype); assert.deepEqual(Object.keys(evil), ['__proto__']);
});

test('5. Luhn-невалидные 16 цифр и IBAN с неверным mod-97 не маскируются', () => {
  assert.equal(maskText('4111 1111 1111 1112').text, '4111 1111 1111 1112');
  assert.equal(maskText('4111111111111112').text, '4111111111111112');
  assert.equal(maskText('DE89 3704 0044 0532 0130 01').text, 'DE89 3704 0044 0532 0130 01');
  assert.equal(maskText('DE89370400440532013001').text, 'DE89370400440532013001');
  assert.equal(maskText('DE89370400440532013000').text, '****');
});

// ---- 6. линейность

test('6. строки в 1 MiB «@@@@…» и «1 1 1 1 …» обрабатываются быстрее 200 мс; прочие тяжёлые вводы — линейно', () => {
  const MiB = 1 << 20;
  // лучший из трёх прогонов: набор идёт параллельно с другими файлами, разовый скачок нагрузки не должен ронять тест
  const timed = (s) => { let best = Infinity; let r; for (let i = 0; i < 3; i++) { const a = performance.now(); r = maskText(s); best = Math.min(best, performance.now() - a); } return [best, r]; };
  // линейность меряем отношением 1 MiB к 256 KiB (линейно ≈ 4, квадратично ≈ 16): абсолютный порог 200 мс мигал под нагрузкой набора;
  // одиночный прогон — около 50 мс, потолок 1 с ловит только явную деградацию
  for (const [unit, n] of [['@', MiB], ['1 ', MiB / 2]]) {
    const [small] = timed(unit.repeat(n / 4));
    const [ms, r] = timed(unit.repeat(n));
    assert.ok(ms < 1000, `${ms.toFixed(0)} мс`); assert.equal(r.n, 0);
    assert.ok(ms < Math.max(small, 5) * 8, `рост не линейный: ${small.toFixed(1)} → ${ms.toFixed(1)} мс`);
  }
  for (const s of ['a@'.repeat(MiB / 2), 'AB12 '.repeat(MiB / 5), '1-'.repeat(MiB / 2), '+7 '.repeat(MiB / 3), 'x.'.repeat(MiB / 2), '(1 '.repeat(MiB / 3), `${'a'.repeat(300)}@`.repeat(MiB / 301)]) {
    const [ms] = timed(s); assert.ok(ms < 1500, `${s.slice(0, 6)}: ${ms.toFixed(0)} мс`);
  }
});

// ---- 7. режимы ответа

test('7a. mask + не-JSON → 502 filtered_non_json; text/event-stream → 502 filtered_stream; слот свободен', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, mask: true } });
  let r = await call(g, { headers: { 'x-mode': 'nonjson' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_non_json']);
  r = await call(g, { headers: { 'x-mode': 'sse' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_stream']);
  assert.equal(inflight(g), 0);
});

test('7b. mask + ответ больше bufferMax → 502 filtered_too_large', async () => {
  const p = app.ctx.catalog.get('hubspot');
  p.bufferMax = 5000;
  try {
    const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, mask: true } });
    const r = await call(g, { headers: { 'x-mode': 'ten' } });
    assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_too_large']);
    assert.equal(inflight(g), 0);
    delete p.bufferMax;
    const ok = await call(g, { headers: { 'x-mode': 'ten' } });
    assert.equal(ok.ok, true); await drain(ok.body);
  } finally { delete p.bufferMax; }
});

test('7c. readOnly без mask: ответ идёт потоком, первый кусок приходит до завершения сервиса', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, readOnly: true } });
  const r = await call(g, { headers: { 'x-mode': 'slow' } });
  assert.equal(r.ok, true);
  const first = await new Promise((ok, bad) => { r.body.once('data', ok); r.body.once('error', bad); setTimeout(() => bad(new Error('нет первого куска')), 3000).unref(); });
  assert.match(first.toString(), /^first-/);
  assert.equal(inflight(g), 1, 'сервис ещё отвечает');
  r.body.destroy();
  await new Promise((ok) => setTimeout(ok, 50));
  assert.equal(inflight(g), 0);
  while (holds.length) holds.pop().end();
});

// ---- 8. секрет

test('8. секрет сервиса в ответе при mask всё равно редактируется после маскировки', async () => {
  const g = await mkGrant({ provider: 'hubspot', filter: { enabled: false, mask: true } });
  const r = await call(g, { headers: { 'x-mode': 'pii' } });
  const text = await drain(r.body);
  assert.ok(!text.includes(SECRETS.hubspot)); assert.equal(JSON.parse(text).note, 'see **** end');
});

// ---- значения по умолчанию, ослабление, форма, «было → стало»

test('умолчания каталога: CRM, Stripe и Twilio — readOnly сразу, остальные — нет; bitrix24-box наследует чтение', () => {
  const cat = app.ctx.catalog;
  for (const slug of ['bitrix24', 'bitrix24-box', 'amocrm', 'hubspot', 'pipedrive', 'zendesk', 'stripe', 'twilio']) assert.equal(defaultFilterFor(cat.get(slug))?.readOnly, true, slug);
  for (const slug of ['openai', 'github', 'telegram', 'other', 'notion']) assert.equal(defaultFilterFor(cat.get(slug)), null, slug);
  assert.deepEqual(['openai', 'anthropic', 'gemini', 'groq', 'mistral', 'openrouter', 'deepgram', 'elevenlabs'].map((s) => protectionOf(cat.get(s))), Array(8).fill({ readOnly: false, mask: false }));
  for (const slug of ['github', 'notion', 'stripe', 'other', 'telegram']) assert.equal(protectionOf(cat.get(slug)).readOnly, true, slug);
});

test('снятие readOnly или mask — ослабление, включение — нет; значения хранятся только включёнными', () => {
  const p = app.ctx.catalog.get('bitrix24');
  const on = normalizeFilter({ enabled: false, readOnly: true, mask: true }, p);
  assert.equal(weakensFilter(normalizeFilter({ enabled: false, mask: true }, p), on), true, 'снят readOnly');
  assert.equal(weakensFilter(normalizeFilter({ enabled: false, readOnly: true }, p), on), true, 'снят mask');
  assert.equal(weakensFilter(on, normalizeFilter({ enabled: false }, p)), false);
  assert.equal(weakensFilter(on, on), false);
  assert.equal('readOnly' in normalizeFilter({ enabled: false, readOnly: false }, p), false);
});

test('сайт: у нового ключа CRM readOnly включён, у OpenAI защиты нет; ослабление требует свежего кода; «было → стало»', async () => {
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  const secret = (await (await get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>/)[1];
  await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
  const policy = { mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' };
  // created_at с точностью до секунды: новый ключ — тот, которого не было раньше
  const known = new Set(app.repo.listCredentials().map((c) => c.id));
  const idOf = () => { const c = app.repo.listCredentials().find((x) => !known.has(x.id)); known.add(c.id); return c.id; };

  assert.match(await (await get('/keys/new/bitrix24')).text(), /name="read_only" value="1" checked/, 'форма нового ключа: чтение отмечено');
  assert.equal((await post('/keys/new/bitrix24', { webhook_url: `https://${HOSTS.bitrix24}/rest/1/abcdef123456/`, ...policy })).status, 302);
  const bx = idOf();
  assert.deepEqual(app.repo.getCredential(bx).filter, { enabled: false, entities: normalizeFilter(null, app.ctx.catalog.get('bitrix24')).entities, methods: [], fields: [], readOnly: true });
  assert.ok(audits('credential.create').some((x) => x.target === bx && x.meta.read_only === true));
  const page = await (await get(`/keys/${bx}`)).text();
  assert.match(page, /name="read_only" value="1" checked/); assert.match(page, /name="mask" value="1"(?! checked)/);
  assert.ok(!/<script(?![^>]*src=)/i.test(page), 'без inline-скриптов');

  // явный отказ от чтения при создании (protect_form без галочки) и сервис без readOnly
  assert.equal((await post('/keys/new/bitrix24', { webhook_url: `https://${HOSTS.bitrix24}/rest/2/abcdef654321/`, ...policy, protect_form: '1' })).status, 302);
  assert.equal(app.repo.getCredential(idOf()).filter, null);
  assert.equal((await post('/keys/new/openai', { key: SECRETS.openai, ...policy })).status, 302);
  const oa = idOf();
  assert.equal(app.repo.getCredential(oa).filter, null);
  assert.ok(!/name="read_only"|name="mask"|protect_form/.test(await (await get(`/keys/${oa}`)).text()), 'у OpenAI защиты нет');
  // pipedrive: нет типов данных, но чтение по умолчанию есть
  assert.equal((await post('/keys/new/pipedrive', { key: 'abcdef0123456789', ...policy })).status, 302);
  const pd = idOf();
  assert.equal(app.repo.getCredential(pd).filter.readOnly, true);
  assert.match(await (await get(`/keys/${pd}`)).text(), /name="read_only" value="1" checked/);

  // включить mask (усиление) — без кода; снять readOnly — на ввод кода, фильтр не меняется
  app.db.prepare('UPDATE sessions SET totp_at = totp_at - 3600').run();
  let r = await post(`/keys/${bx}/filter`, { protect_form: '1', read_only: '1', mask: '1', entities_form: '1' });
  assert.equal(r.headers.get('location'), `/keys/${bx}`);
  assert.deepEqual([app.repo.getCredential(bx).filter.readOnly, app.repo.getCredential(bx).filter.mask], [true, true]);
  r = await post(`/keys/${bx}/filter`, { protect_form: '1', mask: '1', entities_form: '1' });
  assert.match(r.headers.get('location'), /^\/totp/, 'снять readOnly — свежий 2FA');
  assert.equal(app.repo.getCredential(bx).filter.readOnly, true);
  r = await post(`/keys/${pd}/filter`, { protect_form: '1' });
  assert.match(r.headers.get('location'), /^\/totp/, 'без entities_form тоже');
  assert.equal(app.repo.getCredential(pd).filter.readOnly, true);
  r = await post(`/keys/${bx}/filter`, { protect_form: '1', read_only: '1', entities_form: '1' });
  assert.match(r.headers.get('location'), /^\/totp/, 'снять mask — тоже ослабление');
  assert.equal(app.repo.getCredential(bx).filter.mask, true);
  // со свежим кодом снятие применяется
  app.db.prepare('UPDATE sessions SET totp_at = unixepoch()').run();
  r = await post(`/keys/${bx}/filter`, { protect_form: '1', read_only: '1', entities_form: '1' });
  assert.equal(r.headers.get('location'), `/keys/${bx}`);
  assert.deepEqual([app.repo.getCredential(bx).filter.readOnly, app.repo.getCredential(bx).filter.mask], [true, undefined]);
  // форма только с защитой (у сервиса нет типов данных) оставляет выключатель фильтра как есть
  r = await post(`/keys/${pd}/filter`, { protect_form: '1', read_only: '1', mask: '1' });
  assert.equal(app.repo.getCredential(pd).filter.enabled, false);
  assert.equal(app.repo.getCredential(pd).filter.mask, true);
});

test('«было → стало»: черновик показывает readOnly и mask', () => {
  const bx = app.repo.listCredentials().find((c) => c.provider === 'bitrix24' && c.filter?.readOnly);
  const ctx = { repo: app.repo, catalog: app.ctx.catalog };
  const next = { ...normalizeFilter(bx.filter, app.ctx.catalog.get('bitrix24')) };
  delete next.readOnly;
  const s = ACTIONS['key.filter'].summary(ctx, bx.id, { next });
  assert.equal(s.before[t('pending.f.read_only')], t('pending.yes'));
  assert.equal(s.after[t('pending.f.read_only')], t('pending.no'));
});
