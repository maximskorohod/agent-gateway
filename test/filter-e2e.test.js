// Фильтр данных сквозь шлюз (ТЗ v1.3 §11): ключ Bitrix24 → пропуск → mock-портал → что видит агент
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';
import { gzipSync } from 'node:zlib';

initI18n('ru');

const HOST = 'test.bitrix24.ru';
const HOOK = 'abcdef123456';
const PHONE = '+7 999 777-01-02';
const DEALS = { result: [{ ID: '1', TITLE: 'Окна', COMMENTS: 'перезвонить', STAGE_ID: 'NEW', NAME: 'Иван', PHONE: [{ VALUE: PHONE }] }], total: 1, time: { start: 1 } };
let app, base, mock, seen = [];
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
// CSRF-токен берётся из последней показанной формы (в cookie он не хранится, П-22)
let csrfTok = '';
async function grabCsrf(r) { if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; } }
async function get(p) { const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r); await grabCsrf(r); return r; }
async function post(p, fields) {
  const body = new URLSearchParams({ _csrf: csrfTok });
  for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r);
  // сессия сменилась (вход): токен меняется вместе с ней, берём из следующей страницы
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}
let grant, credId, agentToken, totpSecret;
// TOTP одноразовый, шлюз принимает шаг ±1: мастер взял текущий шаг, тестам остаются следующий и предыдущий
const spare = [1, -1];
const freshCode = () => totpAt(totpSecret, Math.floor(Date.now() / 30000) + spare.shift());
const call = (p, opts = {}) => fetch(`${base}/v1/proxy/bitrix24/${p}`, { ...opts, headers: { authorization: `Bearer ${grant}`, ...(opts.headers || {}) } });
const used = () => app.repo.getGrant(app.repo.listActiveGrants()[0].id).calls_used;

before(async () => {
  mock = http.createServer((req, res) => {
    let data = ''; req.on('data', (c) => (data += c));
    req.on('end', () => {
      seen.push({ url: req.url, body: data });
      if (req.url.includes('crm.deal.get')) { res.setHeader('content-type', 'text/xml'); return res.end(`<deal><PHONE>${PHONE}</PHONE></deal>`); }
      // сервис игнорирует accept-encoding: identity и сжимает ответ (П-4)
      if (req.url.includes('gz=1')) { res.setHeader('content-type', 'application/json'); res.setHeader('content-encoding', 'gzip'); return res.end(gzipSync(JSON.stringify({ hook: HOOK, ...DEALS }))); }
      // слишком вложенный ответ (П-28): 33 уровня
      if (req.url.includes('deep=1')) { res.setHeader('content-type', 'application/json'); return res.end('['.repeat(33) + ']'.repeat(33)); }
      // медленный поток: ответ идёт дольше, чем возвращается reply.send (П-11)
      // первый кусок длинный: маскировщик секрета придерживает только хвост длиной с секрет
      if (req.url.includes('slow=1')) { res.setHeader('content-type', 'application/json'); res.write(`{"pad":"${'x'.repeat(4096)}","result":[`); return setTimeout(() => res.end(']}'), 400); }
      if (req.url.includes('crm.lead.list')) { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ result: [{ COMMENTS: 'x'.repeat(3 * 1024 * 1024) }] })); }
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(DEALS));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-filter-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'ru', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` } });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  // мастер: пароль, код, без Telegram
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  const secret = (await (await get('/setup')).text()).match(/Ключ вручную: <code>([A-Z2-7]+)<\/code>/)[1];
  totpSecret = secret;
  await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
  // ключ Bitrix24, агент, заявка, одобрение
  const r = await post('/keys/new/bitrix24', { webhook_url: `https://${HOST}/rest/1/${HOOK}/`, mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2', protect_form: '1' }); // protect_form без галочек: readOnly выключен
  assert.equal(r.status, 302);
  credId = app.repo.listCredentials()[0].id;
  agentToken = (await (await post('/agents', { name: 'аналитик' })).text()).match(/gwa_[A-Za-z0-9_-]+/)[0];
  const a = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 600, calls: 50, reason: 'сделки' }) });
  const { request_id } = await a.json();
  await post(`/requests/${request_id}/approve`, {});
  grant = (await (await fetch(`${base}/v1/grants/${request_id}`, { headers: { authorization: `Bearer ${agentToken}` } })).json()).token;
});
after(async () => { await app.stop(); mock.close(); });

test('фильтр выключен: ответ как в v1.2, целиком', async () => {
  const r = await call('crm.deal.list.json');
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), DEALS);
  assert.match(seen.at(-1).url, new RegExp(`^/rest/1/${HOOK}/crm\\.deal\\.list\\.json`));
  assert.match(await (await get(`/keys/${credId}`)).text(), /Что видит агент/);
});

test('П-11: слот параллельности занят до конца потока, а не до начала отправки', async () => {
  const g = app.repo.listActiveGrants()[0].id;
  const r = await call('crm.deal.list.json?slow=1');
  assert.equal(r.status, 200);
  assert.equal(app.repo.getGrant(g).inflight, 1, 'поток ещё идёт');
  assert.deepEqual(JSON.parse(await r.text()).result, []);
  await new Promise((ok) => setTimeout(ok, 50));
  assert.equal(app.repo.getGrant(g).inflight, 0, 'поток закончился — слот свободен');
});

test('П-1: «.»-сегменты и двойное кодирование в пути — 400, до сервиса не доходит', async () => {
  // fetch схлопывает %2e и «//» по стандарту URL, агенту никто не мешает послать путь как есть
  const raw = (p) => new Promise((ok, fail) => {
    const u = new URL(base);
    http.get({ host: u.hostname, port: u.port, path: `/v1/proxy/bitrix24/${p}`, headers: { authorization: `Bearer ${grant}` } }, (res) => { res.resume(); res.on('end', () => ok(res.statusCode)); }).on('error', fail);
  });
  const n = seen.length;
  for (const p of ['%2e/batch.json', 'x/%2e/crm.contact.list.json', '%2562atch.json', 'a//batch.json', './batch.json']) {
    assert.equal(await raw(p), 400, p);
  }
  assert.equal(seen.length, n);
});

const DEAL_FORM = { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID', 'result.TITLE', 'result.COMMENTS', 'result.STAGE_ID'] };

test('включение фильтра «только сделки» без свежего кода', async () => {
  app.db.prepare('UPDATE sessions SET totp_at = totp_at - 3600').run();
  const page = await (await get(`/keys/${credId}`)).text();
  assert.match(page, /name="ent_leads"/); assert.match(page, /name="f_deals" value="result.MOVED_TIME" checked/, 'галочки видны до включения');
  const r = await post(`/keys/${credId}/filter`, DEAL_FORM);
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), `/keys/${credId}`, 'ужесточение — без кода');
  const f = app.repo.getCredential(credId).filter;
  assert.equal(f.enabled, true); assert.deepEqual(Object.keys(f.entities), ['deals']);
  assert.ok(app.repo.listAudit({ limit: 5 }).some((x) => x.action === 'filter.changed'));
});

test('закрытый метод: 403, сервис не вызван, лимит не тронут', async () => {
  const before = used(); const n = seen.length;
  for (const m of ['crm.contact.get.json?id=7', 'batch.json', 'crm.deal.update.json', 'CRM.Contact.List']) {
    const r = await call(m);
    assert.equal(r.status, 403, m);
    const j = await r.json(); assert.equal(j.error, 'method_not_allowed'); assert.ok(j.allowed.includes('crm.deal.list'));
  }
  assert.equal(seen.length, n, 'до сервиса не дошло'); assert.equal(used(), before);
  assert.ok(app.repo.listAudit({ limit: 10 }).some((x) => x.action === 'proxy.denied'));
});

test('список сделок: только разрешённые поля, select подменён, значения не в журнале', async () => {
  const r = await call('crm.deal.list.json?select[]=PHONE&select[]=NAME&start=0');
  assert.equal(r.status, 200);
  const text = await r.text();
  assert.deepEqual(JSON.parse(text), { result: [{ ID: '1', TITLE: 'Окна', COMMENTS: 'перезвонить', STAGE_ID: 'NEW' }], total: 1, time: { start: 1 } });
  assert.ok(!text.includes(PHONE) && !text.includes('Иван'));
  const q = new URLSearchParams(seen.at(-1).url.split('?')[1]);
  assert.ok(!q.getAll('select[]').includes('PHONE')); assert.ok(q.getAll('select[]').includes('COMMENTS')); assert.equal(q.get('start'), '0');
  const audit = app.repo.listAudit({ limit: 20 });
  const last = audit.find((x) => x.action === 'proxy.call');
  assert.equal(JSON.parse(last.meta_json).fields_removed, 2);
  assert.ok(!JSON.stringify(audit).includes(PHONE) && !JSON.stringify(audit).includes(HOOK));
});

test('POST с JSON: select в теле заменён, остальное тело не тронуто', async () => {
  const r = await call('crm.deal.list.json', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ select: ['PHONE', 'NAME'], filter: { '>ID': 5 } }) });
  assert.equal(r.status, 200);
  const sent = JSON.parse(seen.at(-1).body);
  assert.ok(!sent.select.includes('PHONE')); assert.ok(sent.select.includes('COMMENTS')); assert.deepEqual(sent.filter, { '>ID': 5 });
});

test('не-JSON и слишком большой ответ: 502, тело сервиса не отдано', async () => {
  let r = await call('crm.deal.get.json?id=1');
  assert.equal(r.status, 502); const t = await r.text(); assert.match(t, /filtered_non_json/); assert.ok(!t.includes(PHONE));
  // открыть лиды — это ослабление, нужен свежий код
  app.db.prepare('UPDATE sessions SET totp_at = unixepoch()').run();
  r = await post(`/keys/${credId}/filter`, { ...DEAL_FORM, ent_leads: '1', f_leads: ['result.ID', 'result.COMMENTS'] }); assert.equal(r.status, 302);
  assert.deepEqual(Object.keys(app.repo.getCredential(credId).filter.entities), ['deals', 'leads']);
  r = await call('crm.lead.list.json');
  assert.equal(r.status, 502); assert.match(await r.text(), /filtered_too_large/);
});

test('нельзя разрешить batch и контакты; ослабление без свежего кода — на ввод кода', async () => {
  const cur = app.repo.getCredential(credId).filter;
  const form = { ...DEAL_FORM, ent_leads: '1', f_leads: cur.entities.leads };
  let r = await post(`/keys/${credId}/filter`, { ...form, methods: 'crm.status.list\nbatch', fields_extra: 'result.ID' });
  assert.equal(r.status, 302);
  assert.deepEqual(app.repo.getCredential(credId).filter, cur, 'фильтр не изменился');
  assert.match(await (await get(`/keys/${credId}`)).text(), /закрыт всегда/);
  app.db.prepare('UPDATE sessions SET totp_at = totp_at - 3600').run();
  r = await post(`/keys/${credId}/filter`, { ...form, f_leads: [...cur.entities.leads, 'result.PHONE'] });
  assert.match(r.headers.get('location'), /^\/totp/);
  r = await post(`/keys/${credId}/filter`, {});
  assert.match(r.headers.get('location'), /^\/totp/, 'выключение — тоже ослабление');
  assert.deepEqual(app.repo.getCredential(credId).filter, cur);
});

test('П-4: сжатый ответ сервиса — 502 без тела, секрет не уходит', async () => {
  const r = await call('crm.deal.list.json?gz=1');
  assert.equal(r.status, 502);
  const t = await r.text();
  assert.match(t, /upstream_encoded/); assert.ok(!t.includes(HOOK));
  assert.equal(r.headers.get('content-encoding'), null);
});

/** Новая заявка агента к ключу; ключ переведён на «код на сайте» с меньшим сроком пропуска. */
async function codeRequest() {
  app.db.prepare("UPDATE credentials SET approval = 'web_code', max_ttl = 300, max_calls = 7 WHERE id = ?").run(credId);
  const a = await fetch(`${base}/v1/grants`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 300, calls: 7, reason: 'код' }) });
  const { request_id } = await a.json();
  // лимит ключа уменьшили, пока заявка ждала (П-5)
  app.db.prepare('UPDATE credentials SET max_ttl = 120, max_calls = 3 WHERE id = ?').run(credId);
  return request_id;
}

test('П-5, П-6: заявку с кодом одобряет только код; GET ничего не меняет; лимиты по текущему ключу', async () => {
  app.db.prepare('UPDATE sessions SET totp_at = unixepoch()').run(); // свежий вход не заменяет код заявки
  const id = await codeRequest();
  let r = await post(`/requests/${id}/approve`, {});
  assert.equal(r.headers.get('location'), `/requests/${id}/approve-confirm`);
  r = await get(`/requests/${id}/approve-confirm`);
  assert.equal(r.status, 200); assert.match(await r.text(), new RegExp(`/requests/${id}/approve-code`));
  assert.equal(app.repo.getRequest(id).status, 'pending', 'GET не одобряет');
  r = await post(`/requests/${id}/approve-code`, { code: '000000' });
  assert.match(r.headers.get('location'), /e=code/);
  assert.equal(app.repo.getRequest(id).status, 'pending');
  r = await post(`/requests/${id}/approve-code`, { code: freshCode() });
  assert.equal(app.repo.getRequest(id).status, 'approved');
  const g = app.repo.listActiveGrants().find((x) => x.request_id === id);
  assert.equal(g.max_calls, 3); assert.ok(g.expires_at - g.created_at <= 120);
});

test('П-7: секрет перевыпуска 2FA и резервные коды видит и подтверждает только начавшая сессия', async () => {
  app.db.prepare('UPDATE sessions SET totp_at = unixepoch()').run();
  await post('/settings/2fa/reissue', {});
  const mine = (await (await get('/settings')).text()).match(/<code>([A-Z2-7]{16,})<\/code>/);
  assert.ok(mine, 'своя сессия видит новый секрет');
  assert.equal(app.repo.getMeta('reissue_totp_secret') || '', '', 'в общем meta открытого секрета нет');
  // вторая сессия того же владельца
  const jarA = new Map(jar); jar.clear();
  await get('/login');
  await post('/login', { password: 'correct-horse-battery' });
  await post('/totp', { code: freshCode(), next: '/' });
  const other = await (await get('/settings')).text();
  assert.ok(!other.includes(mine[1]), 'чужая сессия секрет не видит');
  await post('/settings/2fa/confirm', { code: totpAt(mine[1], Math.floor(Date.now() / 30000)) });
  const o = app.repo.getOwner();
  jar.clear(); for (const [k, v] of jarA) jar.set(k, v);
  await get('/settings'); // токен вернувшейся сессии
  assert.equal(app.repo.getOwner().totp_secret_enc, o.totp_secret_enc);
  assert.ok(!app.repo.listAudit({ limit: 10 }).some((x) => x.action === 'totp.reissue'), 'перевыпуск из чужой сессии не прошёл');
});

test('П-9: ошибки кода заявки копятся, а не сбрасываются; после 5 ошибок верный код не принимается', async () => {
  const id = await codeRequest();
  for (let i = 0; i < 5; i++) await post(`/requests/${id}/approve-code`, { code: String(100000 + i) });
  const ok = await app.ctx?.verifyTotp?.('123456');
  assert.equal(ok ?? false, false);
  const r = await post(`/requests/${id}/approve-code`, { code: totpAt(totpSecret, Math.floor(Date.now() / 30000)) });
  assert.match(r.headers.get('location'), /e=locked/);
  assert.equal(app.repo.getRequest(id).status, 'pending');
});

test('П-26/П-28 сквозь шлюз: select в нестандартной форме заменён, неизвестное тело — 400, глубокий ответ — 502', async () => {
  let r = await call('crm.deal.list.json?SELECT=PHONE&Select[0]=NAME');
  assert.equal(r.status, 200);
  const q = new URLSearchParams(seen.at(-1).url.split('?')[1]);
  assert.deepEqual([...q.keys()].filter((k) => /^select/i.test(k)).filter((k) => k !== 'select[]'), []);
  assert.ok(!q.getAll('select[]').includes('PHONE'));
  const n = seen.length;
  r = await call('crm.deal.list.json', { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: 'select=PHONE' });
  assert.equal(r.status, 400); assert.match(await r.text(), /body_not_allowed/);
  assert.equal(seen.length, n, 'до сервиса не дошло');
  r = await call('crm.deal.list.json?deep=1');
  assert.equal(r.status, 502); assert.match(await r.text(), /filtered_too_deep/);
});
