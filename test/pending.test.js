// Черновики 2FA (П-19): контрактные тесты 1-15 из docs/contracts/drafts-team-auth.md.
// Тест 10 (понижение роли до viewer) N/A: таблицы users и ролей в этом этапе нет (6.4); проверяется аналог для одного владельца.
// Без сети: vault file, ключи создаются в базе, апстрим не вызывается.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { createPending, PENDING_TTL } from '../src/web/pending.js';
import { ACTIONS } from '../src/web/actions.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ALLOWED_POLICY = ['label', 'mode', 'always_for', 'approval', 'max_ttl', 'max_calls', 'max_parallel', 'days', 'from', 'to', 'expires_at', 'confirm_sensitive'];
const WEAKER = { mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '5000', max_parallel: '2' };

let app, base, tpl, totpSecret;
const usedSteps = new Set();
function freshCode() {
  const s = Math.floor(Date.now() / 30000);
  const step = [s, s - 1, s + 1].find((x) => !usedSteps.has(x));
  assert.ok(step !== undefined, 'нет свободного шага TOTP');
  usedSteps.add(step);
  return totpAt(totpSecret, step);
}

function client() {
  const jar = new Map();
  const c = { jar, token: '' };
  const store = (res) => {
    for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' });
    store(r);
    const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/);
    if (m) c.token = m[1];
    return r;
  };
  c.post = async (p, fields = {}, { token = c.token } = {}) => {
    const body = new URLSearchParams();
    if (token !== null) body.append('_csrf', token);
    for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
    store(r);
    return r;
  };
  c.hash = () => sha256(jar.get('gw_sid'));
  return c;
}

/** Полная сессия по ссылке мастера, код «свежий». */
async function session() {
  app.db.exec('DELETE FROM pending_actions'); // каждый тест начинает с пустой таблицы черновиков
  const c = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  assert.equal((await c.get(`/setup/${token}`)).status, 302);
  await c.get('/');
  assert.ok(c.token, 'csrf-токен получен');
  return c;
}
const setTotpAt = (c, v) => app.db.prepare('UPDATE sessions SET totp_at = ? WHERE id_hash = ?').run(v, c.hash());
const makeStale = (c) => setTotpAt(c, 1000);
const makeFresh = (c) => setTotpAt(c, Math.floor(Date.now() / 1000));
const rows = () => app.db.prepare('SELECT * FROM pending_actions').all();
const idOf = (r) => { assert.equal(r.status, 302); const m = r.headers.get('location').match(/^\/totp\?next=\/pending\/([A-Za-z0-9_-]{22})$/); assert.ok(m, 'Location ' + r.headers.get('location')); return m[1]; };
const audits = (action) => app.repo.listAudit({ limit: 200 }).filter((a) => a.action === action);

let n = 0;
/** Новый ключ в базе (копия шаблона, созданного через форму). */
function mkKey(extra = {}) {
  const id = crypto.randomBytes(8).toString('base64url');
  app.repo.createCredential({ ...tpl, id, label: `key-${++n}`, ...extra });
  return id;
}
/** Сессия в базе без HTTP и контекст действия для прямых вызовов модуля. */
function rawSession() { const h = crypto.randomBytes(16).toString('hex'); app.repo.createSession(h, Math.floor(Date.now() / 1000) + 3600, 'test'); return h; }
const mkCtx = (sessionHash, over = {}) => ({
  userId: 'owner', user: { id: 'owner', role: 'owner' }, sessionHash, hasRecentTotp: true, repo: app.repo, catalog: app.ctx.catalog,
  csrf: '', telegramConnected: false, now: () => 0, ...over,
});
let clock = 0;
const pend = () => createPending({ repo: app.repo, now: () => clock });
const resetClock = () => { clock = Math.floor(Date.now() / 1000); };

before(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-pending-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const a = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await a.get(`/setup/${token}`); await a.get('/setup');
  await a.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  totpSecret = (await (await a.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  const step0 = Math.floor(Date.now() / 30000);
  usedSteps.add(step0);
  await a.post('/setup', { step: '2', code: totpAt(totpSecret, step0) });
  await a.post('/setup', { step: '3', mode: 'skip' });
  const r = await a.post('/keys/new/bitrix24', { webhook_url: 'https://test.bitrix24.ru/rest/1/abcdef123456/', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' });
  assert.equal(r.status, 302);
  tpl = app.repo.listCredentials()[0];
  assert.equal(tpl.max_calls, 100);
});
after(async () => { await app.stop(); });

test('1: ослабление политики без свежего кода сохраняется черновиком и ведёт на /totp?next=/pending/<id>', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  const r = await c.post(`/keys/${id}/policy`, { ...WEAKER, foo: 'junk', label: 'new name' });
  const pid = idOf(r);
  const all = rows();
  assert.equal(all.length, 1);
  assert.equal(all[0].id, pid); assert.equal(all[0].type, 'key.policy'); assert.equal(all[0].target_id, id);
  assert.equal(all[0].session_hash, c.hash());
  const body = JSON.parse(all[0].body_json);
  assert.ok(Object.keys(body).length > 0 && Object.keys(body).every((k) => ALLOWED_POLICY.includes(k)), JSON.stringify(body));
  assert.ok(!('_csrf' in body) && !('foo' in body));
  assert.equal(app.repo.getCredential(id).max_calls, 100, 'ключ не изменён');
  assert.equal(audits('pending.saved').at(0).target, id);
  assert.ok(!JSON.stringify(audits('pending.saved')).includes('5000'), 'значений в pending.saved нет');
  assert.match(await (await c.get(r.headers.get('location'))).text(), /saved as a draft/);
});

test('2: после верного кода страница показывает «было → стало» без записи; POST apply применяет (via draft)', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  const pid = idOf(await c.post(`/keys/${id}/policy`, WEAKER));
  // без свежего кода страница отправляет на ввод кода
  let r = await c.get(`/pending/${pid}`);
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), `/totp?next=/pending/${pid}`);
  // настоящий код через /totp: возврат на /pending/<id>
  r = await c.post('/totp', { code: freshCode(), next: `/pending/${pid}` });
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), `/pending/${pid}`);
  const before = JSON.stringify(app.repo.getCredential(id));
  r = await c.get(`/pending/${pid}`);
  assert.equal(r.status, 200);
  const page = await r.text();
  assert.match(page, /Will be/); assert.match(page, /<td data-label="Now">100<\/td><td data-label="Will be"><strong>5000<\/strong><\/td>/, 'было 100, стало 5000');
  assert.match(page, new RegExp(`action="/pending/${pid}/apply"`)); assert.match(page, new RegExp(`action="/pending/${pid}/cancel"`));
  assert.doesNotMatch(page, /<script[^>]*>[^<]/, 'инлайн-скриптов нет');
  assert.equal(JSON.stringify(app.repo.getCredential(id)), before, 'GET состояние не меняет');
  assert.equal(rows().length, 1);
  r = await c.post(`/pending/${pid}/apply`);
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), `/keys/${id}`);
  assert.equal(app.repo.getCredential(id).max_calls, 5000);
  assert.equal(rows().length, 0);
  const a = audits('credential.policy').find((x) => x.target === id);
  assert.equal(JSON.parse(a.meta_json).via, 'draft');
  assert.ok(audits('pending.applied').some((x) => x.target === id));
});

test('3: filter: галочки типов, сохранённые до кода, совпадают после применения', async () => {
  const c = await session();
  const id = mkKey();
  app.repo.updateCredentialFilter(id, { enabled: true, entities: { deals: ['result.ID'] }, methods: [], fields: [] });
  makeStale(c);
  const form = { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID', 'result.TITLE'], ent_leads: '1', f_leads: ['result.ID', 'result.COMMENTS'], x_leads: 'result.NOTE' };
  const pid = idOf(await c.post(`/keys/${id}/filter`, form));
  assert.deepEqual(app.repo.getCredential(id).filter.entities, { deals: ['result.ID'] }, 'до кода без изменений');
  makeFresh(c);
  assert.equal((await c.get(`/pending/${pid}`)).status, 200);
  const r = await c.post(`/pending/${pid}/apply`);
  assert.equal(r.headers.get('location'), `/keys/${id}`);
  assert.deepEqual(app.repo.getCredential(id).filter.entities, { deals: ['result.ID', 'result.TITLE'], leads: ['result.ID', 'result.COMMENTS', 'result.NOTE'] });
  assert.equal(JSON.parse(audits('filter.changed').find((x) => x.target === id).meta_json).via, 'draft');
});

test('4: повтор apply даёт «gone» без второго audit; два параллельных apply (agent.create) дают одного агента', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  const pid = idOf(await c.post(`/keys/${id}/policy`, WEAKER));
  makeFresh(c);
  assert.equal((await c.post(`/pending/${pid}/apply`)).headers.get('location'), `/keys/${id}`);
  const n1 = audits('credential.policy').filter((x) => x.target === id).length;
  const again = await c.post(`/pending/${pid}/apply`);
  assert.equal(again.status, 302); assert.equal(again.headers.get('location'), '/');
  assert.match(await (await c.get('/')).text(), /no longer available/);
  assert.equal(audits('credential.policy').filter((x) => x.target === id).length, n1, 'второго audit нет');

  // два параллельных apply на агенте
  makeStale(c);
  const aid = idOf(await c.post('/agents', { name: 'twin' }));
  makeFresh(c);
  const [r1, r2] = await Promise.all([c.post(`/pending/${aid}/apply`), c.post(`/pending/${aid}/apply`)]);
  assert.deepEqual([r1.status, r2.status].sort(), [200, 302], 'ровно один успех');
  const okRes = r1.status === 200 ? r1 : r2;
  assert.match(await okRes.text(), /gwa_[A-Za-z0-9_-]+/, 'токен показан один раз');
  assert.equal(app.repo.listAgents().filter((a) => a.name === 'twin').length, 1);
  assert.equal(audits('agent.create').filter((a) => JSON.parse(a.meta_json).name === 'twin').length, 1);
  assert.ok(!app.db.prepare('SELECT body_json FROM pending_actions').all().length, 'после применения записей нет');
});

test('agent.create: тело в базе без токена и без полей формы keys; привязка сохраняется', async () => {
  const c = await session(); makeStale(c);
  const k1 = mkKey(); mkKey();
  const pid = idOf(await c.post('/agents', { name: 'bound', keys_all: '0', keys: [k1] }));
  const row = rows()[0];
  assert.deepEqual(JSON.parse(row.body_json), { name: 'bound', all: '0', ids: [k1] });
  assert.doesNotMatch(row.body_json, /gwa_/);
  makeFresh(c);
  const page = await (await c.get(`/pending/${pid}`)).text();
  assert.match(page, /New agent/); assert.match(page, /bound/);
  assert.equal((await c.post(`/pending/${pid}/apply`)).status, 200);
  const ag = app.repo.listAgents().find((a) => a.name === 'bound');
  assert.equal(ag.all_credentials, 0);
  assert.deepEqual(app.repo.listAgentCredentials(ag.id), [k1]);
});

test('отмена: POST /pending/:id/cancel удаляет черновик, состояние не меняется', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  const pid = idOf(await c.post(`/keys/${id}/policy`, WEAKER));
  makeFresh(c);
  const r = await c.post(`/pending/${pid}/cancel`);
  assert.equal(r.headers.get('location'), `/keys/${id}`);
  assert.equal(rows().length, 0); assert.equal(app.repo.getCredential(id).max_calls, 100);
  assert.ok(audits('pending.cancelled').some((x) => x.target === id));
});

test('5: одна запись на сессию: второй save заменяет первую, старый id мёртв', () => {
  resetClock();
  const p = pend(); const sh = rawSession(); const ctx = mkCtx(sh);
  const id = mkKey();
  const a = p.save(ctx, 'key.policy', id, WEAKER);
  const b = p.save(ctx, 'key.policy', id, { ...WEAKER, max_calls: '7000' });
  assert.notEqual(a, b); assert.equal(a.length, 22);
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE session_hash = ?').get(sh).n, 1);
  assert.deepEqual(p.apply(ctx, a), { status: 'gone' });
  assert.equal(app.repo.getCredential(id).max_calls, 100);
  assert.equal(p.apply(ctx, b).redirect, `/keys/${id}`);
  assert.equal(app.repo.getCredential(id).max_calls, 7000);
});

test('6: TTL: через 301 с apply и view дают gone, purgePending удаляет', () => {
  resetClock();
  const p = pend(); const ctx = mkCtx(rawSession());
  const id = mkKey();
  const pid = p.save(ctx, 'key.policy', id, WEAKER);
  const t0 = clock;
  clock = t0 + PENDING_TTL - 1;
  assert.equal(p.view(ctx, pid).status, 'ok');
  clock = t0 + 301;
  assert.deepEqual(p.view(ctx, pid), { status: 'gone' });
  assert.deepEqual(p.apply(ctx, pid), { status: 'gone' });
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE id = ?').get(pid).n, 1, 'apply просроченного запись не трогает');
  assert.ok(app.repo.purgePending(t0 + 301) >= 1);
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE id = ?').get(pid).n, 0);
  assert.equal(app.repo.getCredential(id).max_calls, 100);
});

test('7: чужая сессия и другая сессия того же пользователя: gone, запись владельца цела', () => {
  resetClock();
  const p = pend(); const mine = mkCtx(rawSession()); const other = mkCtx(rawSession()); const stranger = mkCtx(mine.sessionHash, { userId: 'someone' });
  const id = mkKey();
  const pid = p.save(mine, 'key.policy', id, WEAKER);
  assert.deepEqual(p.apply(other, pid), { status: 'gone' });
  assert.deepEqual(p.view(other, pid), { status: 'gone' });
  assert.deepEqual(p.cancel(other, pid), { status: 'gone' });
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE id = ?').get(pid).n, 1);
  // тот же сеанс, но другой пользователь: forbidden (запись при этом расходуется)
  assert.equal(p.apply(stranger, pid).status, 'forbidden');
  assert.equal(app.repo.getCredential(id).max_calls, 100);
});

test('8: устаревшая версия: ключ изменён, удалён, привязка агента сменилась — stale, запись удалена, старые значения не пишутся', () => {
  resetClock();
  const p = pend(); const ctx = mkCtx(rawSession());
  // политика изменена другим вызовом
  let id = mkKey();
  let pid = p.save(ctx, 'key.policy', id, WEAKER);
  app.repo.updateCredentialPolicy(id, { max_calls: 7 });
  assert.equal(p.apply(ctx, pid).status, 'stale');
  assert.equal(app.repo.getCredential(id).max_calls, 7, 'ключ не перезаписан старыми значениями');
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE id = ?').get(pid).n, 0);
  assert.ok(audits('pending.stale').some((x) => x.target === id));
  // ключ удалён
  id = mkKey();
  pid = p.save(ctx, 'key.policy', id, WEAKER);
  app.repo.softDeleteCredential(id);
  assert.equal(p.apply(ctx, pid).status, 'stale');
  // привязка агента
  const k1 = mkKey(); const k2 = mkKey();
  const agent = { id: crypto.randomBytes(8).toString('base64url'), name: 'st', token_hash: crypto.randomBytes(8).toString('hex'), all_credentials: 0 };
  app.repo.createAgent(agent); app.repo.setAgentCredentials(agent.id, { all: false, ids: [k1] });
  pid = p.save(ctx, 'agent.keys', agent.id, { all: '0', ids: [k1, k2] });
  assert.equal(p.view(ctx, pid).status, 'ok');
  app.repo.setAgentCredentials(agent.id, { all: false, ids: [] });
  assert.equal(p.view(ctx, pid).status, 'stale');
  assert.equal(p.apply(ctx, pid).status, 'stale');
  assert.deepEqual(app.repo.listAgentCredentials(agent.id), []);
  // расширение привязки без кода: после save и смены состояния всё равно stale, а не needFresh
});

test('agent.keys: расширение привязки идёт через черновик, сужение — сразу', async () => {
  const c = await session();
  const k1 = mkKey(); const k2 = mkKey();
  const agent = { id: crypto.randomBytes(8).toString('base64url'), name: 'bind', token_hash: crypto.randomBytes(8).toString('hex'), all_credentials: 0 };
  app.repo.createAgent(agent); app.repo.setAgentCredentials(agent.id, { all: false, ids: [k1] });
  makeStale(c);
  let r = await c.post(`/agents/${agent.id}/keys`, { keys_all: '0', keys: [k1] }); // не шире
  assert.equal(r.headers.get('location'), '/agents');
  assert.equal(rows().length, 0, 'без расширения черновика нет');
  r = await c.post(`/agents/${agent.id}/keys`, { keys_all: '0', keys: [k1, k2] });
  const pid = idOf(r);
  assert.deepEqual(JSON.parse(rows()[0].body_json), { all: '0', ids: [k1, k2] });
  makeFresh(c);
  assert.equal((await c.post(`/pending/${pid}/apply`)).headers.get('location'), '/agents');
  assert.deepEqual(app.repo.listAgentCredentials(agent.id).sort(), [k1, k2].sort());
  assert.equal(JSON.parse(audits('agent.keys').find((a) => a.target === agent.id).meta_json).via, 'draft');
});

test('9: неверный код: черновик жив; apply без свежего кода даёт needFresh, запись не потеряна', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  const pid = idOf(await c.post(`/keys/${id}/policy`, WEAKER));
  const bad = await c.post('/totp', { code: '000000', next: `/pending/${pid}` });
  assert.equal(bad.status, 302); assert.match(bad.headers.get('location'), /^\/totp\?e=code&next=/);
  assert.equal(rows().length, 1, 'черновик жив после неверного кода');
  // apply без свежего кода: откат consume
  const p = pend(); resetClock();
  const ctx = mkCtx(c.hash(), { hasRecentTotp: false });
  const r = p.apply(ctx, pid);
  assert.equal(r.status, 'needFresh'); assert.equal(r.back, `/keys/${id}`);
  assert.equal(rows().length, 1, 'запись не потеряна');
  assert.equal(app.repo.getCredential(id).max_calls, 100);
  // по HTTP то же: POST apply без кода -> /totp
  const h = await c.post(`/pending/${pid}/apply`);
  assert.equal(h.headers.get('location'), `/totp?next=/pending/${pid}`);
  assert.equal(rows().length, 1);
});

test('10: N/A для ролей (users нет); аналог: владелец не найден или чужой user_id — forbidden, подмена can — forbidden', () => {
  resetClock();
  const p = pend(); const ctx = mkCtx(rawSession());
  let id = mkKey();
  let pid = p.save(ctx, 'key.policy', id, WEAKER);
  app.db.prepare('UPDATE owner SET setup_done = 0 WHERE id = 1').run();
  try { assert.equal(p.apply(ctx, pid).status, 'forbidden'); } finally { app.db.prepare('UPDATE owner SET setup_done = 1 WHERE id = 1').run(); }
  assert.equal(app.repo.getCredential(id).max_calls, 100);
  assert.equal(rows().filter((r) => r.id === pid).length, 0);
  // запрещающий can
  const denied = createPending({ repo: app.repo, now: () => clock, can: () => false });
  assert.equal(denied.save(ctx, 'key.policy', id, WEAKER), null, 'save без прав ничего не сохраняет');
  id = mkKey();
  pid = p.save(ctx, 'key.policy', id, WEAKER);
  assert.equal(createPending({ repo: app.repo, now: () => clock, can: () => false }).apply(ctx, pid).status, 'forbidden');
  assert.equal(app.repo.getCredential(id).max_calls, 100);
});

test('11: CSRF: POST /pending/:id/apply без токена и с токеном другой сессии — 403', async () => {
  const a = await session(); const b = await session();
  makeStale(a);
  const id = mkKey();
  const pid = idOf(await a.post(`/keys/${id}/policy`, WEAKER));
  makeFresh(a);
  assert.equal((await a.post(`/pending/${pid}/apply`, {}, { token: null })).status, 403);
  assert.equal((await a.post(`/pending/${pid}/apply`, {}, { token: b.token })).status, 403);
  assert.equal((await a.post(`/pending/${pid}/cancel`, {}, { token: b.token })).status, 403);
  assert.equal(rows().length, 1); assert.equal(app.repo.getCredential(id).max_calls, 100);
  // чужая сессия с верным собственным токеном: gone
  const r = await b.post(`/pending/${pid}/apply`);
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/');
  assert.equal(rows().length, 1, 'чужая сессия черновик не трогает');
});

test('12: секреты: формы с ключом не сохраняются, поле key/password/token/code — assert, значения в базе нет', () => {
  resetClock();
  const p = pend(); const ctx = mkCtx(rawSession());
  const id = mkKey();
  for (const type of ['key.new', 'key.replace', 'key.delete', 'settings.password', 'unknown']) {
    assert.throws(() => p.save(ctx, type, id, { mode: 'ask' }), /not allowed/, type);
  }
  assert.ok(!('key.new' in ACTIONS) && !('key.replace' in ACTIONS));
  const SECRET = 'fake-secret-' + Math.random().toString(36).slice(2); // собирается в рантайме
  for (const field of ['key', 'secret', 'password', 'token', 'code', 'api_key', 'Password']) {
    let err;
    try { p.save(ctx, 'key.policy', id, { ...WEAKER, [field]: SECRET }); } catch (e) { err = e; }
    assert.ok(err && /secret-like/.test(err.message), field);
    assert.ok(!err.message.includes(SECRET), 'значение не попадает в текст ошибки');
  }
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE session_hash = ?').get(ctx.sessionHash).n, 0);
  const pid = p.save(ctx, 'key.policy', id, { ...WEAKER, _csrf: 'tok' });
  const row = app.db.prepare('SELECT * FROM pending_actions WHERE id = ?').get(pid);
  assert.ok(!row.body_json.includes(SECRET));
  assert.doesNotMatch(row.body_json, /fake-secret|_csrf|tok/);
});

test('13: валидация повторяется при применении: метод, ставший запрещённым в каталоге, даёт errors, а не запись', () => {
  resetClock();
  const p = pend(); const ctx = mkCtx(rawSession());
  const id = mkKey();
  app.repo.updateCredentialFilter(id, { enabled: true, entities: { deals: ['result.ID'] }, methods: [], fields: [] });
  const pid = p.save(ctx, 'key.filter', id, { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID'], methods: 'crm.status.list', fields_extra: 'result.NAME' });
  assert.equal(p.view(ctx, pid).status, 'ok');
  const provider = app.ctx.catalog.get('bitrix24');
  provider.filter.deny.push('crm.status.*');
  try {
    const r = p.apply(ctx, pid);
    assert.ok(Array.isArray(r.errors) && r.errors.length, JSON.stringify(r));
    assert.equal(p.view(ctx, pid).status, 'invalid');
  } finally { provider.filter.deny.pop(); }
  assert.deepEqual(app.repo.getCredential(id).filter.methods, [], 'фильтр не записан');
  assert.equal(rows().filter((r) => r.id === pid).length, 1, 'запись жива (откат consume)');
  assert.equal(p.apply(ctx, pid).redirect, `/keys/${id}`, 'после возврата правил применяется');
});

test('15: исключение внутри apply откатывает consume: запись жива, audit не записан', () => {
  resetClock();
  const p = pend(); const sh = rawSession(); const ctx = mkCtx(sh);
  const id = mkKey();
  const pid = p.save(ctx, 'key.policy', id, WEAKER);
  const broken = Object.create(app.repo);
  broken.updateCredentialPolicy = () => { throw new Error('boom'); };
  const before = audits('pending.applied').length;
  assert.throws(() => p.apply({ ...ctx, repo: broken }, pid), /boom/);
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE id = ?').get(pid).n, 1, 'consume откатан');
  assert.equal(audits('pending.applied').length, before);
  assert.equal(app.repo.getCredential(id).max_calls, 100);
  assert.equal(p.apply(ctx, pid).redirect, `/keys/${id}`, 'повторная попытка проходит');
});

test('Секреты: формы /keys/new/* и /keys/:id/replace черновиков не создают', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  // замена ключа без 2FA-гейта: черновика нет в любом случае; несуществующий провайдер не создаёт запись
  await c.post(`/keys/${id}/replace`, { key: 'fake_SHOULD_NOT_STORE' });
  await c.post('/keys/new/bitrix24', { webhook_url: 'https://x.example/', key: 'fake_SHOULD_NOT_STORE', mode: 'always' });
  assert.equal(rows().length, 0);
  assert.ok(!app.db.prepare('SELECT 1 FROM pending_actions WHERE body_json LIKE ?').get('%SHOULD_NOT_STORE%'));
});

test('14: выход и смена пароля удаляют черновик', async () => {
  const c = await session(); makeStale(c);
  const id = mkKey();
  idOf(await c.post(`/keys/${id}/policy`, WEAKER));
  assert.equal(rows().length, 1);
  assert.equal((await c.post('/logout')).status, 302);
  assert.equal(rows().length, 0, 'выход');

  const d = await session(); makeStale(d);
  const id2 = mkKey();
  idOf(await d.post(`/keys/${id2}/policy`, WEAKER));
  assert.equal(rows().length, 1);
  makeFresh(d);
  const r = await d.post('/settings/password', { password_old: PASSWORD, password_new: 'another-long-password-1', password_repeat: 'another-long-password-1' });
  assert.equal(r.status, 302);
  assert.ok(audits('password.change').length > 0);
  assert.equal(rows().length, 0, 'смена пароля');
});

test('purge: просроченные черновики удаляются, живые остаются; сессия удалена — черновик каскадом', () => {
  resetClock();
  const p = pend(); const sh = rawSession(); const ctx = mkCtx(sh);
  const id = mkKey();
  p.save(ctx, 'key.policy', id, WEAKER);
  assert.equal(app.repo.purgePending(clock + 10), 0);
  assert.equal(app.repo.purgePending(clock + 1000) >= 1, true);
  p.save(ctx, 'key.policy', id, WEAKER);
  app.repo.deleteSession(sh);
  assert.equal(app.db.prepare('SELECT count(*) AS n FROM pending_actions WHERE session_hash = ?').get(sh).n, 0);
});
