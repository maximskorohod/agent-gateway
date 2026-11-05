// Каталог, шаг 3 (интерфейс): ссылка «Get a key», sensitive-подтверждение, иконки, UTC, язык ответов агентам, строка срока.
// Без сети: vault file, mock не нужен (ключи только создаются).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as V from '../src/web/views/index.js';
import { setTimezone } from '../src/web/views/html.js';
import { initI18n } from '../src/i18n.js';
import en from '../src/i18n/en.js';
import ru from '../src/i18n/ru.js';
import { sensitiveNeedsConfirm } from '../src/web/policy.js';
import { createRequestService, inWindow } from '../src/core/requests.js';
import { decideIconAction, saveIcon } from '../scripts/fetch-icons.mjs';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';

const csrf = 'csrf-test-token';
const fake = {
  slug: 'fakesvc', name: 'Fake Service', host: 'api.fake.test', kind: 'static',
  injection: { type: 'header', name: 'authorization' }, maxBody: 1024, timeout: 10,
  fields: ['key'], icon: 'fakesvc', keyHint: 'expected a key like fk_…',
  getKeyUrl: 'https://fake.test/keys', getKeyHint: 'Create a key with read access only',
};

// ---- 1. getKeyUrl / getKeyHint
test('форма ключа: ссылка «Get a key →» и подсказка, если поля есть у провайдера', () => {
  initI18n('en');
  const out = V.keyForm({ csrf, provider: fake, values: {}, telegramConnected: false });
  assert.match(out, /<a href="https:\/\/fake\.test\/keys" target="_blank" rel="noopener noreferrer">Get a key →<\/a>/);
  assert.ok(out.includes('Create a key with read access only'));
});

test('форма ключа: без getKeyUrl/getKeyHint блока нет, не-https ссылка не выводится', () => {
  initI18n('en');
  const plain = { ...fake, getKeyUrl: undefined, getKeyHint: undefined };
  assert.ok(!V.keyForm({ csrf, provider: plain, values: {} }).includes('Get a key'));
  const bad = { ...fake, getKeyUrl: 'javascript:alert(1)', getKeyHint: undefined };
  const out = V.keyForm({ csrf, provider: bad, values: {} });
  assert.ok(!out.includes('javascript:'));
  assert.ok(!out.includes('Get a key'));
});

test('русская подсказка берётся из catalog.getkey.<slug>, если ключ есть', () => {
  initI18n('ru');
  ru['catalog.getkey.fakesvc'] = 'Создайте ключ только на чтение';
  en['catalog.getkey.fakesvc'] = 'Create a read-only key';
  try {
    const out = V.keyForm({ csrf, provider: fake, values: {} });
    assert.ok(out.includes('Создайте ключ только на чтение'));
    assert.ok(!out.includes('Create a key with read access only'));
    assert.ok(out.includes('Где взять ключ →'));
  } finally {
    delete ru['catalog.getkey.fakesvc']; delete en['catalog.getkey.fakesvc'];
    initI18n('en');
  }
});

// ---- 2. sensitive
test('sensitiveNeedsConfirm: только для sensitive и только при расширении «без вопросов»', () => {
  const always = { mode: 'always', always_until: null };
  const sens = { sensitive: true };
  assert.equal(sensitiveNeedsConfirm(always, { mode: 'ask' }, sens, {}), true);
  assert.equal(sensitiveNeedsConfirm(always, { mode: 'ask' }, sens, { confirm_sensitive: '1' }), false);
  assert.equal(sensitiveNeedsConfirm(always, { mode: 'ask' }, {}, {}), false, 'не sensitive — как раньше');
  assert.equal(sensitiveNeedsConfirm({ mode: 'ask' }, { mode: 'deny' }, sens, {}), false, 'не always — подтверждение не нужно');
  assert.equal(sensitiveNeedsConfirm(always, always, sens, {}), false, 'без расширения — не нужно');
});

test('вью: чекбокс подтверждения и предупреждение только у sensitive-провайдера', () => {
  initI18n('en');
  const base = { ...fake, getKeyUrl: undefined };
  const on = V.keyForm({ csrf, provider: { ...base, sensitive: true }, values: {} });
  assert.ok(on.includes('name="confirm_sensitive"'));
  assert.ok(on.includes('can move money'));
  assert.ok(!V.keyForm({ csrf, provider: base, values: {} }).includes('confirm_sensitive'));
});

let app, base, totpSecret;
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
  storeCookies(r); return r;
}
const POLICY = { approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' };

before(async () => {
  initI18n('en');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-catui-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  totpSecret = (await (await get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  await post('/setup', { step: '2', code: totpAt(totpSecret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); });

test('sensitive (Stripe): без подтверждения «без вопросов» отказ, с подтверждением и свежим кодом — ок; обычный сервис как раньше', async () => {
  const stripe = await post('/keys/new/stripe', { key: 'sk_test_FAKEFAKEFAKE1234', mode: 'ask', ...POLICY });
  assert.equal(stripe.status, 302);
  const groq = await post('/keys/new/groq', { key: 'gsk_FAKEFAKEFAKEFAKEFAKE1234', mode: 'ask', ...POLICY });
  assert.equal(groq.status, 302);
  const [sId, gId] = ['stripe', 'groq'].map((s) => app.repo.listCredentials().find((c) => c.provider === s).id);
  // свежий код нужен в любом случае: берём незанятый шаг
  const code = () => totpAt(totpSecret, Math.floor(Date.now() / 30000) + [1, -1].shift());
  await post('/totp', { code: code(), next: '/' });

  // без подтверждения: отказ, режим не изменился
  let r = await post(`/keys/${sId}/policy`, { mode: 'always', always_for: 'forever', ...POLICY });
  assert.equal(r.status, 302);
  assert.equal(app.repo.getCredential(sId).mode, 'ask');
  assert.match(await (await get(`/keys/${sId}`)).text(), /This service is sensitive/);

  // с подтверждением (свежий код 2FA есть) — принято
  r = await post(`/keys/${sId}/policy`, { mode: 'always', always_for: 'forever', confirm_sensitive: '1', ...POLICY });
  assert.equal(r.status, 302);
  assert.equal(app.repo.getCredential(sId).mode, 'always');

  // у обычного провайдера подтверждение не требуется
  r = await post(`/keys/${gId}/policy`, { mode: 'always', always_for: 'forever', ...POLICY });
  assert.equal(r.status, 302);
  assert.equal(app.repo.getCredential(gId).mode, 'always');
});

test('sensitive: создание нового ключа Stripe сразу в «без вопросов» без подтверждения — ошибка формы', async () => {
  const r = await post('/keys/new/stripe', { key: 'sk_test_FAKEFAKEFAKE9999', mode: 'always', always_for: 'forever', ...POLICY });
  assert.equal(r.status, 400);
  assert.match(await r.text(), /Tick the confirmation/);
});

// ---- 3. иконки
test('decideIconAction: найдена — пишем, нет и файл есть — оставляем, нет совсем — заглушка', () => {
  assert.equal(decideIconAction({ found: true, exists: true }), 'write');
  assert.equal(decideIconAction({ found: false, exists: true }), 'keep');
  assert.equal(decideIconAction({ found: false, exists: false }), 'stub');
});

test('saveIcon: существующий файл не затирается заглушкой, заглушка только при отсутствии, запись без остатков .tmp', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-icons-'));
  const file = path.join(dir, 'x.svg');
  fs.writeFileSync(file, '<svg>real</svg>\n');
  assert.equal(await saveIcon(dir, 'x', { svg: null, stub: '<svg>stub</svg>' }), 'keep');
  assert.equal(fs.readFileSync(file, 'utf8'), '<svg>real</svg>\n');
  assert.equal(await saveIcon(dir, 'y', { svg: null, stub: '<svg>stub</svg>' }), 'stub');
  assert.equal(fs.readFileSync(path.join(dir, 'y.svg'), 'utf8'), '<svg>stub</svg>\n');
  assert.equal(await saveIcon(dir, 'x', { svg: '<svg>new</svg>', stub: '<svg>stub</svg>' }), 'write');
  assert.equal(fs.readFileSync(file, 'utf8'), '<svg>new</svg>\n');
  assert.deepEqual(fs.readdirSync(dir).filter((f) => f.endsWith('.tmp')), []);
});

// ---- 4. UTC
test('часовой пояс по умолчанию UTC и берётся из настройки, а не константы', () => {
  initI18n('en');
  assert.equal(V.fmtDate(0), '1 Jan 1970, 00:00');
  assert.equal(setTimezone('Europe/Moscow'), true);
  try {
    assert.equal(V.fmtDate(0), '1 Jan 1970, 03:00');
    assert.equal(V.isoDate(86400 * 365 - 1), '1971-01-01'); // в UTC было бы 1970-12-31
  } finally { setTimezone('UTC'); }
  assert.equal(setTimezone('Not/AZone'), false);
  assert.equal(V.fmtDate(0), '1 Jan 1970, 00:00');
});

test('inWindow считает в заданном поясе, независимо от пояса машины', () => {
  // понедельник 2026-11-02 22:30 UTC = вторник 01:30 в Москве
  const at = new Date('2026-11-02T22:30:00Z');
  const win = { days: [1], from: '20:00', to: '23:00' };
  assert.equal(inWindow(win, 'UTC', at), true);
  assert.equal(inWindow(win, 'Europe/Moscow', at), false);
  assert.equal(inWindow({ days: [2], from: '00:00', to: '02:00' }, 'Europe/Moscow', at), true);
});

// ---- 5. язык ответов агентам
test('ответ агенту об отказе английский при любом языке интерфейса', () => {
  const repo = createRepo(openDb(':memory:'));
  repo.createAgent({ id: 'a1', name: 'agent', token_hash: 'th', enabled: 1 });
  repo.createAgent({ id: 'a2', name: 'off', token_hash: 'th2', enabled: 0 });
  repo.createCredential({ provider: 'telegram', label: 'bot', kind: 'path', host: 'api.telegram.org', injection: { type: 'path', template: '/bot{secret}' }, last4: 'abcd', approval: 'web_button', id: 'c1', vault_param: 'cred/c1', mode: 'deny' });
  const svc = createRequestService({ repo, grants: {}, notify: {}, tz: 'UTC', logger: { warn() {}, error() {} } });
  initI18n('ru');
  try {
    assert.equal(svc.submit({ agent: repo.getAgent('a1'), credential: repo.getCredential('c1'), ttl: 60, calls: 1 }).reason, en['requests.err.key_denied']);
    assert.equal(svc.submit({ agent: repo.getAgent('a2'), credential: repo.getCredential('c1'), ttl: 60, calls: 1 }).reason, en['requests.err.agent_off']);
    assert.equal(svc.submit({ agent: repo.getAgent('a1'), credential: null, ttl: 60, calls: 1 }).reason, en['requests.err.key_missing']);
  } finally { initI18n('en'); }
});

// ---- 6. «for forever»
test('срок always: вариант forever читается целиком, без «for forever» (en) и «на всегда» (ru)', () => {
  const sel = (lang, values) => { initI18n(lang); return V.keyForm({ csrf, provider: fake, values }); };
  try {
    let out = sel('en', {});
    assert.ok(out.includes('>with no time limit<'));
    assert.ok(!/for forever|another forever/.test(out));
    assert.ok(out.includes('>for 1 hour<'));
    out = sel('ru', {});
    assert.ok(out.includes('>без ограничения срока<'));
    assert.ok(!/на всегда|ещё всегда/.test(out));
    // у ключа с действующим сроком — вариант «ещё …»
    const until = Math.floor(Date.now() / 1000) + 3600;
    out = V.keyDetail({ csrf, cred: { id: 'c', provider: 'fakesvc', label: 'L', last4: '1234', created_at: 0, mode: 'always', always_until: until }, provider: fake });
    assert.ok(out.includes('>снять ограничение срока<'));
  } finally { initI18n('en'); }
});
