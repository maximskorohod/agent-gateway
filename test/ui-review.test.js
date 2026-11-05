// Находки «интерфейс глазами» 04.11 (out/ui-review/REPORT.md): B-1 Referrer-Policy и Origin формы, B-2 пустое имя ключа
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';
import * as V from '../src/web/views/index.js';

initI18n('en');

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
const SECRET = '123456:' + 'A'.repeat(35);
let app, base, dataDir, csrfTok = '';
const jar = new Map();
const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function store(r) { for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); const v = kv.slice(i + 1); if (v) jar.set(kv.slice(0, i), v); else jar.delete(kv.slice(0, i)); } }
async function get(p) {
  const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' }); store(r);
  const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1];
  return r;
}
// origin по умолчанию не шлём (как e2e.test.js): publicUrl приложения без порта
async function post(p, fields, origin) {
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded', ...(origin !== undefined && { origin }) }, body: new URLSearchParams({ _csrf: csrfTok, ...fields }), redirect: 'manual' });
  store(r);
  if (r.status === 302 && r.headers.getSetCookie().length) await get(r.headers.get('location'));
  return r;
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-ui-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  // мастер: пароль, 2FA, без Telegram
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  const secret = (await (await get('/setup')).text()).match(/<code>([A-Z2-7]{16,})<\/code>/)[1];
  await post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await get('/setup');
  await post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); fs.rmSync(dataDir, { recursive: true, force: true }); });

test('B-1: Referrer-Policy same-origin в заголовке, meta и обоих Caddyfile (при no-referrer браузер шлёт Origin: null)', async () => {
  const r = await fetch(base + '/login', { redirect: 'manual' }); // без сессии: с ней /login уводит в кабинет
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('referrer-policy'), 'same-origin');
  assert.match(await r.text(), /<meta name="referrer" content="same-origin">/);
  for (const f of ['deploy/Caddyfile', 'Caddyfile.docker']) {
    const txt = fs.readFileSync(path.join(root, f), 'utf8');
    assert.match(txt, /Referrer-Policy "same-origin"/, f);
    assert.doesNotMatch(txt, /no-referrer/, f);
  }
});

test('B-1: CSRF по-прежнему отклоняет Origin: null и чужой сайт', async () => {
  await get('/keys/new/telegram');
  for (const origin of ['null', 'https://evil.example']) {
    const r = await post('/keys/new/telegram', { key: SECRET, mode: 'ask' }, origin);
    assert.equal(r.status, 403, origin);
  }
  assert.equal(app.repo.listCredentials().length, 0);
});

test('B-2: ключ без имени из формы получает имя сервиса, не пустую строку', async () => {
  await get('/keys/new/telegram');
  const r = await post('/keys/new/telegram', { key: SECRET, label: '', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  assert.equal(r.status, 302);
  const [cred] = app.repo.listCredentials();
  assert.equal(cred.label, 'Telegram Bot API');
});

test('B-2: стёртое имя при правке политики — имя сервиса', async () => {
  const [cred] = app.repo.listCredentials();
  await get(`/keys/${cred.id}`);
  const r = await post(`/keys/${cred.id}/policy`, { label: '  ', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  assert.equal(r.status, 302);
  assert.equal(app.repo.getCredential(cred.id).label, 'Telegram Bot API');
});

// ---- находки по снимкам: вывод (views — чистые функции, сервер не нужен)
const HUB = { slug: 'hubspot', name: 'HubSpot' };
const oldKey = { id: 'k1', provider: 'hubspot', label: '', mode: 'ask', max_ttl: 3600, max_calls: 5, max_parallel: 2, approval: 'web_button', last4: '548f', created_at: 0, filter: null };

test('ключ с пустым label показывается под именем сервиса: список, страница ключа, агенты, активность', () => {
  assert.equal(V.keyName(oldKey, [HUB]), 'HubSpot');
  assert.equal(V.keyName({ ...oldKey, label: 'work' }, [HUB]), 'work');
  assert.equal(V.keyName({ ...oldKey, provider: 'zzz' }, [HUB]), 'zzz'); // каталога нет: slug
  const list = V.keysPage({ csrf: 'c', credentials: [oldKey], providers: [HUB] });
  assert.match(list, /<span class="title">HubSpot<\/span>/);
  const detail = V.keyDetail({ csrf: 'c', cred: oldKey, provider: HUB });
  assert.match(detail, /<title>HubSpot · /);
  assert.match(detail, /<h1>HubSpot<\/h1>/);
  const agents = V.agentsPage({ csrf: 'c', agents: [{ id: 'a1', name: 'bot', enabled: 1, all_credentials: 0 }], credentials: [oldKey], bindings: { a1: ['k1'] }, providers: [HUB] });
  assert.match(agents, /Keys: HubSpot/);
  const stats = V.statsPage({ csrf: 'c', calls: [{ agent_id: 'a1', credential_id: 'k1', calls: 2, errors: 0, last_at: 1 }], agents: [{ id: 'a1', name: 'bot' }], credentials: [oldKey], providers: [HUB] });
  assert.match(stats, /height="20">HubSpot<\/span><\/td>/);
});

test('заявка: имя ключа в скобках только если отличается от имени сервиса', () => {
  const req = (credential_label) => ({ id: 'r1', agent_name: 'bot', provider: 'hubspot', credential_label, ttl: 3600, calls: 3, reason: '' });
  const page = (label) => V.keysPage({ csrf: 'c', pending: [req(label)], providers: [HUB] });
  assert.doesNotMatch(page('HubSpot'), /HubSpot \(HubSpot\)/);
  assert.match(page('HubSpot'), /small">HubSpot, /);
  assert.match(page('Sales'), /small">HubSpot \(Sales\), /);
  assert.match(page(''), /small">HubSpot, /);
});

test('экран заявки: строка в списке ведёт на него, решение только POST с CSRF, текст агента экранируется', () => {
  const r = { id: 'r/1', agent_name: '<b>bot</b>', provider: 'hubspot', credential_label: 'Sales', ttl: 900, calls: 20, reason: '<script>x</script>' };
  const list = V.keysPage({ csrf: 'c', pending: [r], providers: [HUB] });
  assert.match(list, /href="\/requests\/r%2F1"/);
  assert.doesNotMatch(list, /action="\/requests/); // в списке решения нет
  assert.match(list, /class="count"[^>]*>1</);
  const page = V.requestPage({ csrf: 'tok', request: r, providers: [HUB], filterLine: 'Agent will see: deals' });
  assert.match(page, /<form method="post" action="\/requests\/r%2F1\/approve"><input type="hidden" name="_csrf" value="tok">/);
  assert.match(page, /<form method="post" action="\/requests\/r%2F1\/deny"><input type="hidden" name="_csrf" value="tok">/);
  assert.match(page, /Agent will see: deals/);
  assert.match(page, /&lt;script&gt;x&lt;\/script&gt;/);
  assert.match(page, /&lt;b&gt;bot&lt;\/b&gt; asks for access to HubSpot \(Sales\)/);
  assert.doesNotMatch(page, /<script>x/);
  assert.doesNotMatch(page, /class="nav"/); // экран решения без меню
});

test('список ключей: на странице ключа текущий отмечен, значения ключа нет, есть только последние 4 символа', () => {
  const page = V.keyDetail({ csrf: 'c', cred: oldKey, provider: HUB, credentials: [oldKey], providers: [HUB] });
  assert.match(page, /class="row on" href="\/keys\/k1" aria-current="true"/);
  assert.match(page, /<h1>HubSpot<\/h1>/);
  const home = V.keysPage({ csrf: 'c', credentials: [oldKey], providers: [HUB], keyLine: 'Agent will see: deals' });
  assert.match(home, /············ 548f/);
  assert.match(home, /Agent will see: deals/);
  assert.match(home, /href="\/keys\/k1">Open key settings/);
});

test('резервные коды: кнопка «Дальше» ждёт сохранения только через JS, без него форма рабочая', () => {
  const page = V.setup({ csrf: 'c', step: 2, data: { backupCodes: ['AAAA-BBBB'], downloadHref: '/setup/backup-codes.txt' } });
  assert.match(page, /<body class="bare dim">/);
  assert.match(page, /data-after-save/);
  assert.doesNotMatch(page, /data-after-save[^>]*disabled|disabled[^>]*data-after-save/);
  assert.match(page, /href="\/setup\/backup-codes.txt" download data-saves-codes/);
});

test('журнал аудита: названия событий из словаря, неизвестный код как есть, секреты и null не выводятся', () => {
  const row = (action, meta) => ({ at: 0, actor: 'owner', action, target: 't1', meta });
  const page = V.auditPage({ csrf: 'c', rows: [
    row('credential.create', JSON.stringify({ provider: 'hubspot', mode: 'ask' })),
    row('mcp.session.open', null),
    row('weird.future_event', 'null'),
    row('notify.secret', JSON.stringify({ webhook: 'https://hooks.example/SECRET-VALUE', token: 'tok-123', channel: 'slack' })),
  ] });
  assert.match(page, />Key added</);
  assert.match(page, />MCP session opened</);
  assert.match(page, />weird\.future_event</); // неизвестное событие — код
  assert.match(page, /title="credential\.create"/);
  assert.doesNotMatch(page, /SECRET-VALUE|tok-123/);
  assert.match(page, /channel: slack/);
  assert.doesNotMatch(page, />null</);
  assert.match(page, /<h1>Audit log<\/h1>/);
  initI18n('ru');
  try {
    const ru = V.auditPage({ csrf: 'c', rows: [row('credential.create', null), row('panic', null)] });
    assert.match(ru, />Ключ добавлен</);
    assert.match(ru, />Аварийный выход</);
    assert.match(ru, /<h1>Журнал аудита<\/h1>/);
    assert.doesNotMatch(ru, />credential\.create</);
  } finally { initI18n('en'); }
});

test('ru: раздел называется «Активность», дата без неоднозначности', () => {
  initI18n('ru');
  try {
    assert.match(V.keysPage({ csrf: 'c' }), /<a href="\/stats">Активность<\/a>/);
    assert.match(V.statsPage({ csrf: 'c', agentId: 'a1', agents: [{ id: 'a1', name: 'бот' }] }), /<h1>Активность: бот<\/h1>/);
  } finally { initI18n('en'); }
  // 4 ноября: в en «4 Nov 2026», а не «04/11/2026» (день и месяц не путаются)
  assert.match(V.fmtDate(Date.UTC(2026, 10, 4, 17, 29) / 1000), /^4 Nov 2026, 17:29$/);
});

test('ru: месяц в родительном падеже (ревью релиза)', () => {
  initI18n('ru');
  try {
    assert.match(V.fmtDate(Date.UTC(2026, 4, 4, 12, 0) / 1000), /^4 мая 2026/);
    assert.match(V.fmtDate(Date.UTC(2026, 10, 4, 12, 0) / 1000), /^4 нояб\. 2026/);
  } finally { initI18n('en'); }
});

test('журнал аудита: счётчик tokens виден, секреты скрыты и во вложенных объектах (ревью релиза)', () => {
  const page = V.auditPage({ csrf: 'c', rows: [
    { at: 0, actor: 'owner', action: 'x', target: '', meta: JSON.stringify({ tokens: 3, api_key: 'VALUE-1', nested: { access_token: 'VALUE-2', ok: 1 } }) },
  ] });
  assert.match(page, /tokens: 3/);
  assert.doesNotMatch(page, /VALUE-1|VALUE-2/);
});

test('маршруты: 404 с меню только владельцу, страница кода заявки только после входа (ревью релиза)', async () => {
  const anon404 = await (await fetch(`${base}/no-such-page`, { redirect: 'manual' })).text();
  assert.doesNotMatch(anon404, /href="\/agents"/);
  assert.match(await (await get('/no-such-page')).text(), /href="\/agents"/);
  assert.match(await (await get('/keys/nope')).text(), /href="\/agents"/, 'ключ не найден');
  assert.match(await (await get('/keys/new/nope')).text(), /href="\/agents"/, 'сервис не найден');
  const code = await fetch(`${base}/requests/no-such/approve-confirm`, { redirect: 'manual' });
  assert.equal(code.status, 302, 'без входа — на страницу входа');
  // полусессия: пароль принят, код 2FA ещё не введён
  const page = await fetch(`${base}/login`, { redirect: 'manual' });
  const cookies = new Map(page.headers.getSetCookie().map((c) => c.split(';')[0].split('=')));
  const tok = (await page.text()).match(/name="_csrf" value="([^"]+)"/)[1];
  const cookieStr = () => [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const login = await fetch(`${base}/login`, { method: 'POST', redirect: 'manual', headers: { cookie: cookieStr(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ _csrf: tok, password: 'correct-horse-battery' }) });
  assert.match(String(login.headers.get('location')), /^\/totp/);
  for (const c of login.headers.getSetCookie()) { const [k, v] = c.split(';')[0].split('='); cookies.set(k, v); }
  const half404 = await (await fetch(`${base}/no-such-page`, { headers: { cookie: cookieStr() }, redirect: 'manual' })).text();
  assert.doesNotMatch(half404, /href="\/agents"/);
  const halfCode = await fetch(`${base}/requests/no-such/approve-confirm`, { headers: { cookie: cookieStr() }, redirect: 'manual' });
  assert.equal(halfCode.status, 302, 'полусессия не видит страницу кода');
});

test('код подтверждения: заголовок по случаю и контекст заявки', () => {
  const page = V.totp({ csrf: 'c', title: 'Approve with a code', details: [['Agent', 'bot'], ['Key', 'HubSpot'], ['Pass duration', '1 h'], ['Calls', '3']] });
  assert.match(page, /<h1>Approve with a code<\/h1>/);
  assert.match(page, /<dt>Agent<\/dt><dd>bot<\/dd>/);
  assert.match(page, /<dt>Key<\/dt><dd>HubSpot<\/dd>/);
  assert.match(V.totp({ csrf: 'c' }), /<h1>Verification code<\/h1>/);
});
