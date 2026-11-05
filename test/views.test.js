// Тесты серверных шаблонов: рендер без исключений, экранирование, без инлайн-скриптов и стилей.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V from '../src/web/views/index.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const csrf = 'csrf-test-token';

const gemini = {
  slug: 'gemini', name: 'Google Gemini', host: 'generativelanguage.googleapis.com', kind: 'static',
  injection: { type: 'header', name: 'x-goog-api-key' }, maxBody: 2097152, timeout: 60,
  fields: ['key'], icon: 'gemini', keyHint: 'ожидается ключ вида AIza…',
};
const bitrix = {
  slug: 'bitrix24', name: 'Bitrix24', host: 'owner', kind: 'path',
  injection: { type: 'path', template: '/rest/{secret}' }, maxBody: 2097152, timeout: 60,
  fields: ['webhook_url'], icon: 'bitrix24', keyHint: 'вставьте ссылку входящего вебхука целиком',
};
const other = {
  slug: 'other', name: 'Другой', host: 'owner', kind: 'static',
  injection: { type: 'header', name: 'owner' }, maxBody: 2097152, timeout: 60,
  fields: ['host', 'header', 'key'], icon: 'other', keyHint: 'адрес API, имя заголовка и ключ',
};
const providers = [gemini, bitrix, other];

const cred = {
  id: 'c1', provider: 'gemini', label: 'Личный', kind: 'static',
  host: 'generativelanguage.googleapis.com', injection: {}, vault_param: 'p',
  mode: 'ask', approval: 'tg_button', max_ttl: 3600, max_calls: 100, max_parallel: 2,
  window: { days: [1, 2, 3, 4, 5], from: '09:00', to: '18:00', tz: 'Europe/Moscow' },
  expires_at: 1800000000, last4: '7Xq2', created_at: 1700000000, deleted_at: null,
};

const pendingReq = {
  id: 'r1', agent_id: 'a1', credential_id: 'c1', ttl: 7200, calls: 5,
  reason: '<b>x</b>', status: 'pending', created_at: 1700000000, expires_at: 1700000600,
  decided_at: null, decided_via: null, tg_message_id: null,
  agent_name: 'research-bot', credential_label: 'Личный', provider: 'gemini',
};

const agent = { id: 'a1', name: 'research-bot', enabled: 1, created_at: 1700000000, last_seen_at: null };

const session = { id: 's1', ua: 'Mozilla/5.0 <test>', created_at: 1700000000, current: true };

const audit = { at: 1700000000, actor: 'owner', action: 'key.create', target: 'c1', meta: { provider: 'gemini' } };

/** Все страницы с полными данными — для проверок безопасности и вёрстки. */
function allPages() {
  return {
    login: V.login({ csrf, error: 'Неверный пароль' }),
    loginLocked: V.login({ csrf, locked: true }),
    totp: V.totp({ csrf, action: 'Подтвердите удаление ключа.', error: 'Неверный код' }),
    setup1: V.setup({ csrf, step: 1, error: 'Пароли не совпадают' }),
    setup2: V.setup({ csrf, step: 2, data: { qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"></svg>', secret: 'ABCDEF' } }),
    setup2codes: V.setup({ csrf, step: 2, data: { backupCodes: ['aaaa-1111', '<i>bbbb</i>'], downloadHref: '/setup/x/codes.txt' } }),
    setup3: V.setup({ csrf, step: 3, data: {} }),
    setup3code: V.setup({ csrf, step: 3, data: { tgCode: 'K9F2', botUsername: 'gw_bot' } }),
    keys: V.keysPage({ csrf, credentials: [cred], pending: [pendingReq], providers }),
    keysEmpty: V.keysPage({ csrf, credentials: [], pending: [], providers }),
    pick: V.pickProvider({ providers, csrf }),
    keyFormGemini: V.keyForm({ csrf, provider: gemini, values: {}, telegramConnected: true }),
    keyFormBitrix: V.keyForm({ csrf, provider: bitrix, values: {}, telegramConnected: false }),
    keyDetail: V.keyDetail({ csrf, cred, provider: gemini, telegramConnected: true }),
    agents: V.agentsPage({ csrf, agents: [agent] }),
    agentCreated: V.agentCreated({ csrf, agent, token: 'tok_abc' }),
    settings: V.settingsPage({ csrf, owner: { totp_enabled: true }, sessions: [session], telegramConnected: true, botUsername: 'gw_bot' }),
    tgLink: V.tgLink({ code: 'K9F2', botUsername: 'gw_bot' }),
    audit: V.auditPage({ csrf, rows: [audit] }),
    error: V.errorPage(404, 'Страница не найдена'),
  };
}

test('каждая страница рендерится с минимальными данными', () => {
  const outs = [
    V.login({}),
    V.totp({}),
    V.setup({ step: 1 }),
    V.setup({ step: 2 }),
    V.setup({ step: 3 }),
    V.keysPage({}),
    V.pickProvider({}),
    V.keyForm({ provider: gemini }),
    V.keyDetail({ cred: { id: 'x', provider: 'gemini', label: 'L', last4: '0000', created_at: 0 } }),
    V.agentsPage({}),
    V.agentCreated({ agent: { name: 'a' }, token: 't' }),
    V.settingsPage({}),
    V.tgLink({ code: 'c', botUsername: 'b' }),
    V.auditPage({}),
    V.errorPage(500, 'Ошибка'),
  ];
  for (const out of outs) {
    assert.equal(typeof out, 'string');
    assert.ok(out.startsWith('<!doctype html>'));
  }
});

test('причина от агента экранируется', () => {
  const out = V.requestPage({ csrf, request: pendingReq, providers });
  assert.ok(out.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.ok(!out.includes('<b>x</b>'));
});

test('форма Bitrix24 содержит вебхук и не содержит поля key', () => {
  const out = V.keyForm({ csrf, provider: bitrix, values: {}, telegramConnected: true });
  assert.ok(out.includes('name="webhook_url"'));
  assert.ok(!out.includes('name="key"'));
});

test('без подключённого Telegram нет варианта tg_button', () => {
  const out = V.keyForm({ csrf, provider: gemini, values: {}, telegramConnected: false });
  assert.ok(!out.includes('value="tg_button"'));
  assert.ok(!out.includes('value="tg_code"'));
  assert.ok(out.includes('value="web_button"'));
});

test('ключ не возвращается в форму и не попадает в страницу', () => {
  const out = V.keyForm({
    csrf, provider: bitrix, telegramConnected: false,
    values: { webhook_url: 'https://x.bitrix24.ru/rest/17/topsecretvalue/' },
  });
  assert.ok(!out.includes('topsecretvalue'));
});

test('ключ-поле имеет type=password и autocomplete=off', () => {
  const out = V.keyForm({ csrf, provider: gemini, values: {}, telegramConnected: true });
  assert.match(out, /<input type="password" name="key" autocomplete="off"/);
});

test('все страницы: скрипт только app.js, без инлайн-стилей и внешних загрузок', () => {
  for (const [name, out] of Object.entries(allPages())) {
    const scripts = out.match(/<script[^>]*>/g) ?? [];
    for (const s of scripts) {
      assert.equal(s, '<script src="/public/app.js" defer>', `${name}: лишний скрипт`);
    }
    assert.ok(!out.includes('style='), `${name}: есть style=`);
    assert.ok(!/(src|href|action)="https?:/.test(out), `${name}: внешняя ссылка в атрибуте`);
    assert.ok(!/<link (?!rel="stylesheet" href="\/public\/style\.css")/.test(out), `${name}: лишний link`);
  }
});

test('все формы POST содержат CSRF-поле', () => {
  for (const [name, out] of Object.entries(allPages())) {
    const forms = (out.match(/<form\b/g) ?? []).length;
    const tokens = (out.match(/name="_csrf"/g) ?? []).length;
    assert.equal(tokens, forms, `${name}: форм ${forms}, CSRF-полей ${tokens}`);
  }
});

test('QR-код вставляется как разметка, данные экранируются', () => {
  const out = V.setup({ step: 2, data: { qrSvg: '<svg id="qr"></svg>', secret: 'ABC' } });
  assert.ok(out.includes('<svg id="qr"></svg>'));
  const codes = V.setup({ step: 2, data: { backupCodes: ['<i>x</i>'], downloadHref: '#' } });
  assert.ok(codes.includes('&lt;i&gt;x&lt;/i&gt;'));
});

test('esc экранирует все спецсимволы', () => {
  assert.equal(V.esc(`<&>"'`), '&lt;&amp;&gt;&quot;&#39;');
});

test('fmtDuration и fmtDate', () => {
  assert.equal(V.fmtDuration(300), '5 мин');
  assert.equal(V.fmtDuration(1800), '30 мин');
  assert.equal(V.fmtDuration(3600), '1 ч');
  assert.equal(V.fmtDuration(5400), '1 ч 30 мин');
  assert.equal(V.fmtDuration(86400), '24 ч');
  assert.equal(V.fmtDate(0), '1 янв. 1970, 00:00');
});
