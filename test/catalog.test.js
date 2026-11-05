// Тесты каталога сервисов (ARCHITECTURE.md → catalog.js). Сеть не нужна.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalog, buildInjection, validateKeyFormat, isValidOwnerHost } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';
import { isPrivateIp } from '../src/core/ssrf.js';

initI18n('ru');

test('isPrivateIp: служебные и туннельные адреса закрыты, публичные открыты', () => {
  for (const a of ['::7f00:1', '64:ff9b::7f00:1', '2002:7f00:1::', '2001::1', 'fec0::1', 'fe80::1', '::1', '::ffff:10.0.0.1', '198.18.0.1', '192.0.0.1', '100.64.0.1', '169.254.169.254']) {
    assert.equal(isPrivateIp(a), true, a);
  }
  for (const a of ['8.8.8.8', '2a00:1450:4001::200e', '2606:4700::1111', '2001:4860:4860::8888']) assert.equal(isPrivateIp(a), false, a);
});

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = loadCatalog(path.join(root, 'providers.yaml'));

test('loadCatalog загружает 26 провайдеров в порядке файла', () => {
  const list = catalog.list();
  assert.equal(list.length, 26);
  assert.equal(catalog.providers.size, 26);
  assert.deepEqual(list.map((p) => p.slug), [
    'openai', 'anthropic', 'gemini', 'openrouter', 'groq', 'mistral', 'github',
    'slack', 'notion', 'linear', 'stripe', 'hubspot', 'pipedrive', 'zendesk', 'atlassian', 'airtable', 'resend', 'sendgrid', 'twilio',
    'deepgram', 'elevenlabs', 'telegram', 'bitrix24', 'bitrix24-box', 'amocrm', 'other',
  ]);
  assert.equal(list[0].slug, 'openai');
  assert.equal(list[0].icon, 'openai');
  assert.equal(list[list.length - 1].slug, 'other');
  assert.equal(catalog.get('nope'), undefined);
});

test('keyPattern: openai, anthropic, stripe, slack', () => {
  const openai = catalog.get('openai');
  assert.equal(openai.keyPattern, '^sk-[A-Za-z0-9_-]{20,}$');
  assert.equal(validateKeyFormat(openai, `sk-${'a'.repeat(24)}`), null);
  assert.equal(typeof validateKeyFormat(openai, 'sk-short'), 'string');

  const anthropic = catalog.get('anthropic');
  assert.equal(anthropic.keyPattern, '^sk-ant-[A-Za-z0-9_-]{20,}$');
  assert.equal(validateKeyFormat(anthropic, `sk-ant-${'a'.repeat(24)}`), null);
  assert.equal(typeof validateKeyFormat(anthropic, `sk-${'a'.repeat(24)}`), 'string');
  assert.deepEqual(anthropic.extraHeaders, { 'anthropic-version': '2023-06-01' });

  const stripe = catalog.get('stripe');
  assert.equal(stripe.keyPattern, '^(sk|rk)_(live|test)_[A-Za-z0-9]+$');
  assert.equal(validateKeyFormat(stripe, `sk_live_${'A'.repeat(24)}`), null);
  assert.equal(validateKeyFormat(stripe, `rk_test_${'A'.repeat(24)}`), null);
  assert.equal(typeof validateKeyFormat(stripe, `pk_live_${'A'.repeat(24)}`), 'string');

  const slack = catalog.get('slack');
  assert.equal(slack.keyPattern, '^xox[abp]-[A-Za-z0-9-]+$');
  assert.equal(validateKeyFormat(slack, 'xoxb-1234-abcd-EFGH'), null);
  assert.equal(typeof validateKeyFormat(slack, 'xoxz-1234'), 'string');
});

test('sensitive: только stripe и twilio', () => {
  assert.equal(catalog.get('stripe').sensitive, true);
  assert.equal(catalog.get('twilio').sensitive, true);
  for (const p of catalog.list()) {
    if (p.slug === 'stripe' || p.slug === 'twilio') continue;
    assert.notEqual(p.sensitive, true, p.slug);
  }
});

test('defaults применяются к провайдеру', () => {
  const gemini = catalog.get('gemini');
  assert.equal(gemini.maxBody, 2097152);
  assert.equal(gemini.timeout, 60);
  assert.equal(gemini.kind, 'static');
  assert.deepEqual(gemini.fields, ['key']);
  assert.equal(catalog.get('deepgram').maxBody, 209715200);
});

test('redactHeaders содержит заголовки всех header-инъекций', () => {
  const names = catalog.redactHeaders();
  for (const name of ['authorization', 'x-goog-api-key', 'xi-api-key', 'cookie', 'x-api-key']) {
    assert.ok(names.includes(name), `нет ${name}`);
  }
  assert.equal(new Set(names).size, names.length, 'имена не уникальны');
});

test('bitrix24: URL вебхука даёт портал, секрет user/code и last4', () => {
  const inj = buildInjection(catalog.get('bitrix24'), {
    webhook_url: 'https://mycompany.bitrix24.ru/rest/17/p4m2zq9w1v5c/crm.lead.add.json',
  });
  assert.equal(inj.host, 'mycompany.bitrix24.ru');
  assert.equal(inj.secret, '17/p4m2zq9w1v5c');
  assert.equal(inj.last4, 'w1v5c'.slice(-4));
  assert.deepEqual(inj.injection, { type: 'path', template: '/rest/{secret}' });
  assert.equal(inj.kind, 'path');
});

test('bitrix24: ссылка-пример из подсказки отклоняется', () => {
  const bitrix = catalog.get('bitrix24');
  const example = /https:\/\/\S+\/rest\/\S+\//.exec(bitrix.keyHint)[0];
  assert.throws(() => buildInjection(bitrix, { webhook_url: example }), /пример из подсказки/);
  assert.throws(() => buildInjection(bitrix, { webhook_url: `${example}crm.lead.add.json` }), /пример из подсказки/);
});

test('bitrix24: http:// отклоняется', () => {
  assert.throws(
    () => buildInjection(catalog.get('bitrix24'), {
      webhook_url: 'http://mycompany.bitrix24.ru/rest/17/k3j9fh2x8s7d/',
    }),
    /https/,
  );
});

test('bitrix24: адрес с IP отклоняется', () => {
  assert.throws(() => buildInjection(catalog.get('bitrix24'), {
    webhook_url: 'https://169.254.169.254/rest/17/k3j9fh2x8s7d/',
  }));
});

test('other: метадата-адрес и приватный IP отклоняются, домен принимается', () => {
  const other = catalog.get('other');
  assert.throws(() => buildInjection(other, { host: 'http://169.254.169.254/', header: 'x-key', key: 'k1' }));
  assert.throws(() => buildInjection(other, { host: 'https://10.0.0.1/', header: 'x-key', key: 'k1' }));
  assert.throws(() => buildInjection(other, { host: 'https://localhost/', header: 'x-key', key: 'k1' }));
  assert.throws(() => buildInjection(other, { host: 'https://api.example.com:8443/', header: 'x-key', key: 'k1' }));
  const ok = buildInjection(other, { host: 'api.example.com', header: 'X-Key', key: 'k1234' });
  assert.equal(ok.host, 'api.example.com');
  assert.deepEqual(ok.injection, { type: 'header', name: 'x-key' });
  assert.equal(ok.last4, '1234');
});

test('other: authorization без схемы получает префикс Bearer', () => {
  const ok = buildInjection(catalog.get('other'), { host: 'https://api.example.com/', header: 'Authorization', key: 'abc' });
  assert.deepEqual(ok.injection, { type: 'header', name: 'authorization', prefix: 'Bearer ' });
  // Ключ с пробелом внутри (например, «Token xyz») отклоняется общим правилом ключа.
  assert.throws(() => buildInjection(catalog.get('other'), { host: 'api.example.com', header: 'authorization', key: 'Token xyz' }), /пробел/);
});

test('amocrm: голый аккаунт, домен и полный URL дают один хост', () => {
  const amo = catalog.get('amocrm');
  const forms = ['mycompany', 'mycompany.amocrm.ru', 'https://mycompany.amocrm.ru/', 'https://mycompany.amocrm.ru/leads'];
  for (const account of forms) {
    const inj = buildInjection(amo, { account, key: 'token123' });
    assert.equal(inj.host, 'mycompany.amocrm.ru', account);
    assert.equal(inj.secret, 'token123');
  }
  assert.equal(buildInjection(amo, { account: 'mycompany.amocrm.com', key: 'token123' }).host, 'mycompany.amocrm.com');
});

test('amocrm: чужой домен отклоняется', () => {
  assert.throws(() => buildInjection(catalog.get('amocrm'), { account: 'evil.example.com', key: 'tok' }));
});

test('пустой ключ и ключ с пробелами отклоняются', () => {
  const gemini = catalog.get('gemini');
  assert.throws(() => buildInjection(gemini, { key: '   ' }), /Введите ключ/);
  assert.throws(() => buildInjection(gemini, { key: 'ab cd' }));
  assert.throws(() => buildInjection(gemini, { key: 'ab\ncd' }));
});

test('обычный провайдер: ключ обрезается, last4 — последние 4 символа', () => {
  const inj = buildInjection(catalog.get('groq'), { key: '  gsk_abcdefghijklmnopqrst1234  ' });
  assert.equal(inj.secret, 'gsk_abcdefghijklmnopqrst1234');
  assert.equal(inj.last4, '1234');
  assert.equal(inj.host, 'api.groq.com');
});

test('validateKeyFormat: gemini', () => {
  const gemini = catalog.get('gemini');
  assert.equal(typeof validateKeyFormat(gemini, 'sk-123'), 'string');
  assert.match(validateKeyFormat(gemini, 'sk-123'), /не тот ключ/);
  assert.equal(validateKeyFormat(gemini, 'AIza' + 'a'.repeat(35)), null);
});

test('validateKeyFormat: telegram', () => {
  const tg = catalog.get('telegram');
  assert.equal(validateKeyFormat(tg, `123456:${'A'.repeat(35)}`), null);
  assert.equal(typeof validateKeyFormat(tg, '123456:short'), 'string');
});

test('validateKeyFormat: без keyPattern всегда null', () => {
  assert.equal(validateKeyFormat(catalog.get('mistral'), 'anything'), null);
});

test('isValidOwnerHost: домен принимается, IP и localhost — нет', () => {
  assert.equal(isValidOwnerHost('api.example.com'), true);
  assert.equal(isValidOwnerHost('API.Example.com.'), true);
  assert.equal(isValidOwnerHost('10.0.0.1'), false);
  assert.equal(isValidOwnerHost('localhost'), false);
  assert.equal(isValidOwnerHost('svc.localhost'), false);
  assert.equal(isValidOwnerHost('[::1]'), false);
});
