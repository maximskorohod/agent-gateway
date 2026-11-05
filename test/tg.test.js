import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createBot,
  fmtDuration,
  sanitizeReason,
  callbackData,
  verifyCallback,
} from '../src/tg/bot.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const KEY = Buffer.from('test-signing-key-0123456789abcdef');

test('sanitizeReason обрезает до 200 символов', () => {
  const out = sanitizeReason('я'.repeat(500));
  assert.ok(Array.from(out).length <= 200);
});

test('sanitizeReason убирает переводы строк', () => {
  const out = sanitizeReason('первая\nвторая\r\nтретья\n\n');
  assert.ok(!/[\r\n]/.test(out));
  assert.equal(out, 'первая вторая третья');
});

test('sanitizeReason нейтрализует ссылки и упоминания', () => {
  const out = sanitizeReason('см. https://evil и @user');
  assert.ok(!out.includes('https://'));
  assert.ok(!out.includes('@user'));
});

test('callbackData и verifyCallback: верный hmac проходит, длина ≤ 64', () => {
  const id = 'r'.repeat(32);
  const approve = callbackData('a', id, KEY);
  assert.ok(Buffer.byteLength(approve) <= 64);
  assert.deepEqual(verifyCallback(approve, KEY), { verb: 'a', id });

  const deny = callbackData('d', id, KEY);
  assert.ok(Buffer.byteLength(deny) <= 64);
  assert.deepEqual(verifyCallback(deny, KEY), { verb: 'd', id });
});

test('verifyCallback: подделанный hmac отклоняется', () => {
  const data = callbackData('a', 'req1', KEY);
  const last = data.slice(-1);
  const forged = data.slice(0, -1) + (last === '0' ? '1' : '0');
  assert.equal(verifyCallback(forged, KEY), null);
});

test('verifyCallback: подмена глагола, чужой ключ и мусор отклоняются', () => {
  const data = callbackData('a', 'req1', KEY);
  assert.equal(verifyCallback('d:' + data.slice(2), KEY), null);
  assert.equal(verifyCallback(data, Buffer.from('other-key')), null);
  assert.equal(verifyCallback('x:req1:000000000000', KEY), null);
  assert.equal(verifyCallback(undefined, KEY), null);
});

test('fmtDuration: человеческий вид срока', () => {
  assert.equal(fmtDuration(7200), '2 ч');
  assert.equal(fmtDuration(300), '5 мин');
  assert.equal(fmtDuration(5400), '1 ч 30 мин');
});

test('createBot: stop() без запущенного бота не падает (сети нет)', async () => {
  const bot = createBot({
    token: '123:test',
    repo: {},
    requests: {},
    links: {},
    logger: { info() {}, warn() {}, error() {} },
    signingKey: KEY,
  });
  await bot.stop();
});
