// П-8: первый middleware Telegram-бота пропускает только личный чат владельца (chat.type private, from.id == chat.id).
// Группы, чужие чаты и подмена from.id молча игнорируются. Сети нет: поддельный Telegram API на localhost (опция apiRoot).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createBot } from '../src/tg/bot.js';
import { initI18n, t } from '../src/i18n.js';

initI18n('en');

const OWNER = 4242;
const STRANGER = 777;
const KEY = Buffer.from('test-signing-key-0123456789abcdef');

/** Поддельный Telegram API: первый getUpdates отдаёт заданные обновления, дальше пусто; sendMessage записывается. */
async function fakeTelegram(updates) {
  const sent = [];
  let served = false;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const method = req.url.split('/').pop();
      const reply = (result) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true, result })); };
      let params = {};
      try { params = JSON.parse(body || '{}'); } catch { /* не JSON */ }
      if (method === 'getMe') return reply({ id: 1, is_bot: true, first_name: 'gw', username: 'gw_test_bot' });
      if (method === 'getUpdates') {
        if (!served) { served = true; return reply(updates); }
        return setTimeout(() => reply([]), 150);
      }
      if (method === 'sendMessage') { sent.push(params); return reply({ message_id: 1, date: 0, chat: { id: params.chat_id } }); }
      return reply(true);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { sent, apiRoot: `http://127.0.0.1:${server.address().port}`, close: () => { server.close(); server.closeAllConnections?.(); } };
}

const msg = (id, chat, from, text) => ({ update_id: id, message: { message_id: id, date: 0, chat, from: { is_bot: false, first_name: 'x', ...from }, text, entities: text.startsWith('/') ? [{ type: 'bot_command', offset: 0, length: text.split(' ')[0].length }] : undefined } });

test('П-8: бот отвечает только в личном чате владельца; группа, чужой чат и подмена from.id игнорируются', async () => {
  const consumed = [];
  const tgSet = [];
  const updates = [
    msg(1, { id: -100500, type: 'group' }, { id: OWNER }, '/keys'),             // владелец, но группа
    msg(2, { id: STRANGER, type: 'private' }, { id: STRANGER }, 'hello'),        // чужой личный чат
    msg(3, { id: OWNER, type: 'private' }, { id: STRANGER }, '/keys'),           // from.id не совпадает с chat.id
    msg(4, { id: -100500, type: 'supergroup' }, { id: OWNER }, '/start somecode'), // привязка из группы
    msg(5, { id: STRANGER, type: 'private' }, { id: STRANGER }, '/start somecode'), // чужой с кодом при уже привязанном владельце
    msg(6, { id: OWNER, type: 'private' }, { id: OWNER }, '/keys'),              // единственное, что должно дойти
  ];
  const tg = await fakeTelegram(updates);
  const owner = { id: 'owner', role: 'owner', disabled: false, tgChatId: OWNER };
  const bot = createBot({
    token: '123:test',
    apiRoot: tg.apiRoot,
    repo: {
      listCredentials: () => [],
      consumeLink: (h, p) => { consumed.push(p); return false; },
      setTg: (c) => tgSet.push(c),
      getOwner: () => ({ tg_bot_param: null }),
    },
    requests: {},
    links: {},
    logger: { info() {}, warn() {}, error() {} },
    signingKey: KEY,
    auth: { getUser: () => owner, getUserByTelegram: (id) => (Number(id) === OWNER ? owner : null) },
  });
  try {
    bot.start();
    const deadline = Date.now() + 5000;
    while (!tg.sent.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 200)); // дать шанс лишним ответам, если они есть
    assert.equal(tg.sent.length, 1, `ожидался один ответ, получено ${tg.sent.length}`);
    assert.equal(Number(tg.sent[0].chat_id), OWNER);
    assert.equal(tg.sent[0].text, t('bot.no_keys'));
    // код проверяется только для личного чата (чужой /start с неверным кодом молча отклонён), из группы — не проверяется
    assert.deepEqual(consumed, ['tg_link']);
    assert.deepEqual(tgSet, [], 'привязка не менялась');
  } finally {
    await bot.stop();
    tg.close();
  }
});
