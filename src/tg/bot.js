// Telegram-бот владельца: заявки на доступ с кнопками, /open, /keys, привязка по /start <код>.
// Состояние хранится в базе (repo); в памяти держим только ожидание 6-значного кода для tg_code (60 с).
import { Bot } from 'grammy';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { t } from '../i18n.js';
import { OWNER_USER_ID } from '../db/repo.js';

const REASON_MAX = 200;
const LINK_TTL_SEC = 900;
const TOTP_WAIT_MS = 60_000;
const TOTP_MAX_ATTEMPTS = 3;
const NO_PREVIEW = { is_disabled: true };

const sha256hex = (s) => createHash('sha256').update(String(s)).digest('hex');

/** Одна строка без управляющих и невидимых символов. */
function flat(s) {
  return String(s ?? '')
    .replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Человеческая длительность: 7200 → «2 ч», 300 → «5 мин», 5400 → «1 ч 30 мин». */
export function fmtDuration(sec) {
  const s = Math.max(0, Math.round(Number(sec) || 0));
  if (s < 60) return `${s} ${t('unit.s')}`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h === 0) return `${m} ${t('unit.min')}`;
  if (m === 0) return `${h} ${t('unit.h')}`;
  return `${h} ${t('unit.h')} ${m} ${t('unit.min')}`;
}

/**
 * Причина от агента для показа владельцу: плоский текст, без ссылок и упоминаний,
 * не длиннее 200 символов. Печатается как текст (parse_mode не используется).
 */
export function sanitizeReason(text) {
  let s = flat(text);
  s = s.replace(/:\/\//g, ' :// ');   // «https://x» → «https :// x»: схема перестаёт быть ссылкой
  s = s.replace(/@/g, '@ ');          // «@user» → «@ user»: упоминания не работают
  s = s.replace(/[«»]/g, '"');        // не ломаем кавычки-обёртку
  s = s.trim();
  const chars = Array.from(s);
  if (chars.length > REASON_MAX) s = chars.slice(0, REASON_MAX - 1).join('') + '…';
  return s || '—';
}

function mac12(key, verb, id) {
  return createHmac('sha256', key).update(`${verb}:${id}`).digest('hex').slice(0, 12);
}

/** callback_data кнопки: `a:{id}:{hmac12}` (разрешить) или `d:{id}:{hmac12}` (отклонить). */
export function callbackData(verb, id, key) {
  const data = `${verb}:${id}:${mac12(key, verb, id)}`;
  if (Buffer.byteLength(data) > 64) throw new Error('callback_data is longer than 64 bytes');
  return data;
}

/** Проверка callback_data. Возвращает { verb, id } или null (подделка, мусор). */
export function verifyCallback(data, key) {
  if (typeof data !== 'string') return null;
  const m = /^([ad]):([^:\s]{1,40}):([0-9a-f]{12})$/.exec(data);
  if (!m) return null;
  const [, verb, id, given] = m;
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(mac12(key, verb, id), 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  return { verb, id };
}

/** Текст заявки. Для редактирования после решения используется тот же текст. */
export function buildText(req, cred, agent, filterLine = () => '') {
  const lines = [
    t('bot.request_title'),
    t('bot.agent', { name: flat(agent?.name) || '—' }),
    t('bot.service', { service: cred ? `${flat(cred.provider)} / ${flat(cred.label)}` : '—' }),
    t('bot.term', { ttl: fmtDuration(req.ttl), calls: req.calls }),
    t('bot.reason', { reason: sanitizeReason(req.reason) }),
  ];
  // «Агент увидит: …» (п. 7.3): строка из фильтра ключа; сбой описания не должен лишить владельца заявки
  if (cred) { try { const l = filterLine(cred); if (l) lines.push(l); } catch { /* заявка уходит без строки */ } }
  if (cred && !String(cred.approval ?? '').startsWith('tg_')) {
    lines.push(t('bot.confirm_on_site'));
  }
  return lines.join('\n');
}

/**
 * Сообщение пришло из личного чата от его хозяина. Группы и каналы бот не слушает: там нажать
 * «Разрешить» мог бы любой участник (П-8). В личном чате chat.id совпадает с from.id.
 */
export function isPrivateFromSelf(chat, from) {
  return chat?.type === 'private' && from?.id !== undefined && Number(from.id) === Number(chat.id);
}

function errInfo(err) {
  return { name: err?.name, message: err?.message, code: err?.error_code ?? err?.code };
}

/**
 * @param {{ apiRoot?:string, token:string, repo:object, requests:object, links:object, logger:object,
 *           signingKey:Buffer, auth:object, publicUrl?:string, filterLine?:(cred:object)=>string }} deps
 *   filterLine — строка «Агент увидит: …» по ключу заявки (п. 7.3); по умолчанию пустая.
 *   publicUrl не нужен боту напрямую: ссылки строит links.makeLink.
 */
export function createBot({ token, repo, requests, links, logger, signingKey, auth, onLinked = () => {}, filterLine = () => '', apiRoot }) {
  // apiRoot — только для тестов (локальный поддельный Telegram API); в бою не задаётся
  const bot = new Bot(token, apiRoot ? { client: { apiRoot } } : undefined);
  // chat_id → { requestId, until, attempts } — ожидание 6 цифр после «Разрешить» при approval tg_code
  const totpWait = new Map();
  let usernameCache = null;

  // Кто такой «владелец» чата, решает модуль входа (auth.getUserByTelegram); бот сам таблицу не читает.
  const ownerChat = () => auth.getUser(OWNER_USER_ID)?.tgChatId ?? null;
  const isOwnerChat = (chatId) => {
    const u = auth.getUserByTelegram(chatId);
    return !!u && u.role === 'owner' && !u.disabled;
  };

  async function safeReply(chatId, text) {
    try {
      return await bot.api.sendMessage(chatId, text, { link_preview_options: NO_PREVIEW });
    } catch (err) {
      logger.error({ err: errInfo(err) }, 'tg: failed to send message');
      return null;
    }
  }

  async function removeButtons(ctx) {
    try {
      await ctx.editMessageReplyMarkup({ reply_markup: { inline_keyboard: [] } });
    } catch (err) {
      logger.warn({ err: errInfo(err) }, 'tg: failed to remove buttons');
    }
  }

  async function editDecided(req, status) {
    if (!req?.tg_message_id) return;
    const chatId = ownerChat();
    const line = ['approved', 'denied', 'expired'].includes(status) ? t(`bot.decided.${status}`) : null;
    if (chatId === null || !line) return;
    const cred = repo.getCredential(req.credential_id);
    const agent = repo.getAgent(req.agent_id);
    const text = `${buildText(req, cred, agent, filterLine)}\n${line}`;
    try {
      await bot.api.editMessageText(chatId, req.tg_message_id, text, {
        link_preview_options: NO_PREVIEW,
        reply_markup: { inline_keyboard: [] },
      });
    } catch (err) {
      logger.warn({ err: errInfo(err) }, 'tg: failed to update request message');
    }
  }

  async function sendRequest(req, cred, agent) {
    const chatId = ownerChat();
    if (chatId === null) return null;
    const extra = { link_preview_options: NO_PREVIEW };
    if (String(cred.approval ?? '').startsWith('tg_')) {
      extra.reply_markup = {
        inline_keyboard: [[
          { text: t('bot.approve'), callback_data: callbackData('a', req.id, signingKey) },
          { text: t('bot.deny'), callback_data: callbackData('d', req.id, signingKey) },
        ]],
      };
    }
    try {
      const msg = await bot.api.sendMessage(chatId, buildText(req, cred, agent, filterLine), extra);
      repo.setRequestTgMessage(req.id, msg.message_id);
      return msg.message_id;
    } catch (err) {
      logger.error({ err: errInfo(err) }, 'tg: failed to send request');
      return null;
    }
  }

  async function send(text) {
    const chatId = ownerChat();
    if (chatId === null) return null;
    try {
      const msg = await bot.api.sendMessage(chatId, String(text), { link_preview_options: NO_PREVIEW });
      return msg.message_id;
    } catch (err) {
      logger.error({ err: errInfo(err) }, 'tg: failed to send message to owner');
      return null;
    }
  }

  async function startWithCode(chatId, code, linked) {
    const ok = repo.consumeLink(sha256hex(code), 'tg_link');
    if (!ok) {
      if (!linked) await safeReply(chatId, t('bot.not_for_you'));
      return;
    }
    const botParam = repo.getOwner()?.tg_bot_param ?? null;
    repo.setTg(chatId, botParam);
    await safeReply(chatId, t('bot.owner_ok'));
    // событие безопасности «привязан Telegram» (контракт уведомлений); сбой уведомления привязку не отменяет
    try { onLinked(); } catch (e) { logger.warn({ errCode: e?.code }, 'tg: link notification failed'); }
  }

  // Первый middleware: всё, что не от владельца, молча игнорируется.
  // Исключение — /start: с кодом проверяем привязку; без кода — справка владельцу.
  // Только личный чат хозяина: привязка chat_id = привязка человека (П-8).
  bot.use(async (ctx, next) => {
    const chatId = ctx.chat?.id;
    if (chatId === undefined) return;
    if (!isPrivateFromSelf(ctx.chat, ctx.from)) return;
    const text = ctx.message?.text;
    const start = typeof text === 'string' ? /^\/start(?:@\S+)?(?:\s+(\S+))?\s*$/.exec(text) : null;
    const owned = isOwnerChat(chatId);
    const linked = ownerChat() !== null;

    if (start) {
      const code = start[1];
      if (code) return startWithCode(chatId, code, linked);
      if (!owned) {
        if (!linked) await safeReply(chatId, t('bot.not_for_you'));
        return;
      }
      return next();
    }
    if (!owned) return;
    return next();
  });

  bot.command('start', async (ctx) => {
    await safeReply(ctx.chat.id, t('bot.help'));
  });

  bot.command('open', async (ctx) => {
    const { url } = links.makeLink(repo, 'open', LINK_TTL_SEC);
    await ctx.reply(`${url}\n\n${t('bot.open_link')}`, {
      link_preview_options: NO_PREVIEW,
    });
  });

  bot.command('keys', async (ctx) => {
    const list = repo.listCredentials();
    if (!list.length) {
      await ctx.reply(t('bot.no_keys'));
      return;
    }
    const lines = list.map(
      (c) => t('bot.keys_line', { label: c.label, mode: ['always', 'ask', 'deny'].includes(c.mode) ? t(`bot.mode.${c.mode}`) : c.mode, ttl: fmtDuration(c.max_ttl) }),
    );
    await ctx.reply(lines.join('\n'), { link_preview_options: NO_PREVIEW });
  });

  // Кнопки «Разрешить» / «Отклонить» на заявках.
  bot.on('callback_query:data', async (ctx) => {
    const chatId = ctx.chat.id;
    const parsed = verifyCallback(ctx.callbackQuery.data, signingKey);
    if (!parsed) {
      await ctx.answerCallbackQuery();
      return;
    }
    const { verb, id } = parsed;
    const approve = verb === 'a';
    const req = repo.getRequest(id);
    const cred = req ? repo.getCredential(req.credential_id) : null;
    if (!req || req.status !== 'pending' || !cred) {
      await ctx.answerCallbackQuery({ text: t('bot.request_inactive') });
      await removeButtons(ctx);
      return;
    }

    if (approve && cred.approval === 'tg_code') {
      totpWait.set(chatId, { requestId: id, until: Date.now() + TOTP_WAIT_MS, attempts: 0 });
      await ctx.answerCallbackQuery();
      await safeReply(chatId, t('bot.enter_code'));
      return;
    }

    const res = await requests.decide({ requestId: id, approve, via: 'tg' });
    if (res?.error === 'use_web') {
      await ctx.answerCallbackQuery({ text: t('bot.use_web') });
      await removeButtons(ctx);
      return;
    }
    if (!res?.ok) {
      await ctx.answerCallbackQuery({ text: t('bot.request_inactive') });
      await removeButtons(ctx);
      return;
    }
    await ctx.answerCallbackQuery({ text: approve ? t('bot.decided.approved') : t('bot.decided.denied') });
    await editDecided(req, approve ? 'approved' : 'denied');
  });

  // Текст: 6 цифр — только если ждём TOTP-код; всё остальное — справка.
  bot.on('message:text', async (ctx) => {
    const chatId = ctx.chat.id;
    const text = ctx.message.text.trim();
    const wait = totpWait.get(chatId);
    if (!wait) {
      await safeReply(chatId, t('bot.help'));
      return;
    }
    if (wait.until < Date.now()) {
      totpWait.delete(chatId);
      await safeReply(chatId, t('bot.help'));
      return;
    }
    if (!/^\d{6}$/.test(text)) {
      await safeReply(chatId, t('bot.enter_digits'));
      return;
    }

    const req = repo.getRequest(wait.requestId);
    if (!req || req.status !== 'pending') {
      totpWait.delete(chatId);
      await safeReply(chatId, t('bot.request_inactive'));
      return;
    }
    const res = await requests.decide({ requestId: wait.requestId, approve: true, via: 'tg', totp: text });
    if (res?.ok) {
      totpWait.delete(chatId);
      await safeReply(chatId, t('bot.decided.approved'));
      await editDecided(req, 'approved');
      return;
    }
    if (res?.error === 'bad_code') {
      wait.attempts += 1;
      if (wait.attempts >= TOTP_MAX_ATTEMPTS) {
        totpWait.delete(chatId);
        await safeReply(chatId, t('bot.bad_code_final'));
      } else {
        await safeReply(chatId, t('bot.bad_code'));
      }
      return;
    }
    totpWait.delete(chatId);
    await safeReply(chatId, t('bot.request_inactive'));
    const fresh = repo.getRequest(wait.requestId);
    if (fresh && fresh.status !== 'pending') await editDecided(fresh, fresh.status);
  });

  // Ошибки обработчиков: только в лог, без текста сообщений пользователя.
  bot.catch((err) => {
    logger.error({ err: errInfo(err?.error ?? err) }, 'tg: handler error');
  });

  function start() {
    bot
      .start({
        drop_pending_updates: true,
        onStart: (info) => logger.info({ username: info?.username }, 'tg: bot started'),
      })
      .catch((err) => logger.error({ err: errInfo(err) }, 'tg: long polling stopped'));
  }

  async function stop() {
    if (bot.isRunning()) await bot.stop();
  }

  async function getUsername() {
    if (usernameCache === null) {
      const me = await bot.api.getMe();
      usernameCache = me.username;
    }
    return usernameCache;
  }

  return { start, stop, sendRequest, editDecided, send, getUsername };
}
