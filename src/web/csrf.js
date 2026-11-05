// CSRF (П-22): токен — HMAC от сессии (или от pre-session cookie), в cookie не хранится.
// Cookie-подсадка с соседнего поддомена не работает: ключ HMAC знает только сервер, а на https cookie с префиксом __Host- подсадить нельзя.
// Вторым рубежом проверяется Origin (запасной вариант — Referer) у каждого POST сайта.
import crypto from 'node:crypto';
import fp from 'fastify-plugin';
import { t } from '../i18n.js';
import { cookieNames } from '../auth/session.js';

const KEY_META = 'csrf_key';
const PRE_RE = /^[A-Za-z0-9_-]{32}$/;
const PRE_MAX_AGE = 3600;
const NO_FORM = /^\/(?:public\/|v1\/|mcp(?:[/?]|$)|healthz(?:\?|$))/;

export const csrfPlugin = fp(async function (fastify, { secure, repo, publicUrl }) {
  // Ключ HMAC: 32 случайных байта, создаются один раз и живут в meta. В логи не попадает.
  let stored = repo.getMeta(KEY_META);
  if (!stored) { stored = crypto.randomBytes(32).toString('base64'); repo.setMeta(KEY_META, stored); }
  const key = Buffer.from(stored, 'base64');
  const mac = (scope, value) => crypto.createHmac('sha256', key).update(scope + ':' + value).digest('base64url');
  const { pre: PRE_COOKIE } = cookieNames(secure);
  const expectedOrigin = new URL(publicUrl).origin;

  // Источник запроса: Origin, при его отсутствии Referer; оба отсутствуют — разрешаем (токен всё равно обязателен).
  const originOk = (req) => {
    const origin = req.headers.origin;
    const src = origin !== undefined ? origin : req.headers.referer;
    if (src === undefined) return true;
    try { return new URL(String(src)).origin === expectedOrigin; } catch { return false; } // «null» не разбирается как URL → отказ
  };
  const deny = (reply, msgKey) => {
    reply.code(403).type('text/html; charset=utf-8');
    return reply.send('<!doctype html><meta charset=utf-8><p>' + t(msgKey) + '</p>');
  };

  fastify.decorateRequest('csrf', '');
  fastify.addHook('onRequest', async (req, reply) => {
    if (req.session) { req.csrf = mac('sid', req.session.id); return; }
    // статика, API агентов, MCP и healthz форм не показывают: cookie формы там не ставим
    // (иначе Set-Cookie попадал в ответ /public/* с Cache-Control: public — ревью staging R-5)
    if (NO_FORM.test(req.url)) return;
    let pre = req.cookies?.[PRE_COOKIE];
    if (!pre || !PRE_RE.test(pre)) {
      pre = crypto.randomBytes(24).toString('base64url');
      reply.setCookie(PRE_COOKIE, pre, { path: '/', httpOnly: true, secure, sameSite: 'strict', maxAge: PRE_MAX_AGE });
    }
    req.csrf = mac('pre', pre);
  });
  fastify.addHook('preHandler', async (req, reply) => {
    // /v1/ (REST агентов) и /mcp (Origin/Host проверяет сам MCP-сервер) — не формы сайта
    if (req.method !== 'POST' || req.url.startsWith('/v1/') || req.url === '/mcp' || req.url.startsWith('/mcp?')) return;
    if (!originOk(req)) return deny(reply, 'error.bad_origin');
    const sent = req.body?._csrf;
    // длины в байтах: символы не ASCII дают буфер длиннее строки, а timingSafeEqual на разных длинах бросает исключение
    const given = Buffer.from(typeof sent === 'string' ? sent : '');
    const expected = Buffer.from(req.csrf);
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
      return deny(reply, 'error.form_expired');
    }
  });
});
