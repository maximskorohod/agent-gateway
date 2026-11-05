// Сессии сайта: cookie HttpOnly Secure SameSite=Strict, 12 ч, продление, не дольше 7 суток, до 3 полных сессий (ТЗ §6)
// Н-3: в cookie лежит случайный id (256 бит), в базе только idHash = sha256(id) hex. Хэш считается ТОЛЬКО здесь,
// слой repo получает уже хэш. Сырой id живёт в памяти запроса (req.session.id) для CSRF-HMAC и больше нигде не хранится.
import crypto from 'node:crypto';
import fp from 'fastify-plugin';
import { OWNER_USER_ID } from '../db/repo.js';

// Имена cookie: на https префикс __Host- (Secure, Path=/, без Domain) — соседний поддомен такую cookie подсадить не может (П-22).
export const cookieNames = (secure) => (secure ? { sid: '__Host-gw_sid', pre: '__Host-gw_pre' } : { sid: 'gw_sid', pre: 'gw_pre' });
export const hashSessionId = (id) => crypto.createHash('sha256').update(String(id)).digest('hex');
const TTL = 12 * 3600;
const MAX_LIFE = 7 * 86400;
const MAX_SESSIONS = 3;       // полных (с кодом) сессий
const MAX_HALF_SESSIONS = 5;  // половинных (только пароль), живут 10 минут
const DEMO_MAX_SESSIONS = 500; // демо: один общий владелец, посетители не должны вытеснять друг друга

// demo: сессия без пароля и 2FA считается «со свежим кодом» (requireRecentTotp в демо выполнен), лимит полных сессий выше
export const sessionPlugin = fp(async function (fastify, { repo, secure, demo = false }) {
  const maxSessions = demo ? DEMO_MAX_SESSIONS : MAX_SESSIONS;
  const now = () => Math.floor(Date.now() / 1000);
  const COOKIE = cookieNames(secure).sid;
  const clearAttrs = { path: '/', httpOnly: true, secure, sameSite: 'strict' };

  fastify.decorateRequest('session', null);
  fastify.addHook('onRequest', async (req) => {
    const sid = req.cookies?.[COOKIE];
    if (!sid) return;
    // №10: статика и healthz не читают и не продлевают сессию — поток картинок и пингов
    // не должен продлевать cookie и писать в базу на каждый запрос.
    const p = req.url.split('?', 1)[0];
    if (p === '/healthz' || p.startsWith('/public/')) return;
    const idHash = hashSessionId(sid);
    const s = repo.getSession(idHash);
    if (!s) return;
    if (now() - s.created_at > MAX_LIFE) { repo.deleteSession(idHash); return; }
    // половинная сессия (пароль введён, код — нет) живёт 10 минут и не продлевается
    if (!s.totp_ok) { if (now() - s.created_at > 600) { repo.deleteSession(idHash); return; } }
    else repo.touchSession(idHash, now() + TTL);
    req.session = { id: sid, idHash, userId: s.user_id, half: !s.totp_ok, totpAt: s.totp_at || 0 };
  });

  fastify.decorateReply('startSession', function (req) {
    // Выдача половинной сессии не трогает живые полные (П-32): пароль без кода не должен выбивать владельца.
    // Ограничиваем только число половинных: самые старые удаляются.
    const half = repo.listSessions().filter((x) => !x.totp_ok); // новые первыми
    for (const s of half.slice(MAX_HALF_SESSIONS - 1)) repo.deleteSession(s.id_hash);
    const id = crypto.randomBytes(32).toString('base64url');
    const idHash = hashSessionId(id);
    repo.createSession(idHash, now() + TTL, String(req.headers['user-agent'] || '').slice(0, 200), OWNER_USER_ID);
    this.setCookie(COOKIE, id, { path: '/', httpOnly: true, secure, sameSite: 'strict', maxAge: MAX_LIFE });
    req.session = { id, idHash, userId: OWNER_USER_ID, half: true, totpAt: 0 };
    return id;
  });
  fastify.decorateReply('endSession', function (req) {
    if (req.session) repo.deleteSession(req.session.idHash);
    this.clearCookie(COOKIE, clearAttrs);
    req.session = null;
  });
  fastify.decorateReply('endAllSessions', function (req) {
    repo.deleteAllSessions();
    this.clearCookie(COOKIE, clearAttrs);
    req.session = null;
  });

  // Код принят: сессия становится полной, самые старые полные вытесняются до лимита (П-32).
  // Синхронно, без await: эффективно атомарно в одном процессе.
  fastify.decorateRequest('markTotp', function () {
    if (!this.session) return;
    repo.setSessionTotp(this.session.idHash);
    this.session.totpAt = now(); this.session.half = false;
    const full = repo.listSessions().filter((x) => x.totp_ok && x.id_hash !== this.session.idHash); // новые первыми
    for (const s of full.slice(maxSessions - 1)) repo.deleteSession(s.id_hash);
  });
  fastify.decorateRequest('hasRecentTotp', function (maxAge = 300) {
    if (demo) return !!this.session && !this.session.half;
    return !!this.session && now() - this.session.totpAt <= maxAge;
  });
});
