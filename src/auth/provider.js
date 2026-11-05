// Сменный модуль входа (контракт drafts-team-auth.md, docs/AUTH.md).
// Веб-слой и Telegram-бот знают только этот интерфейс. Роли, сессии, CSRF и лимиты по IP остаются у шлюза.
// Единственная реализация в 1.0 — local; имя слота supabase зарезервировано (кода нет).
import { hashPassword, verifyPassword } from './password.js';
import * as totp from './totp.js';
import { createLockout } from '../core/ratelimit.js';
import { OWNER_USER_ID } from '../db/repo.js';

/** Провайдер по умолчанию, если config.authProvider пуст (GW_AUTH_PROVIDER не задан). */
export const DEFAULT_PROVIDER = 'local';
const KNOWN = ['local', 'supabase'];

const USER_FAILS_MAX = 5;           // ошибок пароля (и отдельно кода) до блокировки пользователя
const USER_LOCK_SEC = 900;
// Блокировки 5/15 мин считаются по паре «пользователь + адрес клиента»: чужой перебор не запирает владельца.
// Глобальный счётчик ошибок пароля (любые адреса) вход НЕ блокирует: иначе распределённый перебор запирал бы владельца.
// Он лишь сигнализирует (alert в ответе verifyLogin), не чаще раза в окно. Вход всё равно требует второй фактор.
const USER_GLOBAL_PASS_FAILS_MAX = 50;   // ошибок пароля на пользователя за окно (любые адреса) до уведомления
const USER_GLOBAL_ALERT_MS = USER_LOCK_SEC * 1000;
const USER_CODE_FAILS_MAX = 30;     // потолок ошибок кода на пользователя в час (любые адреса): защищает 6-значный TOTP
const HOUR_MS = 3600_000;

/**
 * @typedef {{ id:string, login:string, name:string, role:'owner'|'viewer', disabled:boolean, totpEnabled:boolean, tgChatId:number|null, externalId:string|null }} AuthUser
 * Остальные типы (ProviderInfo, AuthProvider) описаны в docs/AUTH.md и docs/ARCHITECTURE.md.
 */

/**
 * @param {{ config:object, repo:object, keys:{totp:Buffer}, logger?:object }} deps
 * @returns {object} AuthProvider
 */
export function createAuthProvider({ config, repo, keys, logger }) {
  const name = String(config.authProvider || '').trim().toLowerCase() || DEFAULT_PROVIDER;
  if (!KNOWN.includes(name)) throw new Error(`Unknown auth provider "${name}". Supported: ${DEFAULT_PROVIDER}`);
  if (name !== DEFAULT_PROVIDER) throw new Error(`Auth provider "${name}" is not implemented in this release. Supported: ${DEFAULT_PROVIDER}`);
  return createLocalProvider({ config, repo, keys, logger });
}

function createLocalProvider({ config, repo, keys }) {
  const lockout = createLockout({ lockAfter: USER_FAILS_MAX, lockSec: USER_LOCK_SEC });
  const globalLockout = createLockout({ lockAfter: USER_GLOBAL_PASS_FAILS_MAX, lockSec: USER_LOCK_SEC });
  const codeFails = new Map(); // userId -> [timestamp ms] ошибок кода за последний час
  let lastGlobalAlert = 0;     // когда последний раз сообщали о распределённом переборе пароля

  // Пока таблицы users нет (6.4), единственный пользователь — владелец из строки owner.
  function toUser(o) {
    if (!o || !o.password_hash) return null;
    return {
      id: OWNER_USER_ID, login: 'owner', name: 'Owner', role: 'owner', disabled: false,
      totpEnabled: !!o.totp_enabled, tgChatId: o.tg_chat_id ?? null, externalId: null,
    };
  }
  const getUser = (userId) => (userId === OWNER_USER_ID ? toUser(repo.getOwner()) : null);

  // Фиктивный хэш: неизвестный логин тратит столько же времени, сколько неверный пароль
  let dummy = null;
  const dummyHash = () => (dummy ??= hashPassword('dummy-password-for-timing'));

  // ip — ключ клиента от вызывающего (IPv6 уже сведён к /64); без него все вызовы делят один ключ '-'
  const ipPart = (ip) => String(ip || '-').slice(0, 64);
  const passKey = (id, ip) => `u:${id}|${ipPart(ip)}`;
  const codeKey = (id, ip) => `uc:${id}|${ipPart(ip)}`;
  const globalPassKey = (id) => `ug:${id}`;
  const ceilingHit = (id) => {
    const arr = codeFails.get(id); if (!arr) return false;
    const edge = Date.now() - HOUR_MS;
    while (arr.length && arr[0] < edge) arr.shift();
    return arr.length >= USER_CODE_FAILS_MAX;
  };

  return {
    name: 'local',
    capabilities: { password: true, secondFactor: 'local', external: false, manageCredentials: true },

    async verifyLogin({ login, password, ip } = {}) {
      const pw = String(password ?? '');
      const wanted = String(login ?? '').trim().toLowerCase();
      const user = getUser(OWNER_USER_ID);
      // логин необязателен, пока пользователь один
      const match = user && (!wanted || wanted === user.login);
      if (!match) {
        await verifyPassword(await dummyHash(), pw);
        const k = passKey('?' + wanted.slice(0, 64));
        if (lockout.locked(k)) return { ok: false, reason: 'locked' };
        lockout.fail(k);
        return { ok: false, reason: 'bad' };
      }
      if (user.disabled) return { ok: false, reason: 'disabled' };
      if (lockout.locked(passKey(user.id, ip))) return { ok: false, reason: 'locked' };
      const ok = await verifyPassword(repo.getOwner().password_hash, pw);
      if (!ok) {
        lockout.fail(passKey(user.id, ip));
        // порог глобального счётчика достигнут: вход не блокируем, только просим вызывающего уведомить владельца (не чаще раза в окно)
        const crossed = globalLockout.fail(globalPassKey(user.id));
        if (crossed && Date.now() - lastGlobalAlert >= USER_GLOBAL_ALERT_MS) { lastGlobalAlert = Date.now(); return { ok: false, reason: 'bad', alert: 'distributed' }; }
        return { ok: false, reason: 'bad' };
      }
      return { ok: true, user };
    },

    async verifySecondFactor({ userId, code, ip } = {}) {
      const user = getUser(userId);
      if (!user || user.disabled) return { ok: false, reason: 'bad' };
      if (lockout.locked(codeKey(user.id, ip)) || ceilingHit(user.id)) return { ok: false, reason: 'locked' };
      const c = String(code ?? '').trim();
      let kind = null;
      if (/^\d{6}$/.test(c)) {
        const enc = repo.getOwner().totp_secret_enc;
        if (enc && totp.verifyTotp(totp.decryptSecret(enc, keys.totp), c, { take: (step) => repo.takeTotpStep(user.id, step) })) kind = 'totp';
      } else if (/^[a-z0-9]{10}$/i.test(c)) {
        if (repo.useBackupCode(totp.hashCode(c))) kind = 'backup';
      }
      if (!kind) {
        lockout.fail(codeKey(user.id, ip));
        const arr = codeFails.get(user.id) || []; arr.push(Date.now()); codeFails.set(user.id, arr);
        return { ok: false, reason: 'bad' };
      }
      // полный вход пройден: счётчики пользователя обнуляются (пароль — тоже, как раньше у адреса)
      // чужие адреса не сбрасываем: сброс идёт только для адреса, с которого прошёл вход
      lockout.reset(codeKey(user.id, ip)); lockout.reset(passKey(user.id, ip)); globalLockout.reset(globalPassKey(user.id)); codeFails.delete(user.id);
      return { ok: true, kind };
    },

    getUser,
    getUserByTelegram(chatId) {
      const u = toUser(repo.getOwner());
      return u && u.tgChatId !== null && Number(u.tgChatId) === Number(chatId) ? u : null;
    },

    // ---- управление данными для входа (capabilities.manageCredentials)
    async setPassword(userId, newPassword) {
      if (userId !== OWNER_USER_ID) throw new Error('Unknown user');
      repo.setPasswordHash(await hashPassword(String(newPassword)));
    },
    async beginSecondFactorEnrollment(userId) {
      if (userId !== OWNER_USER_ID) throw new Error('Unknown user');
      const secret = totp.generateSecret();
      return { secret, otpauthUrl: totp.otpauthUrl(secret, new URL(config.publicUrl).host) };
    },
    async confirmSecondFactorEnrollment(userId, secret, code) {
      if (userId !== OWNER_USER_ID || !secret) return { ok: false };
      const used = { take: (step) => repo.takeTotpStep(userId, step) };
      if (!totp.verifyTotp(secret, String(code ?? '').trim(), used)) return { ok: false };
      const backupCodes = totp.generateBackupCodes();
      repo.replaceBackupCodes(backupCodes.map(totp.hashCode));
      repo.setTotp(totp.encryptSecret(secret, keys.totp), 1);
      return { ok: true, backupCodes };
    },
    // Дополнение к контракту: новый набор резервных кодов без смены секрета (кнопка в настройках)
    async regenerateBackupCodes(userId) {
      if (userId !== OWNER_USER_ID) throw new Error('Unknown user');
      const backupCodes = totp.generateBackupCodes();
      repo.replaceBackupCodes(backupCodes.map(totp.hashCode));
      return backupCodes;
    },
  };
}
