// Одноразовые ссылки: 128 бит случайности, в базе только sha256, сравнение по хэшу (ТЗ §9.3)
import crypto from 'node:crypto';

export function sha256hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

export function makeLink(repo, purpose, ttlSec, publicUrl) {
  const token = crypto.randomBytes(16).toString('base64url');
  repo.createLink(sha256hex(token), purpose, Math.floor(Date.now() / 1000) + ttlSec);
  const pathByPurpose = { setup: `/setup/${token}`, open: `/l/${token}`, tg_link: null };
  const p = pathByPurpose[purpose];
  return { token, url: p ? publicUrl + p : null };
}

export function consumeLink(repo, token, purpose) {
  if (typeof token !== 'string' || token.length < 8 || token.length > 64) return false;
  return repo.consumeLink(sha256hex(token), purpose);
}

/** Короткий код для /start в Telegram: 8 символов без неоднозначных букв */
export function makeShortCode(repo, purpose, ttlSec) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const code = Array.from(crypto.randomBytes(8), (b) => alphabet[b % alphabet.length]).join('');
  repo.createLink(sha256hex(code), purpose, Math.floor(Date.now() / 1000) + ttlSec);
  return code;
}
