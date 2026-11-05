// TOTP RFC 6238: 6 цифр, 30 с, окно ±1, каждый код принимается один раз (ТЗ §9.6)
import crypto from 'node:crypto';
import { t } from '../i18n.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s) {
  let bits = 0, value = 0; const out = [];
  for (const ch of s.toUpperCase().replace(/=+$/, '')) {
    const i = B32.indexOf(ch); if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

export function generateSecret() { return base32Encode(crypto.randomBytes(20)); }

export function otpauthUrl(secret, label, issuer = t('app.name')) {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function totpAt(secret, step) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const o = h[19] & 0xf;
  const code = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1_000_000;
  return String(code).padStart(6, '0');
}

/**
 * usedStore = { take(step:number): boolean } — атомарно помечает шаг использованным (П-32),
 * false, если шаг уже взят. Реализация: repo.takeTotpStep(userId, step), переживает перезапуск.
 */
export function verifyTotp(secret, code, usedStore, now = Date.now()) {
  if (!/^\d{6}$/.test(code)) return false;
  const step = Math.floor(now / 30000);
  for (const d of [0, -1, 1]) {
    const s = step + d;
    const expected = totpAt(secret, s);
    if (expected.length === code.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(code))) {
      return usedStore.take(s) === true;
    }
  }
  return false;
}

export function generateBackupCodes(n = 10) {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  return Array.from({ length: n }, () => Array.from(crypto.randomBytes(10), (b) => alphabet[b % alphabet.length]).join(''));
}
export function hashCode(code) { return crypto.createHash('sha256').update(code.trim().toLowerCase()).digest('hex'); }

export function encryptSecret(secret, key) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(secret, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), data].map((b) => b.toString('base64')).join('.');
}
export function decryptSecret(enc, key) {
  const [iv, tag, data] = enc.split('.').map((s) => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}

/** QR-код как SVG без зависимостей: минимальная реализация через модуль qr.js */
export { qrSvg } from './qr.js';
