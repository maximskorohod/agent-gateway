// Ревью L4: connectTelegram сначала проверяет новый токен (getMe), и только потом пишет в сейф и перезапускает бота.
// Сети нет: поддельный Telegram API на localhost (overrides.tgApiRoot).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { buildApp } from '../src/app.js';
import { hashPassword } from '../src/auth/password.js';
import { makeLink } from '../src/auth/links.js';
import * as totp from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const dirs = [];
const closers = [];
after(async () => {
  for (const f of closers.reverse()) await f().catch(() => {}); // сначала приложение, потом поддельный Telegram
  for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* Windows: файл ещё занят */ } }
});

const mkToken = () => `${100000 + crypto.randomInt(900000)}:${crypto.randomBytes(27).toString('base64url').slice(0, 35)}`;

/** Поддельный Telegram API: getMe отвечает ok только для токенов из списка good. */
async function fakeTelegram(good) {
  const calls = [];
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const m = req.url.match(/^\/bot([^/]+)\/(\w+)/);
      const [token, method] = m ? [m[1], m[2]] : ['', ''];
      calls.push({ token, method });
      res.setHeader('content-type', 'application/json');
      if (!good.has(token)) { res.statusCode = 401; return res.end(JSON.stringify({ ok: false, error_code: 401, description: 'Unauthorized' })); }
      if (method === 'getMe') return res.end(JSON.stringify({ ok: true, result: { id: 1, is_bot: true, first_name: 'gw', username: 'gw_test_bot' } }));
      if (method === 'getUpdates') return void setTimeout(() => res.end(JSON.stringify({ ok: true, result: [] })), 150);
      return res.end(JSON.stringify({ ok: true, result: true }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  closers.push(async () => { server.close(); server.closeAllConnections?.(); });
  return { calls, apiRoot: `http://127.0.0.1:${server.address().port}` };
}

function client(base) {
  const jar = new Map();
  const c = { token: '' };
  const store = (res) => { for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); } };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' });
    store(r);
    const m = (await r.text()).match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    return r;
  };
  c.post = async (p, fields = {}) => {
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ _csrf: c.token, ...fields }), redirect: 'manual' });
    store(r);
    return r;
  };
  return c;
}

test('L4: неверный токен бота не затирает рабочий; верный пишется в сейф после проверки getMe', async () => {
  const oldToken = mkToken();
  const newToken = mkToken();
  const typo = mkToken();
  const tg = await fakeTelegram(new Set([oldToken, newToken]));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-tgc-'));
  dirs.push(dir);
  const app = await buildApp({ dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', tgApiRoot: tg.apiRoot });
  closers.push(() => app.stop());
  app.repo.setPasswordHash(await hashPassword('correct-horse-battery'));
  app.repo.setTotp(totp.encryptSecret(totp.generateSecret(), app.ctx.keys.totp), 1);
  app.repo.setSetupDone();
  await app.ctx.vault.put('sys/tg_bot', oldToken);
  await app.start();
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const c = client(base);
  assert.equal((await c.get(`/setup/${makeLink(app.repo, 'setup', 900, base).token}`)).status, 302);
  await c.get('/settings');

  // опечатка: getMe не проходит, в сейфе по-прежнему рабочий токен, бот не перезапускался
  await c.post('/settings/telegram/connect', { token: typo });
  assert.equal(await app.ctx.vault.get('sys/tg_bot'), oldToken, 'рабочий токен не затёрт');
  assert.ok(tg.calls.some((x) => x.token === typo && x.method === 'getMe'), 'новый токен проверен через getMe');
  assert.ok(!tg.calls.some((x) => x.token === typo && x.method === 'getUpdates'), 'бот с неверным токеном не запускался');

  // верный токен: проверка, запись, перезапуск
  await c.get('/settings');
  await c.post('/settings/telegram/connect', { token: newToken });
  assert.equal(await app.ctx.vault.get('sys/tg_bot'), newToken, 'новый токен записан');
  assert.ok(tg.calls.some((x) => x.token === newToken && x.method === 'getMe'));
  assert.ok(app.ctx.tg.current(), 'бот запущен');
});
