// Удаление ключа (ревью 9.1): сначала сейф, потом база. Сбой сейфа не оставляет сироту в сейфе: запись ключа
// остаётся, повторное удаление проходит. Без сети: vault file, секреты собираются в рантайме.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';

let app, base, totpSecret;
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
let csrfTok = '';
async function grabCsrf(r) { if (/html/.test(r.headers.get('content-type') || '')) { const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/); if (m) csrfTok = m[1]; } }
async function get(p) { const r = await fetch(base + p, { headers: { cookie: cookieHeader() }, redirect: 'manual' }); storeCookies(r); await grabCsrf(r); return r; }
async function post(p, fields) {
  const body = new URLSearchParams({ _csrf: csrfTok });
  for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
  const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
  storeCookies(r); return r;
}
const POLICY = { mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' };

before(async () => {
  initI18n('en');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-del-'));
  app = await buildApp({ dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent' });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await get(`/setup/${token}`); await get('/setup');
  await post('/setup', { step: '1', password: 'correct-horse-battery', password_repeat: 'correct-horse-battery' });
  totpSecret = (await (await get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  await post('/setup', { step: '2', code: totpAt(totpSecret, Math.floor(Date.now() / 30000)) });
  await post('/setup', { step: '3', mode: 'skip' });
});
after(async () => { await app.stop(); });

test('удаление ключа: сбой сейфа не оставляет сироту, повтор удаляет и запись, и секрет', async () => {
  const sid = 'AC' + crypto.randomBytes(16).toString('hex');
  const r0 = await post('/keys/new/twilio', { account: sid, key: crypto.randomBytes(16).toString('hex'), ...POLICY });
  assert.equal(r0.status, 302);
  const cred = app.repo.listCredentials()[0];
  assert.ok(await app.ctx.vault.get(`cred/${cred.id}`));

  const realDel = app.ctx.vault.del;
  app.ctx.vault.del = async () => { throw new Error('vault down'); };
  try {
    const r = await post(`/keys/${cred.id}/delete`, {});
    assert.ok(r.status >= 500, `сбой сейфа должен давать ошибку, а не 302 (получено ${r.status})`);
  } finally {
    app.ctx.vault.del = realDel;
  }
  // запись ключа на месте: владелец видит его и может повторить удаление; секрет в сейфе не осиротел
  assert.equal(app.repo.listCredentials().length, 1, 'запись ключа осталась');
  assert.ok(await app.ctx.vault.get(`cred/${cred.id}`), 'секрет в сейфе на месте');

  const again = await post(`/keys/${cred.id}/delete`, {});
  assert.equal(again.status, 302);
  assert.equal(app.repo.listCredentials().length, 0);
  assert.equal(await app.ctx.vault.get(`cred/${cred.id}`), null);
});
