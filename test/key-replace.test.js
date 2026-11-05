// Замена ключа (П-25): все провайдеры, привязка к тому же адресу, форма по полям провайдера.
// Без сети: vault file, ключи только сохраняются. Секреты собираются в рантайме.
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
import en from '../src/i18n/en.js';
import ru from '../src/i18n/ru.js';

let app, base, totpSecret;
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function storeCookies(res) {
  for (const c of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = c.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
}
// CSRF-токен берётся из последней показанной формы (в cookie он не хранится, П-22)
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
const rnd = (n = 20) => crypto.randomBytes(n).toString('hex').slice(0, n);
const sid = () => 'AC' + crypto.randomBytes(16).toString('hex');
const secret = (id) => app.ctx.vault.get(`cred/${id}`);
const add = async (slug, fields) => {
  const before = new Set(app.repo.listCredentials().map((c) => c.id));
  const r = await post(`/keys/new/${slug}`, { ...fields, ...POLICY });
  assert.equal(r.status, 302, `создание ${slug}`);
  return app.repo.listCredentials().find((c) => !before.has(c.id));
};
/** Замена: возвращает текст страницы ключа после редиректа (флеш с итогом). */
async function replace(id, fields) {
  const r = await post(`/keys/${id}/replace`, fields);
  assert.equal(r.status, 302);
  return (await (await get(`/keys/${id}`)).text()).match(/<div class="flash[^>]*>([^<]*)</)?.[1] ?? '';
}
const detail = async (id) => (await get(`/keys/${id}`)).text();
/** Часть страницы с формой замены. */
const replaceForm = async (id) => {
  const h = await detail(id);
  const i = h.indexOf(`action="/keys/${id}/replace"`);
  assert.ok(i > 0, 'форма замены есть');
  return h.slice(i, h.indexOf('</form>', i));
};
const names = (formHtml) => [...formHtml.matchAll(/<input[^>]*\bname="([a-z_]+)"/g)].map((m) => m[1]).filter((n) => n !== '_csrf');

before(async () => {
  initI18n('en');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-repl-'));
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

test('Twilio: замена Account SID + токен проходит, хост остался api.twilio.com', async () => {
  const [s1, t1, t2] = [sid(), rnd(32), rnd(32)];
  const c = await add('twilio', { account: s1, key: t1 });
  assert.equal(await secret(c.id), `${s1}:${t1}`);
  const s2 = sid();
  const msg = await replace(c.id, { account: s2, key: t2 });
  assert.equal(msg, en['flash.key_replaced']);
  assert.equal(await secret(c.id), `${s2}:${t2}`);
  assert.equal(app.repo.getCredential(c.id).last4, t2.slice(-4));
  assert.equal(app.repo.getCredential(c.id).host, 'api.twilio.com');
});

test('Twilio: SID неверного формата — ошибка, секрет не тронут', async () => {
  const [s1, t1] = [sid(), rnd(32)];
  const c = await add('twilio', { account: s1, key: t1 });
  const msg = await replace(c.id, { account: 'not-a-sid', key: rnd(32) });
  assert.match(msg, /account ID doesn/);
  assert.equal(await secret(c.id), `${s1}:${t1}`);
  assert.equal(app.repo.getCredential(c.id).last4, t1.slice(-4));
});

test('Zendesk: замена с account + email + токен', async () => {
  const [k1, k2] = [rnd(24), rnd(24)];
  const c = await add('zendesk', { account: 'acme', email: 'owner@acme.test', key: k1 });
  assert.equal(c.host, 'acme.zendesk.com');
  const msg = await replace(c.id, { account: 'acme', email: 'new@acme.test', key: k2 });
  assert.equal(msg, en['flash.key_replaced']);
  assert.equal(await secret(c.id), `new@acme.test/token:${k2}`);
  assert.equal(app.repo.getCredential(c.id).last4, k2.slice(-4));
});

test('Zendesk без e-mail и с другим аккаунтом — отказ, секрет не тронут', async () => {
  const k1 = rnd(24);
  const c = await add('zendesk', { account: 'acme2', email: 'owner@acme.test', key: k1 });
  const orig = await secret(c.id);
  let msg = await replace(c.id, { account: 'acme2', key: rnd(24) });
  assert.equal(msg, en['catalog.err.email']);
  msg = await replace(c.id, { account: 'other', email: 'owner@acme.test', key: rnd(24) });
  assert.ok(msg.startsWith('The new key belongs to a different address (other.zendesk.com)'), msg);
  assert.equal(await secret(c.id), orig);
  assert.equal(app.repo.getCredential(c.id).last4, k1.slice(-4));
});

test('amoCRM: тот же аккаунт — ок, другой — отказ', async () => {
  const [k1, k2, k3] = [rnd(30), rnd(30), rnd(30)];
  const c = await add('amocrm', { account: 'shop.amocrm.ru', key: k1 });
  assert.equal(c.host, 'shop.amocrm.ru');
  assert.equal(await replace(c.id, { account: 'shop.amocrm.ru', key: k2 }), en['flash.key_replaced']);
  assert.equal(await secret(c.id), k2);
  const msg = await replace(c.id, { account: 'rival.amocrm.ru', key: k3 });
  assert.match(msg, /different address \(rival\.amocrm\.ru\)/);
  assert.ok(!msg.includes(k3));
  assert.equal(await secret(c.id), k2);
  assert.equal(app.repo.getCredential(c.id).last4, k2.slice(-4));
});

test('Bitrix24: вебхук того же портала — ок', async () => {
  const [c1, c2] = [rnd(16), rnd(16)];
  const c = await add('bitrix24', { webhook_url: `https://portal1.bitrix24.ru/rest/17/${c1}/` });
  assert.equal(c.host, 'portal1.bitrix24.ru');
  assert.equal(await replace(c.id, { webhook_url: `https://portal1.bitrix24.ru/rest/17/${c2}/` }), en['flash.key_replaced']);
  assert.equal(await secret(c.id), `17/${c2}`);
  assert.equal(app.repo.getCredential(c.id).last4, c2.slice(-4));
});

test('П-25: вебхук Bitrix24 другого портала — отказ, секрет и last4 прежние', async () => {
  const [c1, c2] = [rnd(16), rnd(16)];
  const c = await add('bitrix24', { webhook_url: `https://portal1.bitrix24.ru/rest/17/${c1}/` });
  const msg = await replace(c.id, { webhook_url: `https://evil.bitrix24.ru/rest/17/${c2}/` });
  assert.match(msg, /different address \(evil\.bitrix24\.ru\)/);
  assert.ok(!msg.includes(c2));
  assert.equal(await secret(c.id), `17/${c1}`);
  assert.equal(app.repo.getCredential(c.id).last4, c1.slice(-4));
});

test('bitrix24-box: другой адрес портала — отказ, тот же — ок', async () => {
  const [c1, c2, c3] = [rnd(16), rnd(16), rnd(16)];
  const c = await add('bitrix24-box', { webhook_url: `https://crm.mybox.test/rest/5/${c1}/` });
  const msg = await replace(c.id, { webhook_url: `https://crm.other.test/rest/5/${c2}/` });
  assert.match(msg, /different address \(crm\.other\.test\)/);
  assert.equal(await secret(c.id), `5/${c1}`);
  assert.equal(await replace(c.id, { webhook_url: `https://crm.mybox.test/rest/5/${c3}/` }), en['flash.key_replaced']);
  assert.equal(await secret(c.id), `5/${c3}`);
});

test('«Другой»: замена только ключа, адрес и заголовок из сохранённого; чужие host/header в теле игнорируются', async () => {
  const [k1, k2] = [rnd(24), rnd(24)];
  const c = await add('other', { host: 'https://api.mine.test', header: 'x-api-key', key: k1 });
  assert.equal(await replace(c.id, { key: k2, host: 'https://evil.test', header: 'x-evil' }), en['flash.key_replaced']);
  const after = app.repo.getCredential(c.id);
  assert.equal(await secret(c.id), k2);
  assert.equal(after.host, 'api.mine.test');
  assert.equal(after.injection.name, 'x-api-key');
  assert.equal(after.last4, k2.slice(-4));
});

test('форма замены: поля как при добавлении, без автофокуса, ключ не подставляется', async () => {
  const tw = await add('twilio', { account: sid(), key: rnd(32) });
  const zd = await add('zendesk', { account: 'formtest', email: 'o@formtest.test', key: rnd(24) });
  const am = await add('amocrm', { account: 'formtest.amocrm.ru', key: rnd(30) });
  const bx = await add('bitrix24', { webhook_url: `https://formtest.bitrix24.ru/rest/1/${rnd(16)}/` });
  const ot = await add('other', { host: 'https://api.formtest.test', header: 'x-token', key: rnd(24) });
  const gq = await add('groq', { key: 'gsk_' + rnd(30) });

  assert.deepEqual(names(await replaceForm(tw.id)), ['account', 'key']);
  assert.deepEqual(names(await replaceForm(zd.id)), ['account', 'email', 'key']);
  assert.deepEqual(names(await replaceForm(am.id)), ['account', 'key']);
  assert.deepEqual(names(await replaceForm(bx.id)), ['webhook_url']);
  assert.deepEqual(names(await replaceForm(ot.id)), ['key']);
  assert.deepEqual(names(await replaceForm(gq.id)), ['key']);

  for (const c of [tw, zd, am, bx, ot, gq]) {
    const f = await replaceForm(c.id);
    assert.ok(!f.includes('autofocus'), 'на странице ключа автофокуса нет');
    assert.ok(!/name="(key|webhook_url)"[^>]*value=/.test(f), 'секрет не подставляется');
  }
  // адрес поддоменных сервисов подставлен, SID Twilio и e-mail — нет
  assert.match(await replaceForm(am.id), /name="account" value="formtest\.amocrm\.ru"/);
  assert.match(await replaceForm(zd.id), /name="account" value="formtest\.zendesk\.com"/);
  assert.match(await replaceForm(tw.id), /name="account" value=""/);
  assert.match(await replaceForm(zd.id), /name="email" value=""/);
});

test('подсказки поля account зависят от провайдера, подпись SID у Twilio', async () => {
  const tw = await add('twilio', { account: sid(), key: rnd(32) });
  const zd = await add('zendesk', { account: 'hints', email: 'o@hints.test', key: rnd(24) });
  const am = await add('amocrm', { account: 'hints.amocrm.ru', key: rnd(30) });
  const f = (h) => h.match(/<input name="account"[^>]*>/)[0];
  const [ft, fz, fa] = [await replaceForm(tw.id), await replaceForm(zd.id), await replaceForm(am.id)];
  assert.match(f(ft), /placeholder="AC[x]+"/);
  assert.ok(ft.includes('Account SID'));
  assert.match(f(fz), /placeholder="mycompany"/);
  assert.match(f(fa), /placeholder="mycompany\.amocrm\.ru"/);
  assert.ok(!f(ft).includes('amocrm') && !f(fz).includes('amocrm'));
  // форма добавления использует тот же рендер
  const add3 = await (await get('/keys/new/twilio')).text();
  assert.match(f(add3), /placeholder="AC[x]+"/);
  assert.ok(add3.includes('autofocus'), 'на форме добавления автофокус сохранён');
});

test('i18n: новые ключи есть в en и ru', () => {
  for (const k of ['catalog.err.replace_host', 'catalog.label.account.twilio']) {
    assert.ok(en[k] && ru[k], k);
  }
  assert.ok(en['catalog.err.replace_host'].includes('{host}') && ru['catalog.err.replace_host'].includes('{host}'));
});
