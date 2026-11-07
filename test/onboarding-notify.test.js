// Подключение канала заявок в мастере и онбординге: кнопки наружу, привязка по ссылке, Slack с тестом, логотипы.
// Без внешней сети: поддельные Telegram API и Slack на localhost. Секреты собираются в рантайме.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n, t } from '../src/i18n.js';
import { KINDS, BOTFATHER_URL, slackCreateUrl, telegramStartUrl } from '../src/web/onboarding.js';
import { readChannelMeta } from '../src/notify.js';

initI18n('en');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PASSWORD = 'correct-horse-battery';
const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) { try { await f(); } catch { /* уборка */ } } });

const mkBot = () => `${100000 + crypto.randomInt(900000)}:${crypto.randomBytes(27).toString('base64url').slice(0, 35)}`;
const mkHook = () => `https://hooks.slack.com/services/T${crypto.randomBytes(4).toString('hex')}/B${crypto.randomBytes(4).toString('hex')}/${crypto.randomBytes(12).toString('hex')}`;

async function fakes() {
  const tg = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const method = req.url.match(/^\/bot[^/]+\/(\w+)/)?.[1];
      res.setHeader('content-type', 'application/json');
      if (method === 'getMe') return res.end(JSON.stringify({ ok: true, result: { id: 1, is_bot: true, first_name: 'gw', username: 'gw_test_bot' } }));
      if (method === 'getUpdates') return void setTimeout(() => res.end(JSON.stringify({ ok: true, result: [] })), 100);
      return res.end(JSON.stringify({ ok: true, result: true }));
    });
  });
  const slack = { status: 200, messages: [] };
  const sl = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => { slack.messages.push({ url: req.url, body }); res.statusCode = slack.status; res.end('ok'); });
  });
  await Promise.all([new Promise((r) => tg.listen(0, '127.0.0.1', r)), new Promise((r) => sl.listen(0, '127.0.0.1', r))]);
  cleanup.push(async () => { for (const s of [tg, sl]) { s.close(); s.closeAllConnections?.(); } });
  return { apiRoot: `http://127.0.0.1:${tg.address().port}`, slackOrigin: `http://127.0.0.1:${sl.address().port}`, slack };
}

/** Владелец дошёл до шага 3 мастера; сессия со свежим кодом. */
async function boot() {
  const f = await fakes();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-notify-'));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent', tgApiRoot: f.apiRoot, notifyTest: { slackOrigin: f.slackOrigin },
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const jar = new Map();
  const c = { app, base, token: '', slack: f.slack };
  const store = (r) => { for (const s of r.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); } };
  const headers = (more = {}) => ({ cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), ...more });
  const keep = async (r) => { store(r); r.text2 = await r.text(); const m = r.text2.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1]; return r; };
  c.get = async (p) => keep(await fetch(base + p, { headers: headers(), redirect: 'manual' }));
  c.post = async (p, fields = {}, { csrf = true } = {}) => keep(await fetch(base + p, { method: 'POST', headers: headers({ 'content-type': 'application/x-www-form-urlencoded' }), body: new URLSearchParams({ ...(csrf && { _csrf: c.token }), ...fields }), redirect: 'manual' }));
  c.setTotp = (v) => { for (const s of app.db.prepare('SELECT id_hash FROM sessions').all()) app.db.prepare('UPDATE sessions SET totp_at = ? WHERE id_hash = ?').run(v, s.id_hash); };
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await c.get(`/setup/${token}`); await c.get('/setup');
  await c.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  const page = (await c.get('/setup')).text2;
  const secret = page.match(/([A-Z2-7]{16,})<\/code>/)[1];
  await c.post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  await c.post('/setup', { step: '3' }); // «Дальше» после резервных кодов
  return c;
}

const startLink = (s) => s.match(/https:\/\/t\.me\/gw_test_bot\?start=([A-Z2-9]+)/)?.[1];
const dec = (s) => s.replaceAll('&amp;', '&');

test('telegramStartUrl: только допустимые имя и код', () => {
  assert.equal(telegramStartUrl('my_bot', 'ABC234'), 'https://t.me/my_bot?start=ABC234');
  for (const [u, code] of [[null, 'A'], ['', 'A'], ['a b', 'A'], ['evil.com/x', 'A'], ['bot', null], ['bot', ''], ['bot', 'a&b=c'], ['bot', 'x'.repeat(65)]]) {
    assert.equal(telegramStartUrl(u, code), null, `${u} ${code}`);
  }
});

test('slackCreateUrl: манифест включает только Incoming Webhooks', () => {
  const u = new URL(slackCreateUrl());
  assert.equal(u.origin + u.pathname, 'https://api.slack.com/apps');
  assert.equal(u.searchParams.get('new_app'), '1');
  const m = JSON.parse(u.searchParams.get('manifest_json'));
  assert.equal(m.settings.incoming_webhooks.incoming_webhooks_enabled, true);
  assert.equal(typeof m.display_information.name, 'string');
  assert.equal(m.oauth_config, undefined, 'лишних прав нет');
  assert.equal(m.features, undefined);
});

test('мастер: на шаге 3 кнопки BotFather и Slack, /newbot можно скопировать, пропуск есть', async () => {
  const c = await boot();
  const page = (await c.get('/setup')).text2;
  assert.ok(page.includes(`href="${BOTFATHER_URL}"`));
  assert.ok(dec(page).includes(slackCreateUrl()));
  assert.match(page, /data-copy="#tg-newbot"/);
  assert.match(page, /value="skip"/);
  assert.match(page, /rel="noopener noreferrer"/);
  assert.match(page, /\/public\/icons\/telegram\.svg/);
  assert.match(page, /\/public\/icons\/slack\.svg/);
});

test('мастер, Telegram: токен → ссылка на бота; неудачная проверка выдаёт новый код; после Start мастер завершён', async () => {
  const c = await boot();
  const bot = mkBot();
  assert.equal((await c.post('/setup', { step: '3', mode: 'telegram', token: bot })).status, 302);
  const page = (await c.get('/setup')).text2;
  const first = startLink(page);
  assert.ok(first, 'есть ссылка на бота');
  assert.ok(page.includes(`/start ${first}`), 'запасной путь текстом');
  assert.ok(!page.includes(bot), 'токен в страницу не попадает');
  assert.equal((await c.post('/setup', { step: '3', mode: 'check' })).headers.get('location'), '/setup');
  const second = startLink((await c.get('/setup')).text2);
  assert.ok(second && second !== first, 'просроченная ссылка не тупик: код новый');
  c.app.repo.setTg(777, 'sys/tg_bot');
  const done = await c.post('/setup', { step: '3', mode: 'check' });
  assert.equal(done.headers.get('location'), '/welcome');
  assert.equal(c.app.repo.getMeta('setup_tg_code'), '');
});

test('мастер, Slack: адрес проверен, тест отправлен, канал включён, переход на онбординг', async () => {
  const c = await boot();
  const hook = mkHook();
  const r = await c.post('/setup', { step: '3', mode: 'slack', webhook: hook });
  assert.equal(r.headers.get('location'), '/welcome');
  assert.equal(c.slack.messages.length, 1, 'тестовое сообщение ушло');
  assert.equal(c.slack.messages[0].url, new URL(hook).pathname);
  const meta = readChannelMeta(c.app.repo, 'slack');
  assert.equal(meta.enabled, true);
  assert.equal(meta.configured, true);
  assert.equal(await c.app.ctx.vault.get('sys/slack_webhook'), hook);
  const page = await c.get('/welcome');
  assert.match(page.text2, /Slack connected/);
  assert.ok(!page.text2.includes(new URL(hook).pathname), 'адрес вебхука не показывается');
  assert.match(page.text2, /1 of 3 done/);
});

test('Slack: тест не прошёл — канал не включён, адрес не остался, мастер не завершён', async () => {
  const c = await boot();
  c.slack.status = 500;
  const hook = mkHook();
  const r = await c.post('/setup', { step: '3', mode: 'slack', webhook: hook });
  assert.equal(r.headers.get('location'), '/setup');
  assert.equal(readChannelMeta(c.app.repo, 'slack').configured, false);
  await assert.rejects(async () => { const v = await c.app.ctx.vault.get('sys/slack_webhook'); if (v == null) throw new Error('нет'); });
  const page = (await c.get('/setup')).text2;
  assert.match(page, /Test failed \(http_500\)/);
  assert.ok(!page.includes(new URL(hook).pathname));
  assert.equal(c.app.repo.getOwner().setup_done ? 1 : 0, 0);
});

test('Slack: чужой адрес отклоняется без обращения к сети и без записи', async () => {
  const c = await boot();
  const bad = 'https://evil.example.com/services/T1/B1/x';
  const r = await c.post('/setup', { step: '3', mode: 'slack', webhook: bad });
  assert.equal(r.headers.get('location'), '/setup');
  assert.equal(c.slack.messages.length, 0);
  assert.equal(readChannelMeta(c.app.repo, 'slack').configured, false);
  // отказ на входе, а не после попытки отправки: адрес не попадает в сейф даже на время теста
  const page = (await c.get('/setup')).text2;
  assert.doesNotMatch(page, /Test failed/);
  assert.ok(page.includes(t('flash.slack_url_invalid')), 'текст про неверный адрес');
});

test('онбординг: Slack заменяется только при успешном тесте, прежний адрес при сбое возвращается', async () => {
  const c = await boot();
  await c.post('/setup', { step: '3', mode: 'skip' });
  await c.get('/welcome');
  const good = mkHook();
  assert.equal((await c.post('/welcome/notify/slack', { webhook: good })).headers.get('location'), '/welcome');
  assert.equal(await c.app.ctx.vault.get('sys/slack_webhook'), good);
  await c.get('/welcome');
  c.slack.status = 404;
  await c.post('/welcome/notify/slack', { webhook: mkHook() });
  assert.equal(await c.app.ctx.vault.get('sys/slack_webhook'), good, 'рабочий адрес на месте');
  assert.equal(readChannelMeta(c.app.repo, 'slack').enabled, true);
});

test('онбординг, Telegram: те же шаги; проверка завершает шаг', async () => {
  const c = await boot();
  await c.post('/setup', { step: '3', mode: 'skip' });
  const before = (await c.get('/welcome')).text2;
  assert.ok(before.includes(`href="${BOTFATHER_URL}"`));
  await c.post('/welcome/notify/telegram', { token: mkBot() });
  const page = (await c.get('/welcome')).text2;
  const first = startLink(page);
  assert.ok(first);
  await c.post('/welcome/notify/check');
  const again = (await c.get('/welcome')).text2;
  assert.match(again, /hasn’t received the \/start/);
  assert.notEqual(startLink(again), first);
  c.app.repo.setTg(777, 'sys/tg_bot');
  await c.post('/welcome/notify/check');
  const done = (await c.get('/welcome')).text2;
  assert.match(done, /Telegram connected/);
  assert.equal(startLink(done), undefined);
});

test('онбординг: запись канала требует свежий код и CSRF, анониму закрыта', async () => {
  const c = await boot();
  await c.post('/setup', { step: '3', mode: 'skip' });
  await c.get('/welcome');
  assert.equal((await c.post('/welcome/notify/slack', { webhook: mkHook() }, { csrf: false })).status, 403);
  c.setTotp(0);
  for (const [p, f] of [['/welcome/notify/slack', { webhook: mkHook() }], ['/welcome/notify/telegram', { token: mkBot() }]]) {
    const r = await c.post(p, f);
    assert.equal(r.status, 302);
    assert.match(r.headers.get('location'), /^\/totp\?next=/, p);
  }
  assert.equal(readChannelMeta(c.app.repo, 'slack').configured, false);
  assert.equal(c.slack.messages.length, 0);
  const anon = await fetch(`${c.base}/welcome/notify/check`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '' });
  assert.notEqual(anon.status, 200);
});

test('мастер: Slack со старым кодом уводит на подтверждение, ничего не записав', async () => {
  const c = await boot();
  c.setTotp(0);
  const r = await c.post('/setup', { step: '3', mode: 'slack', webhook: mkHook() });
  assert.match(r.headers.get('location'), /^\/totp\?next=/);
  assert.equal(readChannelMeta(c.app.repo, 'slack').configured, false);
});

test('первый ключ возвращает к онбордингу; после пропуска и завершения ведёт на главную', async () => {
  const key = (b) => ({ key: b, label: 'bot', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  const c = await boot();
  await c.post('/setup', { step: '3', mode: 'skip' });
  await c.get('/keys/new/telegram');
  assert.equal((await c.post('/keys/new/telegram', key(mkBot()))).headers.get('location'), '/welcome');
  await c.get('/welcome');
  await c.post('/welcome/skip');
  await c.get('/keys/new/telegram');
  assert.equal((await c.post('/keys/new/telegram', key(mkBot()))).headers.get('location'), '/');
});

test('логотипы: у каждого агента есть файл без скриптов и он показан на карточке', async () => {
  for (const k of KINDS) {
    const svg = fs.readFileSync(path.join(root, 'assets', 'icons', `agent-${k}.svg`), 'utf8');
    assert.match(svg, /^<svg/, k);
    assert.doesNotMatch(svg, /<script|\son\w+=|<foreignObject|href="http/i, k);
  }
  const c = await boot();
  await c.post('/setup', { step: '3', mode: 'skip' });
  const page = (await c.get('/welcome')).text2;
  for (const k of KINDS) assert.ok(page.includes(`/public/icons/agent-${k}.svg`), k);
  assert.equal((await c.get('/public/icons/agent-hermes.svg')).status, 200);
  const made = await c.post('/welcome/agent/hermes');
  assert.match(made.text2, /\/public\/icons\/agent-hermes\.svg/);
  assert.match((await c.get('/agents')).text2, /class="line-ico"/);
});

test('внешних загрузок нет: логотипы только локальные', async () => {
  const c = await boot();
  const page = (await c.get('/setup')).text2;
  for (const m of page.matchAll(/<(?:img|script|link)[^>]+(?:src|href)="([^"]+)"/g)) assert.match(m[1], /^\//, m[1]);
});
