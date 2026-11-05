// Уведомления (контракт rest-demo-notify.md, «Уведомления и лист ожидания»), тесты 1-6 + свежий 2FA в настройках.
// Без сети: mock Slack и mock SMTP только на localhost; тестовые подмены приходят через buildApp(overrides), не из env.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';
import {
  createNotifier, createChannels, checkSlackWebhook, checkSmtp, emailMessage, writeChannelMeta, EVENTS, DEFAULT_EVENTS,
} from '../src/notify.js';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
// фальшивый адрес вебхука собирается в рантайме (секреты в тестах не пишутся открытым текстом)
const SLACK_URL = `https://hooks.slack.com/services/T0TEST/B0TEST/${crypto.randomBytes(9).toString('hex')}`;
const SMTP_PASS = 'smtp-' + crypto.randomBytes(6).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) await f(); });

// ---- mock Slack
async function mockSlack() {
  const st = { posts: [], status: 200, other: [] };
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      if (req.url === '/elsewhere') { st.other.push(req.url); res.end('ok'); return; }
      st.posts.push({ url: req.url, body });
      if (st.status === 302) { res.writeHead(302, { location: '/elsewhere' }); res.end(); return; }
      res.writeHead(st.status); res.end('ok');
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  cleanup.push(() => new Promise((r) => { srv.closeAllConnections(); srv.close(r); }));
  st.origin = `http://127.0.0.1:${srv.address().port}`;
  return st;
}

// ---- mock SMTP без STARTTLS: приветствие, EHLO без расширений, всё остальное «250 ok»
async function mockSmtp() {
  const st = { connections: 0, lines: [] };
  const socks = new Set();
  const srv = net.createServer((sock) => {
    st.connections++; socks.add(sock);
    sock.on('close', () => socks.delete(sock)); sock.on('error', () => {});
    sock.write('220 mock ESMTP\r\n');
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        st.lines.push(line);
        if (/^(EHLO|HELO)/i.test(line)) sock.write('250-mock\r\n250 8BITMIME\r\n');
        else if (/^QUIT/i.test(line)) { sock.end('221 bye\r\n'); }
        else sock.write('250 ok\r\n');
      }
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  cleanup.push(() => new Promise((r) => { for (const s of socks) s.destroy(); srv.close(r); }));
  st.port = srv.address().port;
  return st;
}

// ---- приложение с мастером пройденным и шаблонным ключом
async function boot(over = {}) {
  const logs = [];
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-notify-'));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'debug', logStream: { write: (s) => logs.push(String(s)) }, ...over,
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const used = new Set();
  let secret;
  const code = () => {
    const s = Math.floor(Date.now() / 30000);
    const step = [s, s - 1, s + 1].find((x) => !used.has(x));
    used.add(step);
    return totpAt(secret, step);
  };
  function client() {
    const jar = new Map();
    const c = { token: '' };
    const store = (res) => {
      for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); }
    };
    const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    c.get = async (p) => {
      const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' });
      store(r);
      const m = (await r.clone().text()).match(/name="_csrf" value="([^"]+)"/);
      if (m) c.token = m[1];
      return r;
    };
    c.post = async (p, fields = {}) => {
      const body = new URLSearchParams();
      body.append('_csrf', c.token);
      for (const [k, v] of Object.entries(fields)) for (const x of [].concat(v)) body.append(k, x);
      const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
      store(r);
      return r;
    };
    c.hash = () => sha256(jar.get('gw_sid'));
    return c;
  }
  const a = client();
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await a.get(`/setup/${token}`); await a.get('/setup');
  await a.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  secret = (await (await a.get('/setup')).text()).match(/Manual key: <code>([A-Z2-7]+)<\/code>|([A-Z2-7]{16,})<\/code>/).slice(1).find(Boolean);
  await a.post('/setup', { step: '2', code: code() });
  await a.post('/setup', { step: '3', mode: 'skip' });
  const r = await a.post('/keys/new/bitrix24', { webhook_url: 'https://test.bitrix24.ru/rest/1/abcdef123456/', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '100', max_parallel: '2' });
  assert.equal(r.status, 302);
  const credential = app.repo.listCredentials()[0];
  const agentId = crypto.randomBytes(6).toString('base64url');
  app.repo.createAgent({ id: agentId, name: 'Bot <1>', token_hash: sha256(agentId), all_credentials: 1 });
  const session = async () => {
    const c = client();
    const l = makeLink(app.repo, 'setup', 900, base);
    assert.equal((await c.get(`/setup/${l.token}`)).status, 302);
    await c.get('/');
    return c;
  };
  const setTotpAt = (c, v) => app.db.prepare('UPDATE sessions SET totp_at = ? WHERE id_hash = ?').run(v, c.hash());
  return {
    app, base, logs, credential, agent: app.repo.getAgent(agentId), session, client,
    stale: (c) => setTotpAt(c, 1000), fresh: (c) => setTotpAt(c, Math.floor(Date.now() / 1000)),
    submit: (reason = 'need data') => app.ctx.requests.submit({ agent: app.repo.getAgent(agentId), credential: app.repo.getCredential(credential.id), ttl: 600, calls: 5, reason }),
  };
}

const allEvents = () => [...EVENTS];
const mockChannel = (id, send, extra = {}) => ({ id, buttons: id === 'telegram', enabled: () => true, events: allEvents, send, test: async () => {}, ...extra });
const silentLogger = () => { const errors = []; return { errors, error: (o, m) => errors.push([o, m]), warn() {}, info() {} }; };

test('1: три mock-канала (бросает, висит, доставляет): submit() сразу, остальные доставили, лог только с channel и кодом', async () => {
  const delivered = [];
  const bad = mockChannel('slack', async () => { throw Object.assign(new Error('POST https://hooks.slack.com/services/T/B/LEAKPATH failed'), { code: 'ECONNRESET' }); });
  const hang = mockChannel('email', () => new Promise(() => {})); // не завершается никогда
  const good = mockChannel('telegram', async (msg) => { delivered.push(msg); });
  const h = await boot({ notifyChannels: [bad, hang, good], notifyTimeoutMs: 300 });
  const t0 = Date.now();
  const r = h.submit('secret reason text');
  assert.equal(r.kind, 'pending');
  assert.ok(Date.now() - t0 < 150, 'submit не ждёт доставки');
  await h.app.ctx.notify.idle();
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0].event, 'request.created');
  const failed = h.logs.map((l) => JSON.parse(l)).filter((l) => l.msg === 'notify failed');
  assert.deepEqual(failed.map((l) => [l.channel, l.errCode]).sort(), [['email', 'timeout'], ['slack', 'ECONNRESET']]);
  const all = h.logs.join('');
  for (const leak of ['LEAKPATH', 'hooks.slack.com', 'secret reason text']) assert.ok(!all.includes(leak), leak);
  assert.ok(!failed.some((l) => 'err' in l || 'text' in l || 'url' in l), 'в записи нет err/text/url');
});

test('security: создание агента шлёт событие во все каналы', async () => {
  const got = [];
  const h = await boot({ notifyChannels: [mockChannel('slack', async (m) => { got.push(m); })] });
  const c = await h.session(); h.fresh(c);
  await c.get('/agents');
  const r = await c.post('/agents', { name: 'audit-bot', all: '1' });
  assert.equal(r.status, 200);
  await h.app.ctx.notify.idle();
  const sec = got.filter((m) => m.event === 'security');
  assert.equal(sec.length, 1);
  assert.match(sec[0].text, /audit-bot/);
  assert.ok(!JSON.stringify(sec).includes('gwa_'), 'токен агента в уведомление не попадает');
});

test('2: таблица событий: request.created в telegram (кнопки) и slack (без), в email по умолчанию нет; key.expired и security идут в email', async () => {
  const h = await boot();
  const slack = await mockSlack();
  const smtp = await mockSmtp();
  const calls = { created: [], decided: [], sent: [] };
  const bot = { sendRequest: async (...a) => { calls.created.push(a); }, editDecided: async (...a) => { calls.decided.push(a); }, send: async (x) => { calls.sent.push(x); } };
  const { repo, ctx } = h.app;
  const vault = ctx.vault;
  await vault.put('sys/slack_webhook', SLACK_URL);
  await vault.put('sys/smtp', JSON.stringify({ host: 'smtp.example.com', port: 587, user: 'u', pass: SMTP_PASS, from: 'gw@example.com', to: ['me@example.com'] }));
  writeChannelMeta(repo, 'slack', { enabled: true, events: DEFAULT_EVENTS.slack, configured: true });
  writeChannelMeta(repo, 'email', { enabled: true, events: DEFAULT_EVENTS.email, configured: true });
  const n = createNotifier({ repo, getBot: () => bot, vault, logger: silentLogger(), publicUrl: 'https://gw.example.org', test: { slackOrigin: slack.origin, smtp: { host: '127.0.0.1', port: smtp.port } } });
  assert.deepEqual(n.channels.map((c) => [c.id, c.buttons]), [['telegram', true], ['slack', false], ['email', false]]);
  assert.deepEqual([...DEFAULT_EVENTS.email], ['key.expired', 'security']);

  const request = repo.getRequest(h.submit().requestId);
  await n.requestCreated(request, h.credential, h.agent);
  assert.equal(calls.created.length, 1, 'telegram: sendRequest (кнопки)');
  assert.equal(slack.posts.length, 1);
  const payload = JSON.parse(slack.posts[0].body);
  assert.ok(!('blocks' in payload) && !('attachments' in payload), 'без кнопок');
  assert.ok(payload.text.includes('https://gw.example.org/requests'));
  assert.ok(!/gwa_|gwt_/.test(payload.text));
  assert.equal(smtp.connections, 0, 'email: request.created выключен');

  await n.requestDecided(request, 'approved');
  assert.equal(calls.decided.length, 1);
  assert.equal(slack.posts.length, 2);
  await n.info('plain info');
  assert.deepEqual(calls.sent, ['plain info']);
  assert.equal(slack.posts.length, 3);
  assert.equal(smtp.connections, 0, 'info в email не идёт');

  await n.info('key period ended', 'key.expired');
  await n.security('password changed');
  assert.equal(slack.posts.length, 5);
  assert.equal(smtp.connections, 2, 'key.expired и security дошли до SMTP (отправка сорвётся на TLS, это проверяет тест 4)');
  assert.ok(smtp.lines.every((l) => !l.includes(SMTP_PASS)));
});

test('3: Slack: не hooks.slack.com или http отклоняются при сохранении; <!channel> экранирован; причина ≤ 300; редирект не выполняется', async () => {
  for (const bad of [
    'http://hooks.slack.com/services/T/B/x', 'https://evil.example/services/T/B/x', 'https://hooks.slack.com.evil.example/services/T/B/x',
    'https://hooks.slack.com:8443/services/T/B/x', 'https://u:p@hooks.slack.com/services/T/B/x', 'https://hooks.slack.com/other/T/B/x',
    'https://hooks.slack.com/services/T/B/x?a=1', 'javascript:alert(1)', '', 'https://127.0.0.1/services/T/B/x',
  ]) assert.equal(checkSlackWebhook(bad).ok, false, bad);
  assert.equal(checkSlackWebhook(SLACK_URL).ok, true);

  const h = await boot();
  const slack = await mockSlack();
  // сохранение через сайт: плохой адрес не попадает в сейф
  const c = await h.session();
  await c.post('/settings/notify/slack/secret', { webhook: 'http://hooks.slack.com/services/T/B/x' });
  assert.equal(await h.app.ctx.vault.get('sys/slack_webhook'), null);
  assert.match(await (await c.get('/settings')).text(), /Only https:\/\/hooks\.slack\.com/);
  await c.post('/settings/notify/slack/secret', { webhook: SLACK_URL });
  assert.equal(await h.app.ctx.vault.get('sys/slack_webhook'), SLACK_URL);

  const { repo, ctx } = h.app;
  writeChannelMeta(repo, 'slack', { enabled: true, events: EVENTS, configured: true });
  const n = createNotifier({ repo, vault: ctx.vault, logger: silentLogger(), publicUrl: 'http://127.0.0.1', test: { slackOrigin: slack.origin } });
  const request = { ttl: 600, calls: 5, reason: '<!channel> & ' + 'x'.repeat(1000) };
  await n.requestCreated(request, { provider: 'bitrix24', label: 'Main' }, { name: 'Bot' });
  const text = JSON.parse(slack.posts[0].body).text;
  assert.ok(!text.includes('<!channel>') && text.includes('&lt;!channel&gt; &amp; '));
  const reason = text.split('Reason: ')[1].split('\n')[0].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  assert.ok(Array.from(reason).length <= 300 && reason.startsWith('<!channel> & x'), `длина ${reason.length}`);

  // редирект не выполняется: ответ 302 = сбой, на /elsewhere никто не ходит
  slack.status = 302;
  const ch = createChannels({ repo, vault: ctx.vault, publicUrl: '', test: { slackOrigin: slack.origin } }).find((x) => x.id === 'slack');
  await assert.rejects(ch.test(), (e) => e.code === 'http_302');
  assert.deepEqual(slack.other, []);
});

test('4: e-mail: конфиг без TLS отклонён; mock SMTP без STARTTLS -> send падает до MAIL/AUTH; subject без CR/LF', async () => {
  const ok = { host: 'smtp.example.com', port: 587, user: 'u', pass: 'p', from: 'gw@example.com', to: 'a@example.com, b@example.com' };
  assert.equal(checkSmtp(ok).ok, true);
  assert.equal(checkSmtp({ ...ok, port: 465, encryption: 'tls' }).ok, true);
  for (const bad of [
    { ...ok, port: 25 }, { ...ok, port: 587, encryption: 'none' }, { ...ok, tls: false }, { ...ok, port: 587, encryption: 'tls' },
    { ...ok, host: '10.0.0.5' }, { ...ok, host: 'localhost' }, { ...ok, host: '127.0.0.1' }, { ...ok, from: 'a@b.co\r\nBcc: x@y.zz' }, { ...ok, to: '' },
    { ...ok, to: 'a@example.com\nb@example.com,not-an-address' },
  ]) assert.equal(checkSmtp(bad).ok, false, JSON.stringify(bad));

  const msg = emailMessage({ event: 'info', title: 'Hello\r\nBcc: evil@example.com', text: 'body', url: 'http://x/requests' });
  assert.ok(!/[\r\n]/.test(msg.subject), JSON.stringify(msg.subject));
  assert.equal(msg.text, 'body\n\nhttp://x/requests');

  const h = await boot();
  const smtp = await mockSmtp();
  const { repo, ctx } = h.app;
  await ctx.vault.put('sys/smtp', JSON.stringify({ host: 'smtp.example.com', port: 587, user: 'u', pass: SMTP_PASS, from: 'gw@example.com', to: ['me@example.com'] }));
  writeChannelMeta(repo, 'email', { enabled: true, events: EVENTS, configured: true });
  const ch = createChannels({ repo, vault: ctx.vault, publicUrl: 'http://127.0.0.1', test: { smtp: { host: '127.0.0.1', port: smtp.port } } }).find((x) => x.id === 'email');
  await assert.rejects(ch.send({ event: 'security', title: 't\r\nx', text: 'body' }));
  assert.ok(smtp.connections >= 1);
  assert.ok(smtp.lines.some((l) => /^EHLO/i.test(l)));
  assert.ok(!smtp.lines.some((l) => /^(MAIL|RCPT|DATA|AUTH)/i.test(l)), 'письмо и пароль не отправлены без шифрования: ' + smtp.lines.join('|'));
});

test('5: секреты sys/slack_webhook и sys/smtp не попадают в логи, audit, meta, черновики и страницу настроек', async () => {
  const slack = await mockSlack();
  const smtp = await mockSmtp();
  const h = await boot({ notifyTest: { slackOrigin: slack.origin, smtp: { host: '127.0.0.1', port: smtp.port } } });
  const c = await h.session();
  assert.equal((await c.post('/settings/notify/slack/secret', { webhook: SLACK_URL })).status, 302);
  assert.equal((await c.post('/settings/notify/email/secret', { host: 'smtp.example.com', port: '587', user: 'user1', pass: SMTP_PASS, from: 'gw@example.com', to: 'me@example.com' })).status, 302);
  assert.equal(await h.app.ctx.vault.get('sys/slack_webhook'), SLACK_URL, 'контроль: секрет в сейфе');
  assert.equal(JSON.parse(await h.app.ctx.vault.get('sys/smtp')).pass, SMTP_PASS);
  // включение (код свежий), проверка, реальные события, сбой SMTP
  for (const id of ['slack', 'email']) await c.post(`/settings/notify/${id}`, { enabled: '1', events: EVENTS });
  await c.post('/settings/notify/slack/test');
  await c.post('/settings/notify/email/test');
  h.submit();
  await c.post('/settings/revoke-all'); // security-событие во все каналы; сессия закрывается
  await h.app.ctx.notify.idle();
  assert.ok(slack.posts.length >= 2, 'контроль: Slack получал сообщения');
  const c2 = await h.session();
  const page = await (await c2.get('/settings')).text();
  const SECRETS = [SLACK_URL.split('/').pop(), 'T0TEST/B0TEST', SMTP_PASS];
  const haystacks = {
    logs: h.logs.join('\n'),
    audit: JSON.stringify(h.app.repo.listAudit({ limit: 500 })),
    meta: JSON.stringify(h.app.db.prepare('SELECT * FROM meta').all()),
    pending: JSON.stringify(h.app.db.prepare('SELECT * FROM pending_actions').all()),
    page,
    slackPayloads: slack.posts.map((p) => p.body).join('\n'),
    smtpWire: smtp.lines.join('\n'),
  };
  for (const [name, text] of Object.entries(haystacks)) for (const s of SECRETS) assert.ok(!text.includes(s), `${name} содержит секрет ${s.slice(0, 4)}…`);
  assert.match(page, /Connection saved \(hidden\)/);
  assert.ok(!/value="https:\/\/hooks\.slack\.com\/services/.test(page));
  assert.ok(h.app.repo.listAudit({ limit: 500 }).some((a) => a.action === 'notify.secret' && a.target === 'slack'));
});

test('6: GW_WAITLIST_URL: https показывается в подвале; javascript: и http: отбрасываются; на страницах нет чужих скриптов и внешних src', async () => {
  const shown = await boot({ waitlistUrl: 'https://example.org/w' });
  let page = await (await fetch(shown.base + '/login')).text();
  assert.match(page, /<a class="waitlist" href="https:\/\/example\.org\/w" rel="noopener noreferrer" target="_blank">Cloud: join the waitlist<\/a>/);
  const c = await shown.session();
  const settings = await (await c.get('/settings')).text();
  assert.ok(settings.includes('href="https://example.org/w"'));
  for (const html of [page, settings]) {
    const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
    assert.ok(scripts.every((s) => /^<script src="\/public\/[A-Za-z0-9._-]+\.js"( defer)?>$/.test(s)), scripts.join(' '));
    assert.ok(!/<script[^>]*>[^<]+<\/script>/i.test(html), 'инлайн-скриптов нет');
    assert.ok(![...html.matchAll(/\ssrc="([^"]+)"/g)].some((m) => !m[1].startsWith('/')), 'внешних src нет');
  }
  for (const bad of ['javascript:alert(1)', 'http://example.org/w', 'https://example.org/' + 'a'.repeat(300), 'https://u:p@example.org/w']) {
    const h = await boot({ waitlistUrl: bad });
    page = await (await fetch(h.base + '/login')).text();
    assert.ok(!page.includes('waitlist') && !page.includes('javascript:'), bad.slice(0, 30));
    assert.ok(h.logs.some((l) => l.includes('GW_WAITLIST_URL ignored')), 'предупреждение в логе');
    assert.ok(!h.logs.join('').includes('alert(1)'));
  }
  const none = await boot({ waitlistUrl: '' });
  assert.ok(!(await (await fetch(none.base + '/login')).text()).includes('waitlist'));
});

test('7: настройки: включение и смена секрета только со свежим 2FA; включение уходит в черновик, выключение и события применяются сразу', async () => {
  const h = await boot();
  const meta = (id) => JSON.parse(h.app.repo.getMeta(`notify.${id}`) || 'null');
  const c = await h.session();
  await c.post('/settings/notify/slack/secret', { webhook: SLACK_URL });
  assert.equal(meta('slack').configured, true);
  assert.equal(meta('slack').enabled, false, 'сохранение секрета не включает канал');

  // секрет без свежего кода: на /totp, в сейфе прежнее значение, формы не сохраняются в черновики
  h.stale(c);
  const other = 'https://hooks.slack.com/services/T9ZZZ/B9ZZZ/OTHERSECRET';
  let r = await c.post('/settings/notify/slack/secret', { webhook: other });
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/totp?next=%2Fsettings');
  assert.equal(await h.app.ctx.vault.get('sys/slack_webhook'), SLACK_URL);
  assert.equal(h.app.db.prepare('SELECT count(*) AS n FROM pending_actions').get().n, 0);
  r = await c.post('/settings/notify/email/secret', { host: 'smtp.example.com', port: '587', pass: 'p', user: 'u', from: 'gw@example.com', to: 'me@example.com' });
  assert.equal(r.headers.get('location'), '/totp?next=%2Fsettings');
  assert.equal(await h.app.ctx.vault.get('sys/smtp'), null);
  r = await c.post('/settings/notify/slack/clear');
  assert.equal(r.headers.get('location'), '/totp?next=%2Fsettings');

  // включение без свежего кода: черновик, канал не включён
  r = await c.post('/settings/notify/slack', { enabled: '1', events: ['security', 'info'] });
  assert.match(r.headers.get('location'), /^\/totp\?next=\/pending\/[A-Za-z0-9_-]{22}$/);
  assert.equal(meta('slack').enabled, false);
  const draft = h.app.db.prepare('SELECT * FROM pending_actions').all();
  assert.equal(draft.length, 1);
  assert.ok(!draft[0].body_json.includes(SLACK_URL.split('/').pop()));

  // свежий код: страница «было → стало», затем применение
  h.fresh(c);
  const pageHtml = await (await c.get(r.headers.get('location').replace('/totp?next=', ''))).text();
  assert.match(pageHtml, /Notifications: Slack/);
  r = await c.post(`/pending/${draft[0].id}/apply`);
  assert.equal(r.status, 302);
  assert.deepEqual(meta('slack'), { enabled: true, events: ['security', 'info'], configured: true });

  // смена событий и выключение — сразу, даже без свежего кода
  h.stale(c);
  r = await c.post('/settings/notify/slack', { enabled: '1', events: ['security'] });
  assert.equal(r.headers.get('location'), '/settings');
  assert.deepEqual(meta('slack').events, ['security']);
  r = await c.post('/settings/notify/slack', { events: ['security'] });
  assert.equal(r.headers.get('location'), '/settings');
  assert.equal(meta('slack').enabled, false);

  // включить канал без сохранённого подключения нельзя
  h.fresh(c);
  r = await c.post('/settings/notify/email', { enabled: '1', events: ['security'] });
  assert.equal(r.headers.get('location'), '/settings');
  assert.equal(meta('email'), null);
  // неизвестный канал
  assert.equal((await c.post('/settings/notify/telegram', { enabled: '1' })).status, 404);
  assert.ok(h.app.repo.listAudit({ limit: 100 }).some((a) => a.action === 'notify.channel' && a.target === 'slack'));
});
