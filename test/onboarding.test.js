// Онбординг «Connect your agent» (ТЗ §5, пункт 6.5): прогресс, карточки, токен один раз, «It works», пропуск.
// Без внешней сети: mock-сервис на localhost. Токены в тестах не пишутся: берутся из ответов сервера.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { makeLink } from '../src/auth/links.js';
import { totpAt } from '../src/auth/totp.js';
import { initI18n } from '../src/i18n.js';
import { onboardingState, needsWelcome, snippetFor, KINDS } from '../src/web/onboarding.js';
import { sha256hex } from '../src/core/access.js';
import crypto from 'node:crypto';

initI18n('en');

const PASSWORD = 'correct-horse-battery';
const BOT = '123456:' + 'A'.repeat(35);
const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";
const WAITLIST = 'https://example.com/waitlist';
const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) await f(); });

let mock, mockPort;
async function startMock() {
  if (mock) return;
  mock = http.createServer((req, res) => { res.setHeader('content-type', 'application/json'); req.resume(); req.on('end', () => res.end('{"ok":true}')); });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  mockPort = mock.address().port;
  cleanup.push(() => new Promise((r) => { mock.closeAllConnections(); mock.close(r); }));
}

/** Приложение + владелец, прошедший мастер (пропуск Telegram); сессия со свежим кодом. */
async function boot(extra = {}) {
  await startMock();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-onb-'));
  const app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { 'api.telegram.org': `http://127.0.0.1:${mockPort}` }, ...extra,
  });
  await app.start();
  cleanup.push(() => app.stop());
  const base = `http://127.0.0.1:${app.fastify.server.address().port}`;
  const jar = new Map();
  const c = { token: '', app, base };
  const store = (res) => { for (const s of res.headers.getSetCookie?.() || []) { const [kv, ...attrs] = s.split(';'); const [k, v] = kv.split('='); if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(k); else jar.set(k, v); } };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  c.get = async (p) => {
    const r = await fetch(base + p, { headers: { cookie: cookie() }, redirect: 'manual' }); store(r);
    const text = await r.clone().text(); const m = text.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    r.text2 = text; return r;
  };
  c.post = async (p, fields = {}) => {
    const body = new URLSearchParams({ _csrf: c.token, ...fields });
    const r = await fetch(base + p, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' }); store(r);
    r.text2 = await r.clone().text(); const m = r.text2.match(/name="_csrf" value="([^"]+)"/); if (m) c.token = m[1];
    return r;
  };
  const { token } = makeLink(app.repo, 'setup', 900, base);
  await c.get(`/setup/${token}`); await c.get('/setup');
  await c.post('/setup', { step: '1', password: PASSWORD, password_repeat: PASSWORD });
  const page = (await c.get('/setup')).text2;
  const secret = page.match(/Manual key: <code>([A-Z2-7]+)<\/code>/)?.[1] || page.match(/([A-Z2-7]{16,})<\/code>/)[1];
  await c.post('/setup', { step: '2', code: totpAt(secret, Math.floor(Date.now() / 30000)) });
  c.finish = () => c.post('/setup', { step: '3', mode: 'skip' });
  c.setTotp = (v) => {
    // totp_at сессии (по sha256 cookie) — как в тестах черновиков
    const sha = app.db.prepare('SELECT id_hash FROM sessions').all();
    for (const s of sha) app.db.prepare('UPDATE sessions SET totp_at = ? WHERE id_hash = ?').run(v, s.id_hash);
  };
  return c;
}

const tokenIn = (s) => s.match(/gwa_[A-Za-z0-9_-]+/)?.[0];
const agentsOf = (c) => c.app.repo.listAgents();

test('прогресс 0/3 → 3/3 выводится из базы; пропуск шага уведомлений', async () => {
  const c = await boot();
  const r = await c.finish();
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/welcome');
  const repo = c.app.repo;
  assert.equal(onboardingState(repo).count, 0);
  const first = (await c.get('/welcome')).text2;
  assert.match(first, /0 of 3 done/);
  // новому пользователю Zendesk токен не выдаёт: на первом экране карточки нет, в каталоге ключей она остаётся
  assert.doesNotMatch(first, /\/keys\/new\/zendesk/);
  assert.match(first, /\/keys\/new\/hubspot/);
  assert.match((await c.get('/keys/new')).text2, /\/keys\/new\/zendesk/);
  assert.match((await c.get('/')).text2, /href="\/welcome"/, 'на корне есть ссылка на онбординг');
  await c.post('/welcome/agent/script');
  assert.equal(onboardingState(repo).count, 1);
  assert.equal(onboardingState(repo).agent, true);
  assert.equal(needsWelcome(onboardingState(repo)), false, 'агент есть: ссылка с корня исчезает');
  const k = await c.post('/keys/new/telegram', { key: BOT, label: 'bot', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  assert.equal(k.status, 302);
  assert.equal(onboardingState(repo).count, 2);
  assert.equal(onboardingState(repo, { telegramConnected: true }).count, 3, 'Telegram подключён = шаг 3');
  assert.match((await c.get('/welcome')).text2, /2 of 3 done/);
  const s = await c.post('/welcome/skip-notify');
  assert.equal(s.status, 302);
  assert.equal(onboardingState(repo).count, 3);
  assert.match((await c.get('/welcome')).text2, /3 of 3 done/);
});

test('карточка создаёт ровно одного агента, токен виден один раз, no-store; сниппет Claude Code с publicUrl/mcp', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  const r = await c.post('/welcome/agent/claude-code');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.equal(agentsOf(c).length, 1);
  assert.equal(agentsOf(c)[0].name, 'Claude Code');
  const tok = tokenIn(r.text2);
  assert.ok(tok, 'токен показан');
  assert.ok(r.text2.includes('claude mcp add --transport http'));
  assert.ok(r.text2.includes('http://127.0.0.1/mcp'), 'publicUrl + /mcp');
  // ТЗ 1.0.2 (пакет 4): сниппет claude-code читает $AGENTKEYGATE_TOKEN, сам токен в тексте не печатается
  assert.ok(r.text2.includes('--header &quot;Authorization: Bearer $AGENTKEYGATE_TOKEN&quot;'), 'заголовок с переменной окружения');
  assert.ok(!r.text2.slice(0, r.text2.indexOf('token-box')).includes(tok), 'в сниппете токена нет');
  assert.match(r.text2, /data-copy="#snippet"/);
  assert.doesNotMatch(r.text2, /<script(?![^>]*\ssrc="\/public\/)/i, 'нет инлайн-скриптов');
  assert.equal(r.headers.get('content-security-policy'), CSP);
  // перезагрузка: токена нет, агент один
  for (const p of ['/welcome', '/agents', '/']) assert.equal(tokenIn((await c.get(p)).text2), undefined, p);
  assert.equal(agentsOf(c).length, 1);
  // в БД и аудите токена нет
  assert.ok(!JSON.stringify(c.app.repo.listAudit({ limit: 200 })).includes(tok));
});

test('без свежего кода карточка уходит в черновик; после кода создаётся один агент; gwa_ нет в адресах', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  c.setTotp(1000); // код давно не вводился
  const r = await c.post('/welcome/agent/cursor');
  assert.equal(r.status, 302);
  const loc = r.headers.get('location');
  assert.match(loc, /^\/totp\?next=\/pending\/[A-Za-z0-9_-]{22}$/);
  assert.ok(!loc.includes('gwa_'));
  assert.equal(agentsOf(c).length, 0);
  c.setTotp(Math.floor(Date.now() / 1000));
  const id = loc.split('/pending/')[1];
  const page = await c.get(`/pending/${id}`); assert.equal(page.status, 200);
  const done = await c.post(`/pending/${id}/apply`);
  assert.equal(done.status, 200);
  assert.equal(agentsOf(c).length, 1); assert.equal(agentsOf(c)[0].name, 'Cursor');
  const tok = tokenIn(done.text2);
  assert.ok(tok);
  assert.ok(done.text2.includes('mcp.json') || done.text2.includes('&quot;mcpServers&quot;'), 'сниппет Cursor');
  assert.ok(!done.text2.includes('cursor://'), 'deep-link не используется');
  const again = await c.post(`/pending/${id}/apply`);
  assert.notEqual(again.status, 200, 'черновик одноразовый');
  assert.equal(agentsOf(c).length, 1);
});

test('сниппеты всех карточек; кривой вид карточки даёт 404', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  const seen = [];
  for (const k of ['chatgpt', 'claude-code', 'cursor', 'claude-desktop', 'script']) {
    const r = await c.post(`/welcome/agent/${k}`);
    assert.equal(r.status, 200, k);
    const loc = r.headers.get('location'); assert.equal(loc, null);
    assert.ok(!/href="[^"]*gwa_/.test(r.text2), `${k}: токена нет в href`);
    seen.push(r.text2);
  }
  assert.equal(agentsOf(c).length, 5);
  assert.ok(seen[4].includes('/v1/grants'), 'curl для скрипта');
  assert.ok(seen[3].includes('mcp-remote'));
  assert.ok(seen[0].includes('openapi'));
  assert.equal((await c.post('/welcome/agent/evil')).status, 404);
  assert.equal(agentsOf(c).length, 5);
  assert.ok(snippetFor('claude-code', { publicUrl: 'https://gw.example', token: 'T' }).includes('https://gw.example/mcp'));
});

test('«It works» после успешного вызова через прокси; лист ожидания и ссылка на Activity', async () => {
  const c = await boot({ waitlistUrl: WAITLIST });
  await c.finish(); await c.get('/welcome');
  assert.doesNotMatch((await c.get('/welcome')).text2, /It works/);
  const created = await c.post('/welcome/agent/script');
  const agentToken = tokenIn(created.text2);
  await c.post('/keys/new/telegram', { key: BOT, label: 'bot', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  const hdr = { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json' };
  let g = await fetch(`${c.base}/v1/grants`, { method: 'POST', headers: hdr, body: JSON.stringify({ provider: 'telegram', ttl: 600, calls: 2 }) });
  assert.equal(g.status, 202);
  const reqId = (await g.json()).request_id;
  await c.get('/');
  assert.equal((await c.post(`/requests/${reqId}/approve`)).status, 302);
  g = await fetch(`${c.base}/v1/grants/${reqId}`, { headers: { authorization: `Bearer ${agentToken}` } });
  const pass = (await g.json()).token;
  assert.match((await c.get('/welcome')).text2, /2 of 3 done|1 of 3 done/);
  assert.doesNotMatch((await c.get('/welcome')).text2, /It works/, 'вызовов ещё не было');
  const call = await fetch(`${c.base}/v1/proxy/telegram/getMe`, { headers: { authorization: `Bearer ${pass}` } });
  assert.equal(call.status, 200);
  assert.equal(c.app.repo.countOkCalls(), 1);
  const w = (await c.get('/welcome')).text2;
  assert.match(w, /It works/);
  assert.match(w, /href="\/stats"/);
  assert.ok(w.includes(`href="${WAITLIST}"`), 'лист ожидания из config.waitlistUrl');
  assert.ok(!w.includes(BOT), 'ключ нигде не показан');
});

test('новые карточки (ТЗ 1.0.2): KINDS, сниппеты без токена, форматы по типам', () => {
  const url = 'https://gw.example.com';
  const tok = `gwa_${'k'.repeat(24)}`;
  const snip = (k) => snippetFor(k, { publicUrl: url, token: tok });
  for (const k of ['codex', 'vscode', 'gemini', 'hermes', 'openclaw', 'cursor', 'claude-code', 'script']) {
    assert.ok(KINDS.includes(k), k);
    assert.ok(!snip(k).includes(tok), `${k}: токена в тексте нет`);
  }
  // codex: TOML с bearer_token_env_var
  const codex = snip('codex');
  assert.ok(codex.includes('[mcp_servers.agentkeygate]'), codex);
  assert.ok(codex.includes(`url = "${url}/mcp"`), codex);
  assert.ok(codex.includes('bearer_token_env_var = "AGENTKEYGATE_TOKEN"'), codex);
  // vscode: JSON с inputs password и ${input:...}
  const vs = JSON.parse(snip('vscode'));
  assert.equal(vs.servers.agentkeygate.type, 'http');
  assert.equal(vs.servers.agentkeygate.url, `${url}/mcp`);
  assert.equal(vs.inputs[0].password, true);
  assert.ok(String(vs.servers.agentkeygate.headers.Authorization).includes('${input:'), snip('vscode'));
  // gemini: httpUrl
  const g = JSON.parse(snip('gemini'));
  assert.equal(g.mcpServers.agentkeygate.httpUrl, `${url}/mcp`);
  assert.ok(String(g.mcpServers.agentkeygate.headers.Authorization).includes('$AGENTKEYGATE_TOKEN'));
  // hermes: YAML
  const hermes = snip('hermes');
  for (const part of ['mcp_servers:', 'agentkeygate:', `${url}/mcp`, '${AGENTKEYGATE_TOKEN}']) assert.ok(hermes.includes(part), part);
  // openclaw: mcp.servers с transport streamable-http
  const oc = JSON.parse(snip('openclaw'));
  assert.equal(oc.mcp.servers.agentkeygate.transport, 'streamable-http');
  assert.equal(oc.mcp.servers.agentkeygate.url, `${url}/mcp`);
  // cursor: переменная окружения в форме Cursor
  assert.ok(snip('cursor').includes('${env:AGENTKEYGATE_TOKEN}'));
  // claude-code: команда c переменной
  assert.ok(snip('claude-code').includes('claude mcp add --transport http agentkeygate'));
  assert.ok(snip('claude-code').includes('$AGENTKEYGATE_TOKEN'));
  // script: curl с переменной
  assert.ok(snip('script').includes('$AGENTKEYGATE_TOKEN'));
  // claude-desktop и chatgpt остались как были: токен в тексте
  assert.ok(snip('claude-desktop').includes(tok));
  assert.ok(snip('chatgpt').includes('openapi'));
});

test('страница создания: блок «что сказать агенту», ссылка на проверку; страница проверки и троттлинг last_seen_at', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  const r = await c.post('/welcome/agent/codex');
  assert.equal(r.status, 200);
  assert.match(r.text2, /What to tell the agent/);
  assert.match(r.text2, /List the services available through agentkeygate/);
  assert.match(r.text2, /data-copy="#say"/);
  const agent = c.app.repo.listAgents()[0];
  assert.ok(agent);
  assert.match(r.text2, new RegExp(`href="/welcome/check/${agent.id}"`), 'ссылка на проверку подключения');
  // страница проверки: без обращения «ещё нет», обновление ссылкой, чужой id даёт 404
  assert.doesNotMatch(r.text2, /<script(?![^>]*\ssrc="\/public\/)/i, 'без инлайн-скриптов');
  const check1 = await c.get(`/welcome/check/${agent.id}`);
  assert.equal(check1.status, 200);
  assert.match(check1.text2, /has not connected yet/);
  assert.match(check1.text2, /href="\/welcome\/check\//, 'кнопка обновить');
  // троттлинг: повторный touch внутри минуты не пишет, за окном пишет
  c.app.repo.touchAgent(agent.id);
  const seen = c.app.repo.getAgent(agent.id).last_seen_at;
  assert.ok(seen, 'после touch last_seen_at выставлен');
  c.app.db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(seen - 30, agent.id);
  c.app.repo.touchAgent(agent.id);
  assert.equal(c.app.repo.getAgent(agent.id).last_seen_at, seen - 30, 'внутри минуты last_seen_at не меняется');
  c.app.db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(seen - 120, agent.id);
  c.app.repo.touchAgent(agent.id);
  assert.ok(c.app.repo.getAgent(agent.id).last_seen_at > seen - 120, 'после окна last_seen_at обновляется');
  const check2 = await c.get(`/welcome/check/${agent.id}`);
  assert.doesNotMatch(check2.text2, /has not connected yet/);
  assert.equal((await c.get('/welcome/check/nope')).status, 404);
  // аноним на вход, создание агента требует сессии
  const anon = await fetch(`${c.base}/welcome/check/${agent.id}`, { redirect: 'manual' });
  assert.equal(anon.status, 302);
  assert.equal(anon.headers.get('location'), '/login');
});

test('успешная авторизация в REST, MCP и прокси ставит last_seen_at; неверный токен и отключённый агент не ставят', async () => {
  await startMock();
  const c = await boot({ testUpstream: { 'api.telegram.org': `http://127.0.0.1:${mockPort}`, 'test.bitrix24.ru': `http://127.0.0.1:${mockPort}` } });
  const { repo, db } = c.app;
  const mk = (id) => {
    const token = `gwa_${crypto.randomBytes(24).toString('base64url')}`;
    repo.createAgent({ id, name: id, token_hash: sha256hex(token), enabled: 1, all_credentials: 1 });
    return token;
  };
  const seen = (id) => repo.getAgent(id).last_seen_at;
  const auth = (token) => ({ authorization: `Bearer ${token}` });

  // REST: GET заявки не проходит через requests.js, поэтому проверяет именно авторизацию API
  const rest = mk('t-rest');
  await (await fetch(`${c.base}/v1/grants/none`, { headers: auth(rest) })).text();
  assert.ok(seen('t-rest'), 'REST');

  // MCP
  const mcp = mk('t-mcp');
  const m = await fetch(`${c.base}/mcp`, {
    method: 'POST',
    headers: { ...auth(mcp), 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
  });
  await m.text();
  assert.equal(m.status, 200);
  assert.ok(seen('t-mcp'), 'MCP');

  // прокси: после выдачи пропуска отметка сбрасывается, вызов пропуском ставит её снова
  repo.createCredential({ id: 't-cred', provider: 'bitrix24', label: 't', kind: 'path', host: 'test.bitrix24.ru', injection: { type: 'path', template: '/rest/{secret}' }, vault_param: 'cred/t-cred', last4: '0000', mode: 'always', max_ttl: 3600, max_calls: 10, max_parallel: 2 });
  await c.app.ctx.vault.put('cred/t-cred', crypto.randomBytes(16).toString('hex'));
  const g = await fetch(`${c.base}/v1/grants`, { method: 'POST', headers: { ...auth(rest), 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'bitrix24', ttl: 600, calls: 5, reason: 't' }) });
  assert.equal(g.status, 200);
  const pass = (await g.json()).token;
  db.prepare('UPDATE agents SET last_seen_at = NULL WHERE id = ?').run('t-rest');
  const p = await fetch(`${c.base}/v1/proxy/bitrix24/crm.deal.list.json`, { headers: auth(pass) });
  await p.text();
  assert.equal(p.status, 200);
  assert.ok(seen('t-rest'), 'прокси');

  // неудачная авторизация отметку не ставит
  const off = mk('t-off');
  repo.setAgentEnabled('t-off', 0);
  await (await fetch(`${c.base}/v1/grants/none`, { headers: auth(off) })).text();
  assert.ok(!seen('t-off'), 'отключённый агент');
});

test('страница создания: блок про переменную только там, где сниппет её читает; проверка открывается в новой вкладке', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  const code = await c.post('/welcome/agent/claude-code');
  assert.ok(code.text2.includes('read -rs AGENTKEYGATE_TOKEN'), 'команда для bash');
  assert.ok(code.text2.includes('$env:AGENTKEYGATE_TOKEN = Read-Host'), 'команда для PowerShell');
  assert.match(code.text2, /href="\/welcome\/check\/[^"]+" target="_blank"/, 'страница с токеном остаётся открытой');
  await c.get('/welcome');
  const vs = await c.post('/welcome/agent/vscode');
  assert.ok(!vs.text2.includes('read -rs AGENTKEYGATE_TOKEN'), 'у VS Code скрытый ввод, переменная не нужна');
});

test('пропуск онбординга убирает ссылку с корня; страницы без инлайн-скриптов и внешних ресурсов', async () => {
  const c = await boot();
  await c.finish();
  const w = await c.get('/welcome');
  assert.equal(w.status, 200);
  assert.equal(w.headers.get('content-security-policy'), CSP);
  assert.equal(w.headers.get('cache-control'), 'no-store');
  for (const html of [w.text2, (await c.get('/')).text2]) {
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc="\/public\/[a-z.]+")[^>]*>/i, 'нет инлайн-скриптов');
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'нет inline-обработчиков');
    assert.doesNotMatch(html, /<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)="(?:https?:)?\/\//i, 'нет внешних загрузок');
    assert.doesNotMatch(html, /\bstyle="/i);
  }
  assert.match((await c.get('/')).text2, /href="\/welcome"/);
  const s = await c.post('/welcome/skip');
  assert.equal(s.status, 302); assert.equal(s.headers.get('location'), '/');
  const root = await c.get('/');
  assert.equal(root.status, 200);
  assert.doesNotMatch(root.text2, /href="\/welcome"/, 'после пропуска ссылки нет');
  assert.equal(onboardingState(c.app.repo).skipped, true);
});

test('онбординг только для владельца: без сессии — на вход', async () => {
  const c = await boot();
  await c.finish();
  const r = await fetch(`${c.base}/welcome`, { redirect: 'manual' });
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/login');
  const p = await fetch(`${c.base}/welcome/agent/script`, { method: 'POST', redirect: 'manual' });
  assert.ok([302, 403].includes(p.status));
  assert.equal(agentsOf(c).length, 0);
});

test('скрипт: страница агента называет имена сервисов для <service>, без ключей — подсказка', async () => {
  const c = await boot();
  await c.finish(); await c.get('/welcome');
  const empty = (await c.post('/welcome/agent/script')).text2;
  assert.match(empty, /No keys yet\. The service name for &lt;service&gt;/);
  await c.post('/keys/new/telegram', { key: BOT, label: 'bot', mode: 'ask', approval: 'web_button', max_ttl: '3600', max_calls: '3', max_parallel: '2' });
  await c.get('/welcome');
  const named = (await c.post('/welcome/agent/script')).text2;
  assert.match(named, /in place of &lt;service&gt;: telegram\./);
  // другим карточкам список не нужен: у них есть MCP
  assert.doesNotMatch((await c.post('/welcome/agent/claude-code')).text2, /in place of &lt;service&gt;/);
});
