// Скриншоты интерфейса глазами: поднимает локальный экземпляр
// на чистом каталоге данных (сейф file, без сети), проходит мастер и вход программно, заводит тестовые ключи
// с поддельными значениями, агента и заявку, затем снимает экраны headless Chrome по CDP.
// Запуск: node tools/ui-shots.mjs [en|ru ...]   Результат: out/ui-review/<lang>/<экран>-<вариант>.png
// Ключи поддельные (только формат), пароль и секрет 2FA — случайные на один прогон, нигде не сохраняются.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { totpAt } from '../src/auth/totp.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'out', 'ui-review');
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const WAIT_FRESH = Number(process.env.UI_WAIT_FRESH ?? 305); // окно свежести TOTP 300 с: ради экрана «было → стало»
const LANG_VARIANTS = {
  en: [['desktop', 'light'], ['desktop', 'dark'], ['mobile', 'light'], ['mobile', 'dark']],
  ru: [['desktop', 'light'], ['mobile', 'dark']],
};
const VIEW = { desktop: { width: 1366, height: 900, mobile: false }, mobile: { width: 375, height: 812, mobile: true } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- HTTP-клиент сайта с cookie и CSRF
function client(base) {
  const jar = new Map();
  async function web(method, p, form) {
    const headers = { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') };
    let body;
    if (form) {
      const u = new URLSearchParams();
      for (const [k, v] of Object.entries(form)) for (const x of [].concat(v)) u.append(k, String(x));
      body = u.toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin = base;
    }
    const r = await fetch(base + p, { method, headers, body, redirect: 'manual' });
    for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); const v = kv.slice(i + 1); if (v) jar.set(kv.slice(0, i), v); else jar.delete(kv.slice(0, i)); }
    return { status: r.status, location: r.headers.get('location'), text: await r.text() };
  }
  return { jar, web };
}

// Поля формы по умолчанию (как отправил бы браузер без правок): input/select/textarea внутри <form action="...">
function formDefaults(html, actionRe) {
  const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/g)];
  const f = forms.find((m) => actionRe.test((m[1].match(/action="([^"]*)"/) || [])[1] || ''));
  if (!f) return null;
  const attr = (s, n) => (s.match(new RegExp(`\\b${n}="([^"]*)"`)) || [])[1];
  const unesc = (s) => (s || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  const out = {};
  const add = (k, v) => { if (!k) return; out[k] = k in out ? [].concat(out[k], v) : v; };
  for (const m of f[2].matchAll(/<input\b([^>]*)>/g)) {
    const a = m[1]; const type = (attr(a, 'type') || 'text').toLowerCase();
    if (['submit', 'button', 'file'].includes(type)) continue;
    if ((type === 'checkbox' || type === 'radio') && !/\bchecked\b/.test(a)) continue;
    add(attr(a, 'name'), unesc(attr(a, 'value') ?? (type === 'checkbox' ? 'on' : '')));
  }
  for (const m of f[2].matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g)) {
    const opts = [...m[2].matchAll(/<option\b([^>]*)>/g)].map((o) => o[1]);
    const sel = opts.find((o) => /\bselected\b/.test(o)) ?? opts[0];
    if (sel !== undefined) add(attr(m[1], 'name'), unesc(attr(sel, 'value')));
  }
  for (const m of f[2].matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g)) add(attr(m[1], 'name'), unesc(m[2]));
  return out;
}

// ---- Chrome DevTools Protocol
async function startChrome(port) {
  const dir = fs.mkdtempSync(path.join(OUT, 'chrome-'));
  const proc = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, '--no-first-run', '--hide-scrollbars', '--disable-extensions', 'about:blank'], { stdio: 'ignore' });
  let ver;
  for (let i = 0; i < 50 && !ver; i++) { await sleep(200); ver = await fetch(`http://127.0.0.1:${port}/json/version`).then((r) => r.json()).catch(() => null); }
  if (!ver) throw new Error('chrome did not start');
  const ws = new WebSocket(ver.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let seq = 0; const waits = new Map(); const listeners = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && waits.has(m.id)) { const w = waits.get(m.id); waits.delete(m.id); m.error ? w.j(new Error(m.error.message)) : w.r(m.result); }
    else if (m.method) for (const l of listeners) l(m);
  };
  const send = (method, params = {}, sessionId) => new Promise((r, j) => { const id = ++seq; waits.set(id, { r, j }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const page = (method, params) => send(method, params, sessionId);
  await page('Page.enable'); await page('Network.enable');
  const loaded = () => new Promise((r) => { const l = (m) => { if (m.method === 'Page.loadEventFired' && m.sessionId === sessionId) { listeners.splice(listeners.indexOf(l), 1); r(); } }; listeners.push(l); });
  return {
    async shot(url, cookies, file, [view, theme]) {
      const v = VIEW[view];
      await page('Emulation.setDeviceMetricsOverride', { width: v.width, height: v.height, deviceScaleFactor: 1, mobile: v.mobile });
      await page('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] });
      await page('Network.clearBrowserCookies');
      for (const [name, value] of cookies) await page('Network.setCookie', { name, value, url });
      const done = loaded(); await page('Page.navigate', { url }); await done; await sleep(250);
      const { cssContentSize: s } = await page('Page.getLayoutMetrics');
      const { data } = await page('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: v.width, height: Math.min(Math.ceil(s.height), 6000), scale: 1 } });
      fs.writeFileSync(file, Buffer.from(data, 'base64'));
    },
    // Страница-ответ на POST: открыть форму, заполнить и отправить в самом браузере, снять результат
    async shotSubmit(url, cookies, file, variant, js) {
      await this.shot(url, cookies, file, variant);
      const done = loaded(); await page('Runtime.evaluate', { expression: js }); await done; await sleep(250);
      const v = VIEW[variant[0]];
      const { cssContentSize: s } = await page('Page.getLayoutMetrics');
      const { data } = await page('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: v.width, height: Math.min(Math.ceil(s.height), 6000), scale: 1 } });
      fs.writeFileSync(file, Buffer.from(data, 'base64'));
    },
    close() {
      try { ws.close(); } catch { /* уже закрыт */ }
      proc.kill();
      // профиль Chrome на Windows освобождается не сразу; не удалился — останется в out/ (в .gitignore)
      setTimeout(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* занят */ } }, 3000);
    },
  };
}

async function runLang(lang, port, cdpPort) {
  const dir = path.join(OUT, lang); fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
  const dataDir = path.join(OUT, `data-${lang}`); fs.rmSync(dataDir, { recursive: true, force: true }); fs.mkdirSync(dataDir, { recursive: true });
  const base = `http://127.0.0.1:${port}`;
  const env = { ...process.env, GW_DATA_DIR: dataDir, GW_PORT: String(port), GW_PUBLIC_URL: base, GW_VAULT: 'file', GW_LANG: lang, GW_LOG_LEVEL: 'warn', GW_TZ: 'Europe/Moscow' };
  const init = spawnSync(process.execPath, ['bin/gateway.js', 'init'], { cwd: ROOT, env, encoding: 'utf8' });
  const link = (init.stdout + init.stderr).match(/http:\/\/\S+\/setup\/[A-Za-z0-9_-]+/)?.[0];
  if (!link) throw new Error(`${lang}: no setup link from init`);
  const srv = spawn(process.execPath, ['bin/gateway.js', 'start'], { cwd: ROOT, env, stdio: ['ignore', 'ignore', 'pipe'] });
  srv.stderr.on('data', (d) => fs.appendFileSync(path.join(dir, 'server.log'), d));
  for (let i = 0; i < 50; i++) { await sleep(200); if (await fetch(base + '/healthz').then((r) => r.ok).catch(() => false)) break; }
  const chrome = await startChrome(cdpPort);
  const { jar, web } = client(base);
  const csrfOf = (h) => h.match(/name="_csrf" value="([^"]+)"/)?.[1];
  const post = async (p, form, from) => web('POST', p, { _csrf: csrfOf((await web('GET', from)).text), ...form });
  const shots = [];
  const shot = async (name, p, cookies = [...jar]) => {
    for (const variant of LANG_VARIANTS[lang]) {
      const file = path.join(dir, `${name}-${variant.join('-')}.png`);
      await chrome.shot(base + p, cookies, file, variant); shots.push(path.relative(OUT, file));
    }
  };
  try {
    // мастер
    await web('GET', new URL(link).pathname);
    await shot('01-setup-1-password', '/setup');
    const password = crypto.randomBytes(18).toString('base64url');
    await post('/setup', { step: '1', password, password_repeat: password }, '/setup');
    const s2 = await web('GET', '/setup');
    const secret = s2.text.match(/<code>([A-Z2-7]{16,})<\/code>/)?.[1];
    await shot('02-setup-2-totp', '/setup');
    const code = () => totpAt(secret, Math.floor(Date.now() / 30000));
    await post('/setup', { step: '2', code: code() }, '/setup');
    await shot('03-setup-3-telegram', '/setup');
    await post('/setup', { step: '3', mode: 'skip' }, '/setup');
    await shot('04-welcome', '/welcome');
    // вход (отдельно, без сессии)
    const anon = [];
    await shot('05-login', '/login', anon);
    // ключи с поддельными значениями нужного формата
    const keys = [
      ['hubspot', { key: 'pat-eu1-' + crypto.randomUUID() }],
      ['bitrix24', { webhook_url: 'https://acme.bitrix24.com/rest/1/' + crypto.randomBytes(8).toString('hex') + '/' }],
      ['stripe', { key: 'rk_test_' + crypto.randomBytes(12).toString('hex') }],
      ['telegram', { key: '123456789:' + crypto.randomBytes(27).toString('base64url').slice(0, 35) }],
    ];
    await shot('06-keys-empty', '/');
    await shot('07-keys-new', '/keys/new');
    await shot('08-key-form-hubspot', '/keys/new/hubspot');
    const submit = (fill) => `(() => { const f = [...document.forms].find((x) => /${'${ACTION}'}/.test(x.getAttribute('action') || '')); ${fill}; f.requestSubmit ? f.requestSubmit() : f.submit(); })()`;
    const shotSubmit = async (name, p, action, fill) => {
      for (const variant of LANG_VARIANTS[lang]) {
        const file = path.join(dir, `${name}-${variant.join('-')}.png`);
        await chrome.shotSubmit(base + p, [...jar], file, variant, submit(fill).replace('${ACTION}', action)); shots.push(path.relative(OUT, file));
      }
    };
    // неверный формат ключа: ошибка формы (в сеть ничего не уходит)
    await shotSubmit('09-key-form-error', '/keys/new/gemini', '\\/keys\\/new\\/gemini$', "f.elements.key.value = 'not-a-key'");
    for (const [slug, values] of keys) {
      const form = formDefaults((await web('GET', `/keys/new/${slug}`)).text, new RegExp(`/keys/new/${slug}$`));
      const r = await post(`/keys/new/${slug}`, { ...form, ...values }, `/keys/new/${slug}`);
      if (r.status !== 302) throw new Error(`${lang}: key ${slug} not saved (${r.status})`);
    }
    const home = (await web('GET', '/')).text;
    const ids = [...new Set([...home.matchAll(/href="\/keys\/([A-Za-z0-9_-]{6,})"/g)].map((m) => m[1]))];
    const credOf = async (slug) => { for (const id of ids) if ((await web('GET', `/keys/${id}`)).text.includes(`/keys/new/${slug}`) || (await web('GET', `/keys/${id}`)).text.includes(`icons/${slug}`)) return id; return ids[0]; };
    const hub = await credOf('hubspot'); const btx = await credOf('bitrix24');
    await shot('10-key-hubspot-filter', `/keys/${hub}`);
    await shot('11-key-bitrix24-filter', `/keys/${btx}`);
    // агент и заявка
    const agentsHtml = (await web('GET', '/agents')).text;
    const af = formDefaults(agentsHtml, /^\/agents$/) || {};
    const nameField = Object.keys(af).find((k) => /name/.test(k)) || 'name';
    const created = await post('/agents', { ...af, [nameField]: 'research-bot' }, '/agents');
    const token = created.text.match(/gwa_[A-Za-z0-9_-]+/)?.[0];
    await shot('12-agents', '/agents');
    await shotSubmit('13-agent-created', '/agents', '^\\/agents$', `f.elements['${nameField}'].value = 'demo-' + Math.random().toString(36).slice(2, 7)`);
    let reqId;
    if (token) {
      const g = await fetch(base + '/v1/grants', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ provider: 'hubspot', credential_id: hub, ttl: 900, calls: 20, reason: lang === 'ru' ? 'Выгрузить сделки за неделю для отчёта' : 'Export last week deals for the report' }) }).then((r) => r.json());
      reqId = g.request_id;
    }
    await shot('14-home-with-request', '/');
    if (reqId) { await shot('15-request-approve-confirm', `/requests/${reqId}/approve-confirm`); await shot('16-requests', '/requests'); }
    await shot('17-settings', '/settings');
    await shot('18-audit', '/audit');
    await shot('19-stats', '/stats');
    await shot('20-not-found', '/keys/nope');
    // вход: пароль → экран 2FA (отдельная сессия)
    const c2 = client(base);
    const lp = (await c2.web('GET', '/login')).text;
    await c2.web('POST', '/login', { _csrf: csrfOf(lp), password });
    await shot('21-totp', '/totp', [...c2.jar]);
    // «было → стало»: правка политики без свежего TOTP уходит в черновик
    if (WAIT_FRESH > 0) {
      await sleep(WAIT_FRESH * 1000);
      const kp = (await web('GET', `/keys/${hub}`)).text;
      const pf = formDefaults(kp, new RegExp(`/keys/${hub}/policy$`));
      if (pf) {
        const r = await post(`/keys/${hub}/policy`, { ...pf, mode: 'always' }, `/keys/${hub}`);
        const next = r.location && new URL(r.location, base).searchParams.get('next');
        if (next) {
          await shot('23-totp-for-change', r.location);
          await post('/totp', { code: code(), next }, r.location);
          await shot('24-pending-diff', next);
        }
      }
    }
  } finally {
    chrome.close(); srv.kill();
  }
  return shots;
}

const langs = process.argv.slice(2).filter((l) => LANG_VARIANTS[l]);
fs.mkdirSync(OUT, { recursive: true });
const res = await Promise.all((langs.length ? langs : ['en', 'ru']).map((l, i) => runLang(l, 4610 + i, 9330 + i).then((s) => `${l}: ${s.length} shots`, (e) => `${l}: FAIL ${e.message}`)));
console.log(res.join('\n'));
console.log('DONE');
