// Анимация для README: агент просит доступ -> владелец одобряет на сайте -> вызов проходит.
// Поднимает демо-экземпляр (GW_DEMO=1: сервис Demo CRM, мок в процессе, без сети) на чистом каталоге в out/,
// снимает кадры headless Chrome по CDP (1280x800, светлая тема, en) и собирает GIF чистым JS, без ffmpeg и зависимостей.
// Запуск: node tools/demo-gif.mjs     Результат: assets/demo.gif (кадры в out/demo-gif/frames)
// Chrome: переменная CHROME. Токены агента на кадры не попадают; адресная строка не снимается (headless).
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'out', 'demo-gif');
const FRAMES = path.join(OUT, 'frames');
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 4630;
const CDP = 9360;
const W = 1280;
const H = 800;
const DELAY_CS = 250; // 2,5 с на кадр
const LAST_DELAY_CS = 350;
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

// ---- Chrome DevTools Protocol
async function startChrome() {
  const dir = fs.mkdtempSync(path.join(OUT, 'chrome-'));
  const proc = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${CDP}`, `--user-data-dir=${dir}`, '--no-first-run', '--hide-scrollbars', '--disable-extensions', 'about:blank'], { stdio: 'ignore' });
  let ver;
  for (let i = 0; i < 50 && !ver; i++) { await sleep(200); ver = await fetch(`http://127.0.0.1:${CDP}/json/version`).then((r) => r.json()).catch(() => null); }
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
  await page('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  await page('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  const loaded = () => new Promise((r) => { const l = (m) => { if (m.method === 'Page.loadEventFired' && m.sessionId === sessionId) { listeners.splice(listeners.indexOf(l), 1); r(); } }; listeners.push(l); });
  const evaluate = (expression) => page('Runtime.evaluate', { expression, awaitPromise: true });
  const snap = async (file) => {
    const { data } = await page('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: W, height: H, scale: 1 } });
    fs.writeFileSync(file, Buffer.from(data, 'base64'));
  };
  // Плашка с подписью шага поверх страницы (только стили через CSSOM: CSP сайта инлайн-атрибуты не пропускает)
  const caption = (n, text) => evaluate(`(() => {
    document.getElementById('demo-cap')?.remove();
    const d = document.createElement('div'); d.id = 'demo-cap';
    d.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:99999;padding:16px 28px;background:#14213d;color:#fff;font:600 22px/1.3 system-ui,Segoe UI,sans-serif;display:flex;gap:14px;align-items:center';
    const b = document.createElement('span'); b.textContent = ${JSON.stringify(String(n))};
    b.style.cssText = 'background:#fff;color:#14213d;border-radius:50%;width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;font-size:20px;flex:none';
    const s = document.createElement('span'); s.textContent = ${JSON.stringify(text)};
    d.append(b, s); document.body.append(d);
  })()`);
  return {
    async open(url, cookies, file, cap) {
      await page('Network.clearBrowserCookies');
      for (const [name, value] of cookies) await page('Network.setCookie', { name, value, url });
      const done = loaded(); await page('Page.navigate', { url }); await done; await sleep(300);
      if (cap) await caption(...cap);
      await snap(file);
    },
    // Заполненная страница-«терминал» агента: HTML кладётся в документ через CDP (внешних загрузок нет)
    async terminal(html, file, cap) {
      const done = loaded(); await page('Page.navigate', { url: 'about:blank' }); await done;
      const { frameTree } = await page('Page.getFrameTree');
      await page('Page.setDocumentContent', { frameId: frameTree.frame.id, html });
      await sleep(200);
      if (cap) await caption(...cap);
      await snap(file);
    },
    // Действие в странице (отправка формы) с ожиданием загрузки и снимком
    async act(expression, file, cap) {
      const done = loaded(); await evaluate(expression); await done; await sleep(300);
      if (cap) await caption(...cap);
      await snap(file);
    },
    close() {
      try { ws.close(); } catch { /* уже закрыт */ }
      proc.kill();
      setTimeout(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* занят */ } }, 3000);
    },
  };
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// Страница-терминал: команда агента и ответ шлюза. lines: [{ t: 'cmd' | 'out' | 'note', s }]
function terminalHtml(title, lines) {
  const body = lines.map((l) => `<div class="${l.t}">${esc(l.s)}</div>`).join('');
  return `<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;height:100%;background:#f4f6fb;font-family:system-ui,Segoe UI,sans-serif}
.wrap{padding:44px 64px}
h1{margin:0 0 22px;font-size:26px;color:#14213d}
.term{background:#fff;border:1px solid #cfd6e4;border-radius:10px;padding:26px 30px;font:20px/1.55 Consolas,Menlo,monospace;color:#1c2333;box-shadow:0 2px 10px rgba(20,33,61,.08);white-space:pre-wrap}
.cmd{color:#0b5cad}.cmd:before{content:"$ ";color:#6b7488}.note{color:#6b7488;margin-top:14px}.out{margin-top:8px}.sp{height:12px}
</style><div class="wrap"><h1>${esc(title)}</h1><div class="term">${body}</div></div>`;
}

// ---- PNG -> RGBA (8 бит, без чересстрочности: так отдаёт Chrome)
function decodePng(buf) {
  let p = 8; let w; let h; let ct; const idat = [];
  while (p < buf.length) {
    const len = buf.readUInt32BE(p); const type = buf.toString('latin1', p + 4, p + 8); const d = buf.subarray(p + 8, p + 8 + len);
    if (type === 'IHDR') { w = d.readUInt32BE(0); h = d.readUInt32BE(4); ct = d[9]; if (d[8] !== 8 || d[12] !== 0) throw new Error('png: unsupported'); }
    else if (type === 'IDAT') idat.push(d);
    p += 12 + len;
  }
  const bpp = ct === 6 ? 4 : ct === 2 ? 3 : 0;
  if (!bpp) throw new Error('png: unsupported color type');
  const raw = zlib.inflateSync(Buffer.concat(idat)); const stride = w * bpp; const px = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)]; const src = y * (stride + 1) + 1; const dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? px[dst + x - bpp] : 0; const b = y ? px[dst - stride + x] : 0; const c = x >= bpp && y ? px[dst - stride + x - bpp] : 0;
      let v = raw[src + x];
      if (f === 1) v += a; else if (f === 2) v += b; else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const pa = Math.abs(b - c); const pb = Math.abs(a - c); const pc = Math.abs(a + b - 2 * c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      px[dst + x] = v & 255;
    }
  }
  return { w, h, bpp, px };
}

// ---- палитра: медианный разрез по гистограмме 5 бит на канал
function buildPalette(images, size = 256) {
  const hist = new Map();
  for (const im of images) for (let i = 0; i < im.px.length; i += im.bpp) {
    const k = ((im.px[i] >> 3) << 10) | ((im.px[i + 1] >> 3) << 5) | (im.px[i + 2] >> 3);
    hist.set(k, (hist.get(k) || 0) + 1);
  }
  let boxes = [[...hist].map(([k, n]) => ({ r: (k >> 10) & 31, g: (k >> 5) & 31, b: k & 31, n }))];
  const range = (box, ch) => { let lo = 31; let hi = 0; for (const c of box) { lo = Math.min(lo, c[ch]); hi = Math.max(hi, c[ch]); } return hi - lo; };
  while (boxes.length < size) {
    // делим самый «населённый» ящик по самому широкому каналу
    let bi = -1; let best = 0;
    boxes.forEach((b, i) => { const wgt = b.reduce((s, c) => s + c.n, 0); if (b.length > 1 && wgt > best) { best = wgt; bi = i; } });
    if (bi < 0) break;
    const box = boxes[bi]; const ch = ['r', 'g', 'b'].sort((a, b) => range(box, b) - range(box, a))[0];
    box.sort((a, b) => a[ch] - b[ch]);
    const half = box.reduce((s, c) => s + c.n, 0) / 2; let acc = 0; let cut = 1;
    for (let i = 0; i < box.length - 1; i++) { acc += box[i].n; cut = i + 1; if (acc >= half) break; }
    boxes.splice(bi, 1, box.slice(0, cut), box.slice(cut));
  }
  const pal = boxes.map((b) => {
    const n = b.reduce((s, c) => s + c.n, 0);
    const avg = (ch) => Math.min(255, Math.round((b.reduce((s, c) => s + c[ch] * c.n, 0) / n) * 8 + 4));
    return [avg('r'), avg('g'), avg('b')];
  });
  // чистый белый и близкие к нему оттенки фона не должны уплывать
  pal[0] = pal[0] || [255, 255, 255];
  while (pal.length < size) pal.push([0, 0, 0]);
  return pal;
}

function indexImage(im, pal) {
  const cache = new Map(); const out = Buffer.alloc(im.w * im.h);
  for (let i = 0, o = 0; o < out.length; i += im.bpp, o++) {
    const r = im.px[i]; const g = im.px[i + 1]; const b = im.px[i + 2];
    const k = (r << 16) | (g << 8) | b; let idx = cache.get(k);
    if (idx === undefined) {
      let bd = Infinity; idx = 0;
      for (let j = 0; j < pal.length; j++) { const d = (pal[j][0] - r) ** 2 + (pal[j][1] - g) ** 2 + (pal[j][2] - b) ** 2; if (d < bd) { bd = d; idx = j; if (!d) break; } }
      cache.set(k, idx);
    }
    out[o] = idx;
  }
  return out;
}

// ---- GIF89a: LZW, глобальная палитра, цикл
function lzw(indices, minCode) {
  const clear = 1 << minCode; const eoi = clear + 1; const bytes = []; let cur = 0; let nbits = 0;
  const put = (code, size) => { cur |= code << nbits; nbits += size; while (nbits >= 8) { bytes.push(cur & 255); cur >>>= 8; nbits -= 8; } };
  let size = minCode + 1; let next = eoi + 1; let dict = new Map();
  put(clear, size);
  let prefix = indices[0];
  for (let i = 1; i < indices.length; i++) {
    const c = indices[i]; const key = (prefix << 8) | c; const hit = dict.get(key);
    if (hit !== undefined) { prefix = hit; continue; }
    put(prefix, size);
    if (next < 4096) { dict.set(key, next++); if (next - 1 === (1 << size) && size < 12) size++; }
    else { put(clear, size); dict = new Map(); size = minCode + 1; next = eoi + 1; }
    prefix = c;
  }
  put(prefix, size); put(eoi, size);
  if (nbits > 0) bytes.push(cur & 255);
  return Buffer.from(bytes);
}

function encodeGif(w, h, pal, frames) {
  const parts = [];
  const hdr = Buffer.alloc(13); hdr.write('GIF89a', 0, 'latin1'); hdr.writeUInt16LE(w, 6); hdr.writeUInt16LE(h, 8); hdr[10] = 0xf7; // глобальная палитра 256
  parts.push(hdr, Buffer.from(pal.flat()));
  parts.push(Buffer.from([0x21, 0xff, 0x0b, ...Buffer.from('NETSCAPE2.0', 'latin1'), 0x03, 0x01, 0, 0, 0])); // бесконечный цикл
  for (const f of frames) {
    parts.push(Buffer.from([0x21, 0xf9, 0x04, 0x04, f.delay & 255, f.delay >> 8, 0, 0]));
    const d = Buffer.alloc(10); d[0] = 0x2c; d.writeUInt16LE(w, 5); d.writeUInt16LE(h, 7); parts.push(d, Buffer.from([8]));
    const data = lzw(f.indices, 8);
    for (let i = 0; i < data.length; i += 255) { const c = data.subarray(i, i + 255); parts.push(Buffer.from([c.length]), c); }
    parts.push(Buffer.from([0]));
  }
  parts.push(Buffer.from([0x3b]));
  return Buffer.concat(parts);
}

// ---- сценарий
async function main() {
  fs.rmSync(OUT, { recursive: true, force: true }); fs.mkdirSync(FRAMES, { recursive: true });
  const dataDir = path.join(OUT, 'data'); // не создаём: демо требует пустой или отсутствующий каталог
  const base = `http://127.0.0.1:${PORT}`;
  const env = { ...process.env, GW_DEMO: '1', GW_DATA_DIR: dataDir, GW_PORT: String(PORT), GW_PUBLIC_URL: base, GW_VAULT: 'file', GW_LANG: 'en', GW_LOG_LEVEL: 'warn', GW_TZ: 'UTC' };
  for (const k of Object.keys(env)) if (/^(AWS_|GW_SSM_|GW_VAULT_PREFIX|GW_PROD_HOSTS)/.test(k)) delete env[k];
  const srv = spawn(process.execPath, ['bin/gateway.js', 'start'], { cwd: ROOT, env, stdio: ['ignore', 'ignore', 'pipe'] });
  srv.stderr.on('data', (d) => fs.appendFileSync(path.join(OUT, 'server.log'), d));
  let chrome;
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) { await sleep(250); up = await fetch(base + '/healthz').then((r) => r.ok).catch(() => false); }
    if (!up) throw new Error('server did not start (see out/demo-gif/server.log)');
    chrome = await startChrome();
    const { jar, web } = client(base);
    await web('GET', '/login'); // автовход демо-владельца
    const csrfOf = (h) => h.match(/name="_csrf" value="([^"]+)"/)?.[1];
    const post = async (p, form, from) => web('POST', p, { _csrf: csrfOf((await web('GET', from)).text), ...form });
    const f = (n) => path.join(FRAMES, `${n}.png`);

    // агент (токен нужен только скрипту и на кадры не попадает)
    const created = await post('/agents', { name: 'research-bot' }, '/agents');
    const token = created.text.match(/gwa_[A-Za-z0-9_-]+/)?.[0];
    if (!token) throw new Error('agent token not found');
    const api = (m, p, body) => fetch(base + p, { method: m, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });

    // 1. агент просит доступ
    const reason = 'Export last week deals for the report';
    const g = await api('POST', '/v1/grants', { provider: 'demo', ttl: 900, calls: 20, reason });
    const gj = await g.json();
    if (!gj.request_id) throw new Error('no request: ' + JSON.stringify(gj));
    await chrome.terminal(terminalHtml('Agent: research-bot', [
      { t: 'cmd', s: 'curl -X POST https://gw.example.com/v1/grants -H "Authorization: Bearer $AGENT_TOKEN" \\\n  -d \'{"provider":"demo","ttl":900,"calls":20,\n       "reason":"' + reason + '"}\'' },
      { t: 'out', s: '202 Accepted' },
      { t: 'out', s: JSON.stringify({ status: 'pending', request_id: gj.request_id, poll_after: 5 }, null, 2) },
      { t: 'note', s: 'The agent waits for the owner. It has no key and no pass yet.' },
    ]), f('1-agent-asks'), [1, 'The agent asks for access: 15 minutes, 20 calls, with a reason']);

    // 2. владелец видит заявку на сайте
    await chrome.open(base + '/', [...jar], f('2-owner-sees'), [2, 'You see the request on the site: who, what, how long, why']);

    // 3. одобрение кнопкой
    await chrome.act(`(() => { const f = [...document.forms].find((x) => /\\/requests\\/[^/]+\\/approve$/.test(x.getAttribute('action') || '')); if (!f) throw new Error('no approve form'); f.requestSubmit ? f.requestSubmit() : f.submit(); })()`, f('3-approved'), [3, 'You approve it with one click. The pass is limited by time and calls']);

    // 4. агент получает пропуск и вызывает сервис
    const pj = await (await api('GET', `/v1/grants/${gj.request_id}`)).json();
    if (!pj.token) throw new Error('no pass: ' + JSON.stringify(pj));
    const call = await fetch(base + '/v1/proxy/demo/deals', { headers: { authorization: `Bearer ${pj.token}` } });
    const cj = await call.json();
    const deals = (cj.result || []).slice(0, 3).map((d) => `  { "ID": "${d.ID}", "TITLE": "${d.TITLE}", "STAGE_ID": "${d.STAGE_ID}" }`).join(',\n');
    await chrome.terminal(terminalHtml('Agent: research-bot', [
      { t: 'cmd', s: 'curl https://gw.example.com/v1/grants/<request_id>' },
      { t: 'out', s: '{ "status": "approved", "token": "gwt_...", "max_calls": 20 }' },
      { t: 'cmd', s: 'curl https://gw.example.com/v1/proxy/demo/deals -H "Authorization: Bearer gwt_..."' },
      { t: 'out', s: `${call.status} OK\n{ "result": [\n${deals},\n  ...\n] }` },
      { t: 'note', s: 'The gateway added the key itself. The agent never saw it.' },
    ]), f('4-call-passes'), [4, 'The call goes through the gateway. The agent never sees your key']);

    // 5. аудит
    await chrome.open(base + '/stats', [...jar], f('5-activity'), [5, 'Every request, approval and call is counted and kept in the audit log']);

    // GIF
    const files = fs.readdirSync(FRAMES).filter((n) => n.endsWith('.png')).sort();
    const images = files.map((n) => decodePng(fs.readFileSync(path.join(FRAMES, n))));
    const pal = buildPalette(images);
    const frames = images.map((im, i) => ({ indices: indexImage(im, pal), delay: i === images.length - 1 ? LAST_DELAY_CS : DELAY_CS }));
    const gif = encodeGif(W, H, pal, frames);
    fs.mkdirSync(path.join(ROOT, 'assets'), { recursive: true });
    fs.writeFileSync(path.join(ROOT, 'assets', 'demo.gif'), gif);
    console.log(`assets/demo.gif: ${files.length} frames, ${(gif.length / 1024).toFixed(0)} KiB`);
  } finally {
    chrome?.close(); srv.kill();
  }
}

await main().catch((e) => { console.error('FAIL', e.message); process.exitCode = 1; });
console.log('DONE');
