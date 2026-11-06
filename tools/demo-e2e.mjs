// Сквозная проверка демо-экземпляра (ТЗ 1.0.2, пакет 9): node tools/demo-e2e.mjs <base-url>
// Проходит сценарий главной страницы как посетитель и проверяет защиты демо. Без зависимостей.
// Токены и пропуска не печатаются: команды и ответы не выводятся, только OK/BAD по шагам.
// Работает и с http://127.0.0.1, и с https-адресом: Origin берётся из переданного адреса.
const base = process.argv[2] || '';
if (!/^https?:\/\/[^\s/]+$/.test(base)) {
  console.error('usage: node tools/demo-e2e.mjs <base-url>');
  process.exit(2);
}
const ORIGIN = new URL(base).origin;

const jar = new Map();
function storeCookies(res) {
  for (const s of res.headers.getSetCookie?.() || []) {
    const [kv, ...attrs] = s.split(';');
    const i = kv.indexOf('=');
    if (i < 1) continue;
    const name = kv.slice(0, i).trim();
    const value = kv.slice(i + 1);
    if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(name);
    else jar.set(name, value);
  }
}
const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

const csrfFrom = (html) => html.match(/name="_csrf" value="([^"]+)"/)?.[1] ?? '';

async function get(path) {
  const res = await fetch(base + path, { headers: { cookie: cookie() }, redirect: 'manual' });
  storeCookies(res);
  return res;
}
async function post(path, fields, { anonymous = false } = {}) {
  const body = new URLSearchParams(fields).toString();
  const res = await fetch(base + path, {
    method: 'POST',
    headers: anonymous ? { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN } : { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    body,
    redirect: 'manual',
  });
  storeCookies(res);
  return res;
}

const results = [];
let failed = false;
async function step(name, fn) {
  try {
    const note = await fn();
    results.push([name, true, '']);
    if (note) results[results.length - 1][2] = String(note);
  } catch (e) {
    failed = true;
    results.push([name, false, String(e.message || e).replace(/gwt_[A-Za-z0-9_.-]+|gwa_[A-Za-z0-9_.-]+/g, '<token>')]);
  }
}

const expect = (cond, message) => { if (!cond) throw new Error(message); };

await step('1. /healthz отвечает 200', async () => {
  const res = await get('/healthz');
  expect(res.status === 200, `status ${res.status}`);
});

await step('2. вход через /login', async () => {
  const res = await get('/login');
  expect(res.status === 302 && String(res.headers.get('location')).startsWith('/'), `status ${res.status}`);
});

let homeCsrf = '';
await step('3. на главной шаг 1 (кнопка Simulate, сценарий с начала)', async () => {
  const res = await get('/');
  expect(res.status === 200, `status ${res.status}`);
  const html = await res.text();
  homeCsrf = csrfFrom(html);
  expect(homeCsrf.length > 10, 'нет CSRF-токена в форме');
  expect(html.includes('action="/demo/simulate"'), 'нет формы /demo/simulate');
  expect(!html.includes('id="demo-curl"'), 'шаг 3 показан раньше одобрения');
});

await step('4. Simulate: заявка создана', async () => {
  const res = await post('/demo/simulate', { _csrf: homeCsrf });
  expect(res.status === 302, `status ${res.status}`);
});

let requestId = '';
let requestCsrf = '';
await step('5. на главной шаг 2 со ссылкой на заявку', async () => {
  const res = await get('/');
  expect(res.status === 200, `status ${res.status}`);
  const html = await res.text();
  requestId = html.match(/href="\/requests\/([A-Za-z0-9_-]+)"/)?.[1] ?? '';
  expect(requestId, 'ссылки на заявку нет');
  requestCsrf = csrfFrom(html);
});

await step('6. Approve: заявка одобрена', async () => {
  const page = await get(`/requests/${requestId}`);
  expect(page.status === 200, `экран заявки: status ${page.status}`);
  const form = await page.text();
  const csrf = csrfFrom(form) || requestCsrf;
  const res = await post(`/requests/${requestId}/approve`, { _csrf: csrf });
  expect(res.status === 302, `status ${res.status}`);
});

let curlCommand = '';
await step('7. на главной шаг 3 с командой curl (команда не печатается)', async () => {
  const res = await get('/');
  expect(res.status === 200, `status ${res.status}`);
  const html = await res.text();
  curlCommand = (html.match(/<code id="demo-curl">([\s\S]*?)<\/code>/)?.[1] ?? '').replace(/&quot;/g, '"').trim();
  expect(curlCommand.startsWith('curl'), 'команды curl нет');
  expect(/Bearer [A-Za-z0-9_.-]+/.test(curlCommand), 'в команде нет пропуска');
});

await step('8. вызов /deals пропуском из команды: 200 и непустой result', async () => {
  const url = curlCommand.match(/https?:\/\/\S+/)?.[0] ?? '';
  expect(url, 'в команде нет адреса');
  const pass = curlCommand.match(/Bearer ([A-Za-z0-9_.-]+)/)?.[1] ?? '';
  expect(pass, 'в команде нет пропуска');
  // Команда содержит GW_PUBLIC_URL; вызов идёт на проверяемый адрес, чтобы через туннель не попасть в другой экземпляр.
  const target = new URL(url);
  const res = await fetch(`${base}${target.pathname}${target.search}`, { headers: { authorization: `Bearer ${pass}` } });
  expect(res.status === 200, `status ${res.status}`);
  const body = await res.json();
  expect(Array.isArray(body.result) && body.result.length > 0, 'result пустой');
});

await step('9. /stats содержит вызов demo/deals', async () => {
  const res = await get('/stats');
  expect(res.status === 200, `status ${res.status}`);
  const html = await res.text();
  expect(html.includes('demo/deals'), 'demo/deals на странице нет');
});

await step('10. посевной ключ защищён: policy с mode=deny даёт 400', async () => {
  const home = await get('/');
  const csrf = csrfFrom(await home.text()) || homeCsrf;
  const res = await post('/keys/demo/policy', { _csrf: csrf, label: 'x', mode: 'deny', approval: 'web_button', max_ttl: '3600', max_calls: '10', max_parallel: '2' });
  expect(res.status === 400, `status ${res.status}`);
});

await step('11. /settings закрыт в демо: 404', async () => {
  const res = await get('/settings');
  expect(res.status === 404, `status ${res.status}`);
});

await step('12. анонимный POST /agents с неверным CSRF даёт 403', async () => {
  const res = await post('/agents', { _csrf: 'x', name: 'e2e' }, { anonymous: true });
  expect(res.status === 403, `status ${res.status}`);
});

// ---- итог: каждая строка OK или BAD, ни одного токена в выводе ----
const okCount = results.filter(([, ok]) => ok).length;
for (const [name, ok, note] of results) {
  console.log(`${ok ? 'OK' : `BAD${note ? ` (${note})` : ''}`} ${name}${ok && note ? ` (${note})` : ''}`);
}
console.log(`итог: ${okCount}/${results.length} OK`);
process.exit(failed ? 1 : 0);
