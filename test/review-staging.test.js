// Регрессии по ревью живого staging (04.11, out/review-staging/REPORT.md): R-1, R-2 (Caddy), R-3 (413 на большой JSON),
// R-5 (cookie формы только там, где есть формы), R-11 (backup.sh исполняемый в git). Без сети: сервер на 127.0.0.1.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
let app, base;

before(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-rst-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
  });
  await app.start();
  base = `http://127.0.0.1:${app.fastify.server.address().port}`;
});
after(async () => { await app.stop(); });

/** Сырой POST по сокету: видно, ответил ли сервер или оборвал соединение. */
function rawPost(p, body) {
  return new Promise((ok) => {
    const u = new URL(base + p);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      let data = ''; res.on('data', (c) => { data += c; }); res.on('end', () => ok({ status: res.statusCode, body: data }));
    });
    req.on('error', (e) => ok({ status: 0, error: e.code }));
    req.end(body);
  });
}

test('R-3: JSON больше 64 KiB на /v1/grants — ответ 413 body_too_large, соединение не рвётся', async () => {
  const big = JSON.stringify({ provider: 'hubspot', reason: 'x'.repeat(100 * 1024) });
  const r = await rawPost('/v1/grants', big);
  assert.equal(r.status, 413, `ответ вместо обрыва (${r.error || r.status})`);
  assert.deepEqual(JSON.parse(r.body), { error: 'body_too_large' });
  // небольшой JSON по-прежнему разбирается (без токена — 401, а не 400/413)
  const small = await rawPost('/v1/grants', JSON.stringify({ provider: 'hubspot' }));
  assert.equal(small.status, 401);
});

test('R-5: cookie формы не ставится на статике, /healthz, /v1 и /mcp; на /login ставится', async () => {
  for (const p of ['/public/app.js', '/healthz', '/v1/grants/x', '/mcp']) {
    const r = await fetch(base + p, { redirect: 'manual' });
    assert.equal(r.headers.getSetCookie().filter((c) => /gw_pre=/.test(c)).length, 0, `Set-Cookie на ${p}`);
  }
  const login = await fetch(base + '/login', { redirect: 'manual' });
  assert.ok(login.headers.getSetCookie().some((c) => /gw_pre=/.test(c)), 'cookie формы на /login');
  assert.match(await login.text(), /name="_csrf" value="[^"]+"/);
});

// Активные строки конфига Caddy после setup.sh без --behind-cloudflare: строки "#cf " удаляются.
const activeCaddy = (text) => text.split('\n').filter((l) => !/^\s*#cf /.test(l) && !/^\s*#/.test(l)).join('\n');

for (const file of ['deploy/Caddyfile', 'Caddyfile.docker']) {
  test(`R-2: ${file} без HTTP/3 (protocols h1 h2 в глобальном servers)`, () => {
    const a = activeCaddy(read(file));
    assert.match(a, /^\{\n\s*servers \{[\s\S]*?\n\s*protocols h1 h2\n/, 'первый блок — глобальные опции с protocols h1 h2');
  });
  test(`R-1: ${file}: служебный журнал Caddy с фильтрами query и заголовков`, () => {
    const a = activeCaddy(read(file));
    const m = a.match(/log default \{([\s\S]*?)\n\t\}/);
    assert.ok(m, 'есть log default в глобальных опциях');
    assert.match(m[1], /request>uri regexp "\\\?\.\*\$" ""/);
    assert.match(m[1], /request>headers delete/);
  });
}

test('R-1/R-2: deploy/Caddyfile — скобки сбалансированы в обоих режимах setup.sh', () => {
  const text = read('deploy/Caddyfile');
  const nocf = text.split('\n').filter((l) => !/^\s*#cf /.test(l));
  const cf = text.split('\n').map((l) => l.replace(/^(\s*)#cf /, '$1')).filter((l) => !/#nocf$/.test(l));
  for (const lines of [nocf, cf]) {
    const code = lines.filter((l) => !/^\s*#/.test(l)).join('\n').replace(/"[^"]*"/g, '');
    assert.equal((code.match(/\{/g) || []).length - (code.match(/\{\$DOMAIN\}/g) || []).length, (code.match(/\}/g) || []).length - (code.match(/\{\$DOMAIN\}/g) || []).length);
  }
  assert.match(cf.join('\n'), /servers \{\n[^\n]*\n\s*protocols h1 h2\n\s*trusted_proxies static/, 'за Cloudflare trusted_proxies в том же блоке servers');
});

const hasGit = spawnSync('git', ['--version']).status === 0;
test('R-11: scripts/backup.sh исполняемый в индексе git (setup.sh делает 0755, иначе дрейф git status)', { skip: !hasGit && 'git не найден' }, () => {
  const r = spawnSync('git', ['ls-files', '-s', 'scripts/backup.sh'], { cwd: root, encoding: 'utf8' });
  if (!r.stdout.trim()) return; // не git-checkout (архив)
  assert.match(r.stdout, /^100755 /);
});
