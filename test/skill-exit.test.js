// Скилл skills/agentkeygate/scripts/gw.sh: коды выхода при закрытии метода фильтром владельца (п. 7.3).
// Mock-шлюз на localhost; нужны bash, curl и jq — нет их, тест пропускается.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'skills', 'agentkeygate', 'scripts', 'gw.sh').replace(/\\/g, '/');
const run = (cmd, args, env = {}) => new Promise((resolve) => {
  execFile(cmd, args, { env: { ...process.env, ...env }, timeout: 20000, windowsHide: true }, (err, stdout, stderr) => resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout, stderr }));
});

let server, url, tmp, tools = false;
const hits = [];

before(async () => {
  // gw.sh отдаёт токен curl через -K <(…): curl для Windows такой конфиг не читает, тогда тест пропускается (CI на Linux его гоняет)
  const probe = await Promise.all([run('bash', ['-c', "command -v jq >/dev/null && curl -sS -K <(printf 'silent\\n') --version >/dev/null 2>&1 && echo yes"]), run('bash', ['-c', `test -r "${SCRIPT}" && echo yes`])]);
  tools = probe.every((p) => p.code === 0 && p.stdout.trim() === 'yes');
  server = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    res.setHeader('content-type', 'application/json');
    const send = (code, obj) => { res.statusCode = code; res.end(JSON.stringify(obj)); };
    if (req.url.includes('crm.contact.get')) return send(403, { error: 'method_not_allowed', allowed: ['crm.deal.list'] });
    if (req.url.includes('crm.deal.add')) return send(403, { error: 'write_not_allowed', allowed: ['crm.deal.list'] });
    if (req.url.includes('forbidden-other')) return send(403, { error: 'something_else' });
    if (req.url.includes('crm.deal.list')) return send(200, { result: [{ ID: '1' }] });
    send(404, { error: 'not_found' });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${server.address().port}`;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-skill-'));
  // готовый пропуск: gw.sh читает его из ${XDG_RUNTIME_DIR}/agentkeygate/ (значение не настоящее, собрано в рантайме)
  fs.mkdirSync(path.join(tmp, 'agentkeygate'), { mode: 0o700 });
  fs.writeFileSync(path.join(tmp, 'agentkeygate', 'bitrix24.token'), `${['gw', 't_'].join('')}${'0'.repeat(24)}\n`);
});
after(() => { server.close(); server.closeAllConnections?.(); fs.rmSync(tmp, { recursive: true, force: true }); });

const gw = (...args) => run('bash', [SCRIPT, ...args], { AGENTKEYGATE_URL: url, AGENTKEYGATE_TOKEN: `${['gw', 'a_'].join('')}x`, XDG_RUNTIME_DIR: tmp.replace(/\\/g, '/') });

test('gw.sh call: method_not_allowed → код 3, write_not_allowed → код 4, тело шлюза остаётся в stdout', async (t) => {
  if (!tools) return t.skip('нет bash, curl или jq');
  let r = await gw('call', 'bitrix24', 'GET', 'crm.contact.get.json');
  assert.equal(r.code, 3);
  assert.match(r.stderr, /closed by the owner's filter, do not ask to bypass it/);
  assert.match(r.stdout, /"allowed":\["crm.deal.list"\]/);
  r = await gw('call', 'bitrix24', 'POST', 'crm.deal.add.json', '{}');
  assert.equal(r.code, 4);
  assert.match(r.stderr, /do not ask to bypass it/);
});

test('gw.sh call: прочие ответы не получают кодов 3 и 4', async (t) => {
  if (!tools) return t.skip('нет bash, curl или jq');
  let r = await gw('call', 'bitrix24', 'GET', 'crm.deal.list.json');
  assert.equal(r.code, 0);
  assert.match(r.stdout, /"ID":"1"/);
  r = await gw('call', 'bitrix24', 'GET', 'forbidden-other');
  assert.equal(r.code, 1, '403 с другой причиной — общая ошибка');
  r = await gw('call', 'bitrix24', 'GET', 'missing');
  assert.equal(r.code, 1);
  r = await gw('call');
  assert.equal(r.code, 2, 'неверный вызов');
});

test('gw.sh call (ревью M5): filter[ID]= и @ в запросе проходят; .. @ :// в пути отклоняются; код curl 3 и 7 различаются', async (t) => {
  if (!tools) return t.skip('нет bash, curl или jq');
  let r = await gw('call', 'bitrix24', 'GET', 'crm.deal.list?filter[ID]=1&email=a@b.c&next=http://x/..');
  assert.equal(r.code, 0, r.stderr);
  assert.ok(hits.includes('GET /v1/proxy/bitrix24/crm.deal.list?filter[ID]=1&email=a@b.c&next=http://x/..'), 'запрос дошёл как есть, скобки не разобраны curl');
  for (const bad of ['a/../b', 'user@host/x', 'http://evil/x']) {
    r = await gw('call', 'bitrix24', 'GET', bad);
    assert.equal(r.code, 1, bad);
    assert.match(r.stderr, /invalid path/, bad);
  }
  // код 3: адрес с пробелом curl считает искажённым
  r = await gw('call', 'bitrix24', 'GET', 'crm.deal.list?q=a b');
  assert.equal(r.code, 1);
  assert.match(r.stderr, /malformed URL/);
  // код 7: на порту никто не слушает
  const dead = http.createServer();
  await new Promise((res) => dead.listen(0, '127.0.0.1', res));
  const deadUrl = `http://127.0.0.1:${dead.address().port}`;
  await new Promise((res) => dead.close(res));
  r = await run('bash', [SCRIPT, 'call', 'bitrix24', 'GET', 'crm.deal.list'], { AGENTKEYGATE_URL: deadUrl, AGENTKEYGATE_TOKEN: `${['gw', 'a_'].join('')}x`, XDG_RUNTIME_DIR: tmp.replace(/\\/g, '/') });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /cannot reach/);
});

test('gw.sh: curl вызывается с -g (ревью M5)', () => {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  assert.match(src, /curl -sS -g /);
});

test('gw.sh: пропуск лежит в приватном каталоге 0700, а не в предсказуемом /tmp (ревью 9.1)', () => {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  assert.match(src, /mkdir -p -m 700/);
  assert.match(src, /umask 077/);
  assert.ok(!/\$\{TMPDIR:-\/tmp\}/.test(src.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')), 'пропуск не должен лежать в /tmp');
});

test('gw.sh: bash -n (синтаксис)', async (t) => {
  const r = await run('bash', ['-n', SCRIPT]);
  if (r.code === -1) return t.skip('нет bash');
  assert.equal(r.code, 0, r.stderr);
});
