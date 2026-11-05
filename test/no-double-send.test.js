// Находка аудита №15: редирект без сессии не должен писать в журнал «Cannot write headers after they are sent».
// Причина была в `return;` после reply.redirect в async-обработчике: Fastify отправлял ответ второй раз.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const cleanup = [];
after(async () => { for (const f of cleanup.reverse()) { try { await f(); } catch { /* уборка */ } } });

async function start(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-send-'));
  cleanup.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  const logs = [];
  const app = await buildApp({
    dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'info', logStream: { write: (s) => logs.push(String(s)) }, ...extra,
  });
  await app.start();
  cleanup.push(() => app.stop());
  return { app, logs, base: `http://127.0.0.1:${app.fastify.server.address().port}` };
}

const doubleSends = (logs) => logs.filter((l) => l.includes('Cannot write headers') || (l.includes('"level":50') && l.includes('unhandled')));

// маршруты обоих режимов: закрытые страницы и формы, у всех редирект на вход
const GETS = ['/', '/keys', '/keys/new', '/keys/new/demo', '/keys/x', '/agents', '/stats', '/audit', '/requests/x', '/requests/x/approve-confirm', '/settings', '/welcome'];

test('без сессии: редирект на вход без второй отправки ответа и без ошибки в журнале', async () => {
  const { app, logs, base } = await start();
  app.repo.setSetupDone(); // иначе свежая установка уводит на мастер раньше проверки владельца
  for (const p of GETS) {
    const r = await fetch(base + p, { redirect: 'manual' });
    await r.text();
    assert.ok(r.status === 302 || r.status === 404 || r.status === 200, `${p}: ${r.status}`);
  }
  await new Promise((resolve) => { setTimeout(resolve, 100); });
  assert.deepEqual(doubleSends(logs), []);
});

test('демо без сессии: то же, что на обычной установке', async () => {
  const { logs, base } = await start({ demo: true, dataDirExplicit: true, prodHosts: [], env: {} });
  for (const p of GETS) {
    const r = await fetch(base + p, { redirect: 'manual', headers: { 'x-forwarded-for': '10.90.0.1' } });
    await r.text();
  }
  await new Promise((resolve) => { setTimeout(resolve, 100); });
  assert.deepEqual(doubleSends(logs), []);
});
