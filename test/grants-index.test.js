// Находка аудита I-11: дубликаты пропусков в старой базе не должны молча снимать защиту «один пропуск на заявку».
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');
const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-idx-')); dirs.push(d); return d; };

/** Старая база: индекса нет, на одну заявку два пропуска. */
function oldDbWithDuplicates(file) {
  openDb(file).close();
  const raw = new Database(file);
  raw.pragma('foreign_keys = OFF');
  raw.exec('DROP INDEX grants_request');
  const ins = raw.prepare("INSERT INTO grants (id, request_id, agent_id, credential_id, expires_at, max_calls, max_parallel) VALUES (?, 'r1', 'a1', 'c1', 1, 1, 1)");
  ins.run('g1');
  ins.run('g2');
  raw.close();
}

test('чистая база: индекс есть', () => {
  const db = openDb(path.join(tmp(), 'gw.db'));
  assert.equal(createRepo(db).hasGrantsRequestIndex(), true);
  db.close();
});

test('дубликаты: база открывается, индекса нет, repo это видит', () => {
  const file = path.join(tmp(), 'gw.db');
  oldDbWithDuplicates(file);
  const db = openDb(file);
  assert.equal(createRepo(db).hasGrantsRequestIndex(), false);
  db.close();
});

test('дубликаты: шлюз запускается и пишет ошибку в журнал', async () => {
  const dir = tmp();
  oldDbWithDuplicates(path.join(dir, 'gw.db'));
  const logs = [];
  const app = await buildApp({
    dataDir: dir, dbPath: path.join(dir, 'gw.db'), vaultFile: path.join(dir, 'vault.json'), masterKeyFile: path.join(dir, 'master.key'),
    lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'info', logStream: { write: (s) => logs.push(String(s)) },
  });
  await app.stop?.();
  assert.ok(logs.some((l) => l.includes('"level":50') && l.includes('grants_request index missing')));
});
