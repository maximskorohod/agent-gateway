// Тесты слоя БД: только :memory:, без сети и AWS.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';

/** Свежая база + repo. now() — время самой базы (unixepoch), чтобы не расходиться с SQL. */
function setup() {
  const db = openDb(':memory:');
  const repo = createRepo(db);
  const now = () => db.prepare('SELECT unixepoch() AS t').get().t;
  return { db, repo, now };
}

function makeCred(over = {}) {
  return {
    id: 'c1',
    provider: 'openrouter',
    label: 'OpenRouter основной',
    kind: 'static',
    host: 'openrouter.ai',
    injection: { type: 'header', name: 'Authorization', prefix: 'Bearer ' },
    vault_param: 'cred/c1',
    mode: 'ask',
    approval: 'web_button',
    max_ttl: 3600,
    max_calls: 100,
    max_parallel: 2,
    window: null,
    expires_at: null,
    last4: 'abcd',
    ...over,
  };
}

/** Агент + credential + одобренная заявка + grant g1 (если не переопределено). */
function seed(repo, now, grantOver = {}) {
  const t = now();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1', enabled: 1 });
  repo.createCredential(makeCred());
  repo.createRequest({
    id: 'r1',
    agent_id: 'a1',
    credential_id: 'c1',
    ttl: 3600,
    calls: 10,
    reason: 'тест',
    status: 'approved',
    expires_at: t + 600,
  });
  repo.createGrant({
    id: 'g1',
    request_id: 'r1',
    agent_id: 'a1',
    credential_id: 'c1',
    expires_at: t + 3600,
    max_calls: 3,
    max_parallel: 1,
    ...grantOver,
  });
}

test('reserveCall: квота max_calls=3 → три успешных, четвёртый null', (t) => {
  const { repo, now } = setup();
  t.after(() => repo.revokeAllGrants());
  seed(repo, now, { max_calls: 3, max_parallel: 10 });

  assert.notEqual(repo.reserveCall('g1', 60), null);
  assert.notEqual(repo.reserveCall('g1', 60), null);
  assert.notEqual(repo.reserveCall('g1', 60), null);
  assert.equal(repo.reserveCall('g1', 60), null);

  const g = repo.getGrant('g1');
  assert.equal(g.calls_used, 3);
  assert.equal(g.inflight, 3);
});

test('reserveCall: параллельность max_parallel=1 → второй null до release', () => {
  const { repo, now } = setup();
  seed(repo, now, { max_calls: 100, max_parallel: 1 });

  const lease = repo.reserveCall('g1', 60);
  assert.notEqual(lease, null);
  assert.equal(repo.reserveCall('g1', 60), null);

  assert.equal(repo.releaseCall(lease), true);
  assert.notEqual(repo.reserveCall('g1', 60), null);
});

test('reserveCall: истёкший grant → null', () => {
  const { repo, now } = setup();
  seed(repo, now, { expires_at: now() - 1 });
  assert.equal(repo.reserveCall('g1', 60), null);
  assert.equal(repo.getGrant('g1').calls_used, 0);
});

test('reserveCall: отозванный grant → null', () => {
  const { repo, now } = setup();
  seed(repo, now);
  assert.equal(repo.revokeGrant('g1'), true);
  assert.equal(repo.reserveCall('g1', 60), null);
});

test('reserveCall: несуществующий grant → null', () => {
  const { repo } = setup();
  assert.equal(repo.reserveCall('нет-такого', 60), null);
});

test('releaseCall идемпотентен и не трогает чужой lease', () => {
  const { repo, now } = setup();
  seed(repo, now, { max_calls: 100, max_parallel: 5 });

  const l1 = repo.reserveCall('g1', 60);
  const l2 = repo.reserveCall('g1', 60);
  assert.equal(repo.getGrant('g1').inflight, 2);

  assert.equal(repo.releaseCall(l1), true);
  assert.equal(repo.getGrant('g1').inflight, 1);

  // Повторный release того же lease — no-op: второй lease не должен быть задет.
  assert.equal(repo.releaseCall(l1), false);
  assert.equal(repo.getGrant('g1').inflight, 1);

  assert.equal(repo.releaseCall(l2), true);
  assert.equal(repo.getGrant('g1').inflight, 0);
  assert.equal(repo.releaseCall(l2), false);
  assert.equal(repo.getGrant('g1').inflight, 0);
});

test('reapLeases возвращает inflight у просроченных lease и удаляет их', (t) => {
  const { db, repo, now } = setup();
  seed(repo, now, { max_calls: 100, max_parallel: 5 });

  const expired = repo.reserveCall('g1', 60);
  const alive = repo.reserveCall('g1', 60);
  // Делаем первый lease просроченным прямо в базе.
  db.prepare('UPDATE leases SET expires_at = unixepoch() - 5 WHERE id = ?').run(expired);
  assert.equal(repo.getGrant('g1').inflight, 2);

  assert.equal(repo.reapLeases(), 1);
  assert.equal(repo.getGrant('g1').inflight, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM leases WHERE id = ?').get(expired).n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM leases WHERE id = ?').get(alive).n, 1);

  // Повторный reap ничего не находит; release живого lease работает штатно.
  assert.equal(repo.reapLeases(), 0);
  assert.equal(repo.releaseCall(alive), true);
  assert.equal(repo.getGrant('g1').inflight, 0);
});

test('reapLeases не уводит inflight в минус', () => {
  const { db, repo, now } = setup();
  seed(repo, now, { max_calls: 100, max_parallel: 5 });
  const lease = repo.reserveCall('g1', 60);
  db.prepare('UPDATE leases SET expires_at = unixepoch() - 5 WHERE id = ?').run(lease);
  // Искусственно обнуляем inflight: reap не должен сделать его отрицательным.
  db.prepare('UPDATE grants SET inflight = 0 WHERE id = ?').run('g1');
  repo.reapLeases();
  assert.equal(repo.getGrant('g1').inflight, 0);
});

test('consumeLink одноразовая: второй вызов false', () => {
  const { repo, now } = setup();
  repo.createLink('h-open', 'open', now() + 900);
  assert.equal(repo.consumeLink('h-open', 'open'), true);
  assert.equal(repo.consumeLink('h-open', 'open'), false);
});

test('consumeLink: чужое назначение (purpose) → false', () => {
  const { repo, now } = setup();
  repo.createLink('h-setup', 'setup', now() + 900);
  assert.equal(repo.consumeLink('h-setup', 'open'), false);
  // Ссылка не сгорела из-за неверного назначения.
  assert.equal(repo.consumeLink('h-setup', 'setup'), true);
});

test('consumeLink: истёкшая ссылка → false', () => {
  const { repo, now } = setup();
  repo.createLink('h-old', 'open', now() - 1);
  assert.equal(repo.consumeLink('h-old', 'open'), false);
});

test('decideRequest меняет статус только из pending', () => {
  const { repo, now } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  repo.createCredential(makeCred());
  repo.createRequest({
    id: 'r-p',
    agent_id: 'a1',
    credential_id: 'c1',
    ttl: 600,
    calls: 5,
    expires_at: now() + 600,
  });

  assert.equal(repo.decideRequest('r-p', 'approved', 'web'), true);
  assert.equal(repo.decideRequest('r-p', 'denied', 'tg'), false);
  const r = repo.getRequest('r-p');
  assert.equal(r.status, 'approved');
  assert.equal(r.decided_via, 'web');
  assert.notEqual(r.decided_at, null);
});

test('decideRequest не трогает уже истёкшую (expired) заявку', () => {
  const { repo, now } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  repo.createCredential(makeCred());
  repo.createRequest({
    id: 'r-e',
    agent_id: 'a1',
    credential_id: 'c1',
    ttl: 600,
    calls: 5,
    expires_at: now() - 1,
  });
  assert.equal(repo.expireRequests(), 1);
  assert.equal(repo.decideRequest('r-e', 'approved', 'web'), false);
  assert.equal(repo.getRequest('r-e').status, 'expired');
});

test('decideRequest отклоняет недопустимый статус', () => {
  const { repo, now } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  repo.createCredential(makeCred());
  repo.createRequest({ id: 'r-x', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, expires_at: now() + 600 });
  assert.throws(() => repo.decideRequest('r-x', 'pending', 'web'), /invalid decision status/);
  assert.equal(repo.getRequest('r-x').status, 'pending');
});

test('expireRequests переводит просроченные pending в expired/timeout', () => {
  const { repo, now } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  repo.createCredential(makeCred());
  repo.createRequest({ id: 'r-old', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, expires_at: now() - 1 });
  repo.createRequest({ id: 'r-new', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, expires_at: now() + 600 });

  assert.equal(repo.expireRequests(), 1);
  const old = repo.getRequest('r-old');
  assert.equal(old.status, 'expired');
  assert.equal(old.decided_via, 'timeout');
  assert.equal(repo.getRequest('r-new').status, 'pending');
});

test('softDeleteCredential удаляет ключ из выборок и отзывает его grants', () => {
  const { repo, now } = setup();
  seed(repo, now);
  assert.equal(repo.listActiveGrants().length, 1);

  assert.equal(repo.softDeleteCredential('c1'), true);

  assert.equal(repo.getCredential('c1'), null);
  assert.equal(repo.listCredentials().length, 0);
  assert.notEqual(repo.getGrant('g1').revoked_at, null);
  assert.equal(repo.listActiveGrants().length, 0);
  assert.equal(repo.reserveCall('g1', 60), null);
});

test('setAgentEnabled(0) отзывает все grants агента, другие агенты не затронуты', () => {
  const { repo, now } = setup();
  seed(repo, now);
  repo.createAgent({ id: 'a2', name: 'агент-2', token_hash: 'th-a2', enabled: 1 });
  repo.createRequest({ id: 'r2', agent_id: 'a2', credential_id: 'c1', ttl: 600, calls: 5, status: 'approved', expires_at: now() + 600 });
  repo.createGrant({ id: 'g2', request_id: 'r2', agent_id: 'a2', credential_id: 'c1', expires_at: now() + 600, max_calls: 5, max_parallel: 1 });

  assert.equal(repo.setAgentEnabled('a1', 0), true);

  assert.equal(repo.getAgent('a1').enabled, 0);
  assert.notEqual(repo.getGrant('g1').revoked_at, null);
  assert.equal(repo.getGrant('g2').revoked_at, null);
});

test('audit: UPDATE и DELETE запрещены триггерами', () => {
  const { db, repo } = setup();
  repo.audit('owner', 'login', null, { ok: true });
  assert.throws(() => db.prepare('UPDATE audit SET actor = ?').run('x'), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM audit').run(), /append-only/);
  assert.equal(repo.listAudit().length, 1);
});

test('audit: meta сериализуется, undefined → null; listAudit по id DESC с before', () => {
  const { repo } = setup();
  repo.audit('owner', 'a', 'x1', { k: 1 });
  repo.audit('owner', 'b', undefined);
  repo.audit('owner', 'c', 'x3', { k: 3 });

  const rows = repo.listAudit({ limit: 10 });
  assert.deepEqual(rows.map((r) => r.action), ['c', 'b', 'a']);
  assert.deepEqual(JSON.parse(rows[0].meta_json), { k: 3 });
  assert.equal(rows[1].meta_json, null);

  const older = repo.listAudit({ limit: 10, before: rows[0].id });
  assert.deepEqual(older.map((r) => r.action), ['b', 'a']);
});

test('getSession возвращает null после истечения и живую сессию', () => {
  const { repo, now } = setup();
  repo.createSession('s-old', now() - 1, 'ua');
  repo.createSession('s-live', now() + 3600, 'ua');
  assert.equal(repo.getSession('s-old'), null);
  assert.equal(repo.getSession('s-live').id_hash, 's-live');
});

test('credentials: injection и window парсятся, *_json наружу не отдаются', () => {
  const { repo } = setup();
  const window = { days: [1, 2, 3, 4, 5], from: '09:00', to: '18:00', tz: 'Europe/Moscow' };
  repo.createCredential(makeCred({ id: 'cw', window, injection: { type: 'path', template: '/bot{secret}' }, kind: 'path' }));
  repo.createCredential(makeCred({ id: 'cn', window: null }));

  const cw = repo.getCredential('cw');
  assert.deepEqual(cw.window, window);
  assert.deepEqual(cw.injection, { type: 'path', template: '/bot{secret}' });
  assert.equal('injection_json' in cw, false);
  assert.equal('window_json' in cw, false);
  assert.equal(repo.getCredential('cn').window, null);
  assert.equal(repo.listCredentials().length, 2);
});

test('updateCredentialPolicy: частичное обновление, window и expires_at можно сбросить', () => {
  const { repo } = setup();
  repo.createCredential(makeCred({ window: { days: [1], from: '09:00', to: '10:00', tz: 'UTC' }, expires_at: 12345 }));

  assert.equal(repo.updateCredentialPolicy('c1', { mode: 'always', max_calls: 500 }), true);
  let c = repo.getCredential('c1');
  assert.equal(c.mode, 'always');
  assert.equal(c.max_calls, 500);
  assert.deepEqual(c.window, { days: [1], from: '09:00', to: '10:00', tz: 'UTC' });
  assert.equal(c.expires_at, 12345);

  repo.updateCredentialPolicy('c1', { window: null, expires_at: null });
  c = repo.getCredential('c1');
  assert.equal(c.window, null);
  assert.equal(c.expires_at, null);

  assert.equal(repo.updateCredentialPolicy('нет', { mode: 'deny' }), false);
});

test('always_until: истёкший режим «без вопросов» возвращается в ask, бессрочный и будущий не трогаются', () => {
  const { repo, now } = setup();
  const t = now();
  repo.createCredential(makeCred({ id: 'past', mode: 'always', always_until: t - 1 }));
  repo.createCredential(makeCred({ id: 'future', mode: 'always', always_until: t + 3600 }));
  repo.createCredential(makeCred({ id: 'forever', mode: 'always' }));
  repo.createCredential(makeCred({ id: 'gone', mode: 'always', always_until: t - 1 }));
  repo.softDeleteCredential('gone');

  const ended = repo.endExpiredAlways();
  assert.deepEqual(ended.map((c) => c.id), ['past']);
  assert.equal(ended[0].mode, 'ask');
  assert.equal(repo.getCredential('past').mode, 'ask');
  assert.equal(repo.getCredential('past').always_until, null);
  assert.equal(repo.getCredential('future').mode, 'always');
  assert.equal(repo.getCredential('forever').always_until, null);
  assert.deepEqual(repo.endExpiredAlways(), [], 'повторный вызов ничего не находит');

  repo.updateCredentialPolicy('future', { always_until: null });
  assert.equal(repo.getCredential('future').always_until, null);
});

test('backup codes: replace заменяет набор, useBackupCode одноразовый', () => {
  const { db, repo } = setup();
  repo.replaceBackupCodes(['h1', 'h2']);
  assert.equal(repo.useBackupCode('h1'), true);
  assert.equal(repo.useBackupCode('h1'), false);

  repo.replaceBackupCodes(['h3']);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM backup_codes').get().n, 1);
  assert.equal(repo.useBackupCode('h2'), false);
  assert.equal(repo.useBackupCode('h3'), true);
});

test('owner: записи создают строку id=1, getOwner до этого null', () => {
  const { repo } = setup();
  assert.equal(repo.getOwner(), null);
  repo.setPasswordHash('hash');
  repo.setTotp('enc', true);
  repo.setTg(42, 'param');
  repo.setSetupDone();
  const o = repo.getOwner();
  assert.equal(o.id, 1);
  assert.equal(o.password_hash, 'hash');
  assert.equal(o.totp_enabled, 1);
  assert.equal(o.tg_chat_id, 42);
  assert.equal(o.setup_done, 1);
});

test('listPending: только pending и не истёкшие, с именами агента и ключа', () => {
  const { repo, now } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  repo.createCredential(makeCred());
  repo.createRequest({ id: 'p-ok', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, expires_at: now() + 600 });
  repo.createRequest({ id: 'p-old', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, expires_at: now() - 1 });

  const list = repo.listPending();
  assert.deepEqual(list.map((r) => r.id), ['p-ok']);
  assert.equal(list[0].agent_name, 'агент-1');
  assert.equal(list[0].credential_label, 'OpenRouter основной');
  assert.equal(list[0].provider, 'openrouter');
});

test('getAgent/listAgents не отдают token_hash; getAgentByTokenHash находит агента', () => {
  const { repo } = setup();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1' });
  assert.equal(repo.getAgentByTokenHash('th-a1').id, 'a1');
  assert.equal('token_hash' in repo.getAgent('a1'), false);
  assert.equal('token_hash' in repo.listAgents()[0], false);
  assert.equal(repo.getAgentByTokenHash('нет'), null);
});

test('reserveCall: revokeAllGrants отзывает все незакрытые grants', () => {
  const { repo, now } = setup();
  seed(repo, now);
  assert.equal(repo.revokeAllGrants(), 1);
  assert.equal(repo.reserveCall('g1', 60), null);
  assert.equal(repo.listActiveGrants().length, 0);
});

test('привязка ключей: по умолчанию все, выбранные, отзыв пропусков к отвязанным', () => {
  const { repo, now } = setup();
  seed(repo, now);
  repo.createCredential(makeCred({ id: 'c2', vault_param: 'cred/c2' }));
  assert.equal(repo.getAgent('a1').all_credentials, 1);
  assert.equal(repo.agentCanUse('a1', 'c1'), true);
  assert.equal(repo.agentCanUse('a1', 'c2'), true);

  // Только c2: пропуск g1 к c1 отзывается, несуществующий id молча пропускается
  assert.equal(repo.setAgentCredentials('a1', { all: false, ids: ['c2', 'нет', 'c2'] }), true);
  assert.deepEqual(repo.listAgentCredentials('a1'), ['c2']);
  assert.equal(repo.agentCanUse('a1', 'c1'), false);
  assert.equal(repo.agentCanUse('a1', 'c2'), true);
  assert.ok(repo.getGrant('g1').revoked_at);

  // Снова «все»: список сохраняется, доступ ко всем
  repo.setAgentCredentials('a1', { all: true, ids: [] });
  assert.equal(repo.agentCanUse('a1', 'c1'), true);
  assert.equal(repo.setAgentCredentials('нет', { all: true }), false);
  assert.equal(repo.agentCanUse('нет', 'c1'), false);

  // Удаление агента удаляет привязки (ON DELETE CASCADE), если нет истории
  repo.createAgent({ id: 'a2', name: 'агент-2', token_hash: 'th-a2', all_credentials: 0 });
  repo.setAgentCredentials('a2', { all: false, ids: ['c1'] });
  assert.equal(repo.deleteAgent('a2'), true);
  assert.deepEqual(repo.listAgentCredentials('a2'), []);
});

test('миграция: у старой базы без all_credentials агенты получают все ключи', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-mig-'));
  const file = path.join(dir, 'old.db');
  const raw = new Database(file);
  raw.exec("CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_seen_at INTEGER); INSERT INTO agents (id, name, token_hash) VALUES ('old', 'старый', 'th');");
  raw.close();
  const db = openDb(file);
  const repo = createRepo(db);
  assert.equal(repo.getAgent('old').all_credentials, 1);
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('статистика: вызовы и заявки по агенту и ключу, журнал вызовов', () => {
  const { repo, now } = setup();
  seed(repo, now);
  const call = (status, ms) => repo.audit('agent:a1', 'proxy.call', 'POST openrouter/v1/chat', { grant: 'g1', agent: 'a1', credential: 'c1', provider: 'openrouter', status, ms });
  call(200, 120); call(200, 80); call(500, 40); call(0, 10002);
  repo.audit('owner', 'agent.create', 'a1', null);
  const [row] = repo.callStats(1);
  assert.deepEqual({ ...row, last_at: undefined }, { agent_id: 'a1', credential_id: 'c1', calls: 4, errors: 2, last_at: undefined });
  const [req] = repo.requestStats(1);
  assert.equal(req.total, 1); assert.equal(req.approved, 1); assert.equal(req.denied, 0);
  const recent = repo.listCalls({ days: 1, limit: 3 });
  assert.equal(recent.length, 3);
  assert.equal(recent[0].status, 0); assert.equal(recent[0].ms, 10002); assert.equal(recent[0].target, 'POST openrouter/v1/chat');
  assert.equal(repo.listCalls({ days: 1, agentId: 'другой' }).length, 0);
});

test('approveRequest (П-10): одобрение и пропуск вместе, второй раз и после срока — нет', () => {
  const { db, repo, now } = setup();
  const t = now();
  repo.createAgent({ id: 'a1', name: 'агент-1', token_hash: 'th-a1', enabled: 1 });
  repo.createCredential(makeCred());
  repo.createRequest({ id: 'r1', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, reason: '', expires_at: t + 600 });
  const g = (id) => ({ id, agent_id: 'a1', credential_id: 'c1', expires_at: t + 600, max_calls: 5, max_parallel: 1 });
  assert.equal(repo.approveRequest('r1', 'web', g('g1')), true);
  assert.equal(repo.getRequest('r1').status, 'approved');
  assert.equal(repo.approveRequest('r1', 'web', g('g2')), false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM grants WHERE request_id = ?').get('r1').n, 1);
  // уникальный индекс: второй пропуск на ту же заявку не записывается даже напрямую
  assert.throws(() => repo.createGrant({ ...g('g3'), request_id: 'r1' }));
  repo.createRequest({ id: 'r2', agent_id: 'a1', credential_id: 'c1', ttl: 600, calls: 5, reason: '', expires_at: t - 1 });
  assert.equal(repo.approveRequest('r2', 'web', g('g4')), false, 'истёкшая заявка');
  assert.equal(repo.getGrant('g4'), null);
});
