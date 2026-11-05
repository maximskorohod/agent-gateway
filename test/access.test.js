// core/access.js (П-15): авторизация вызова и выбор ключа. Сеть не нужна.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { loadCatalog } from '../src/catalog.js';
import { createGrantService } from '../src/core/grants.js';
import { createRequestService } from '../src/core/requests.js';
import { createAccess, authAgent, sha256hex } from '../src/core/access.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = loadCatalog(path.join(root, 'providers.yaml'));
const nowSec = () => Math.floor(Date.now() / 1000);
const silent = { warn() {}, error() {}, info() {}, debug() {} };

function setup() {
  const db = openDb(':memory:');
  const repo = createRepo(db);
  const grants = createGrantService({ repo, signingKey: crypto.randomBytes(32), logger: silent });
  const notify = { grantAuto: async () => {}, requestCreated: async () => {}, requestDecided: async () => {}, info: async () => {} };
  const requests = createRequestService({ repo, grants, notify, tz: 'UTC', logger: silent });
  const access = createAccess({ repo, catalog, grants, requests });
  repo.createAgent({ id: 'a1', name: 'агент', token_hash: sha256hex('gwa_one'), enabled: 1 });
  repo.createAgent({ id: 'a2', name: 'другой', token_hash: sha256hex('gwa_two'), enabled: 1 });
  let n = 0;
  const addCred = (extra = {}) => {
    const id = `k${++n}`;
    repo.createCredential({
      id, provider: 'telegram', label: `бот ${n}`, kind: 'path', host: 'api.telegram.org',
      injection: { type: 'path', template: '/bot{secret}' }, vault_param: `cred/${id}`, last4: 'abcd', ...extra,
    });
    return repo.getCredential(id);
  };
  const bind = (agentId, ...ids) => repo.setAgentCredentials(agentId, { all: false, ids });
  // активный пропуск агента на ключ
  const issue = (agentId, cred) => {
    const req = { id: `r${++n}`, agent_id: agentId, credential_id: cred.id, ttl: 600, calls: 5, reason: '', expires_at: nowSec() + 600 };
    repo.createRequest(req);
    return grants.issue(req, cred);
  };
  return { db, repo, grants, requests, access, addCred, bind, issue };
}

test('authorizeCall: нормальный вызов проходит и отдаёт agent, grant, credential, provider', () => {
  const s = setup();
  const cred = s.addCred(); s.bind('a1', cred.id);
  const { token } = s.issue('a1', cred);
  const r = s.access.authorizeCall({ token, provider: 'telegram' });
  assert.equal(r.ok, true);
  assert.equal(r.agent.id, 'a1');
  assert.equal(r.credential.id, cred.id);
  assert.equal(r.provider.slug, 'telegram');
});

test('authorizeCall: каждая причина отказа даёт invalid_grant без токена в reason', () => {
  const s = setup();
  const expectFail = (token, provider, reason) => {
    const r = s.access.authorizeCall({ token, provider });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'invalid_grant');
    assert.equal(r.reason, reason);
    assert.ok(!String(r.reason).includes('gwt_'));
  };

  // битая подпись и не токен
  const c1 = s.addCred(); s.bind('a1', c1.id);
  const t1 = s.issue('a1', c1).token;
  expectFail(t1.slice(0, -2) + 'xx', 'telegram', 'token');
  expectFail('мусор', 'telegram', 'token');
  expectFail(undefined, 'telegram', 'token');

  // истёкший токен (grant истёк в базе)
  const c2 = s.addCred(); s.bind('a1', c2.id);
  const g2 = s.issue('a1', c2);
  s.db.prepare('UPDATE grants SET expires_at = ? WHERE id = ?').run(nowSec() - 5, g2.grant.id);
  expectFail(g2.token, 'telegram', 'token');

  // revoked grant
  const c3 = s.addCred(); s.bind('a1', c3.id);
  const g3 = s.issue('a1', c3);
  s.repo.revokeGrant(g3.grant.id);
  expectFail(g3.token, 'telegram', 'token');

  // удалённый ключ (softDelete отзывает grant, значит reason token; ключ без отзыва проверяем прямым UPDATE)
  const c4 = s.addCred(); s.bind('a1', c4.id);
  const g4 = s.issue('a1', c4);
  s.db.prepare('UPDATE credentials SET deleted_at = ? WHERE id = ?').run(nowSec(), c4.id);
  expectFail(g4.token, 'telegram', 'key_missing');

  // provider из URL не совпадает с ключом
  const c5 = s.addCred(); s.bind('a1', c5.id);
  const g5 = s.issue('a1', c5);
  expectFail(g5.token, 'github', 'provider_mismatch');

  // ключ не привязан к агенту
  const c6 = s.addCred(); s.bind('a1', c6.id);
  const g6 = s.issue('a1', c6);
  s.db.prepare('DELETE FROM agent_credentials WHERE agent_id = ? AND credential_id = ?').run('a1', c6.id);
  expectFail(g6.token, 'telegram', 'not_bound');

  // ключ истёк
  const c7 = s.addCred(); s.bind('a1', c7.id);
  const g7 = s.issue('a1', c7);
  s.db.prepare('UPDATE credentials SET expires_at = ? WHERE id = ?').run(nowSec() - 5, c7.id);
  expectFail(g7.token, 'telegram', 'key_unusable');

  // mode deny
  const c8 = s.addCred(); s.bind('a1', c8.id);
  const g8 = s.issue('a1', c8);
  s.db.prepare("UPDATE credentials SET mode = 'deny' WHERE id = ?").run(c8.id);
  expectFail(g8.token, 'telegram', 'key_unusable');

  // вне окна
  const c9 = s.addCred(); s.bind('a1', c9.id);
  const g9 = s.issue('a1', c9);
  const h = new Date().getUTCHours();
  const win = h < 12 ? { days: [0, 1, 2, 3, 4, 5, 6, 7], from: '20:00', to: '21:00' } : { days: [0, 1, 2, 3, 4, 5, 6, 7], from: '02:00', to: '03:00' };
  s.db.prepare('UPDATE credentials SET window_json = ? WHERE id = ?').run(JSON.stringify(win), c9.id);
  expectFail(g9.token, 'telegram', 'key_unusable');
});

test('authorizeCall: agent.enabled=0 при активном grant -> agent_disabled', () => {
  const s = setup();
  const cred = s.addCred(); s.bind('a1', cred.id);
  const { token } = s.issue('a1', cred);
  assert.equal(s.access.authorizeCall({ token, provider: 'telegram' }).ok, true);
  s.db.prepare('UPDATE agents SET enabled = 0 WHERE id = ?').run('a1');
  const r = s.access.authorizeCall({ token, provider: 'telegram' });
  assert.deepEqual({ ok: r.ok, code: r.code, reason: r.reason }, { ok: false, code: 'invalid_grant', reason: 'agent_disabled' });
  assert.equal(authAgent(s.repo, 'gwa_one'), null);
});

test('authorizeCall: agentId и credentialId сверяются с пропуском', () => {
  const s = setup();
  const c1 = s.addCred(); const c2 = s.addCred(); s.bind('a1', c1.id, c2.id);
  const { token } = s.issue('a1', c1);
  assert.equal(s.access.authorizeCall({ token, provider: 'telegram', agentId: 'a1', credentialId: c1.id }).ok, true);
  assert.equal(s.access.authorizeCall({ token, provider: 'telegram', agentId: 'a2' }).reason, 'agent_mismatch');
  assert.equal(s.access.authorizeCall({ token, provider: 'telegram', agentId: 'a1', credentialId: c2.id }).reason, 'credential_mismatch');
});

test('pickCredential: ноль, один и два ключа; чужой ключ неотличим от несуществующего', () => {
  const s = setup();
  const agent = s.repo.getAgent('a1');
  const provider = catalog.get('telegram');
  assert.deepEqual(s.access.pickCredential({ agent, provider }), { ok: false, error: 'no_credential' });

  const c1 = s.addCred(); const c2 = s.addCred(); s.bind('a1', c1.id);
  s.bind('a2', c2.id);
  const one = s.access.pickCredential({ agent, provider });
  assert.equal(one.ok, true); assert.equal(one.credential.id, c1.id);

  // чужой привязанный ключ и несуществующий дают одинаковый ответ
  const foreign = s.access.pickCredential({ agent, provider, credentialId: c2.id });
  const missing = s.access.pickCredential({ agent, provider, credentialId: 'nope' });
  assert.deepEqual(foreign, { ok: false, error: 'no_credential' });
  assert.deepEqual(missing, foreign);

  // ключ другого провайдера
  const gh = s.addCred({ provider: 'github', host: 'api.github.com', kind: 'static', injection: { type: 'header', name: 'authorization', prefix: 'Bearer ' } });
  s.bind('a1', c1.id, gh.id);
  assert.deepEqual(s.access.pickCredential({ agent, provider, credentialId: gh.id }), { ok: false, error: 'no_credential' });

  // два ключа: список только {id,label}
  const c3 = s.addCred(); s.bind('a1', c1.id, c3.id);
  const two = s.access.pickCredential({ agent, provider });
  assert.equal(two.ok, false); assert.equal(two.error, 'credential_id_required');
  assert.deepEqual(two.credentials, [{ id: c1.id, label: c1.label }, { id: c3.id, label: c3.label }]);
  assert.deepEqual(Object.keys(two.credentials[0]).sort(), ['id', 'label']);
  // явный выбор снимает неоднозначность
  assert.equal(s.access.pickCredential({ agent, provider, credentialId: c3.id }).credential.id, c3.id);
});
