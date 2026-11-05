// Режим «без вопросов на время»: разбор формы, требование кода 2FA, выдача пропуска. Без сети.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePolicy, widensAlways, weakensPolicy } from '../src/web/policy.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { createRequestService } from '../src/core/requests.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const nowSec = () => Math.floor(Date.now() / 1000);

test('parsePolicy: always_for задаёт срок, forever и старые формы — бессрочно, другие режимы сбрасывают срок', () => {
  const day = parsePolicy({ mode: 'always', always_for: '86400' }, { telegramConnected: false }).policy;
  assert.ok(Math.abs(day.always_until - (nowSec() + 86400)) <= 2);
  assert.equal(parsePolicy({ mode: 'always', always_for: 'forever' }, { telegramConnected: false }).policy.always_until, null);
  assert.equal(parsePolicy({ mode: 'always' }, { telegramConnected: false }).policy.always_until, null);
  assert.equal(parsePolicy({ mode: 'ask', always_for: '3600' }, { telegramConnected: false }).policy.always_until, null);
  assert.deepEqual(parsePolicy({ mode: 'always', always_for: '5' }, { telegramConnected: false }).errors, ['Неверный срок режима «без вопросов»']);

  const current = { mode: 'always', always_until: nowSec() + 100 };
  assert.equal(parsePolicy({ mode: 'always', always_for: 'keep' }, { telegramConnected: false, current }).policy.always_until, current.always_until);
});

test('parsePolicy: снятые галочки дней в форме убирают окно, а без полей формы окно не меняется', () => {
  const current = { window: { days: [2], from: '10:00', to: '11:00' } };
  const ctx = { telegramConnected: false, current };
  assert.equal(parsePolicy({ mode: 'ask', from: '', to: '' }, ctx).policy.window, null);
  assert.deepEqual(parsePolicy({ mode: 'ask' }, ctx).policy.window, current.window);
  assert.deepEqual(parsePolicy({ mode: 'ask', days: '3', from: '09:00', to: '10:00' }, ctx).policy.window, { days: [3], from: '09:00', to: '10:00' });
});

test('widensAlways: код 2FA нужен при включении и при продлении, но не при сокращении', () => {
  const t = nowSec();
  assert.equal(widensAlways({ mode: 'always', always_until: t + 3600 }, { mode: 'ask' }), true);
  assert.equal(widensAlways({ mode: 'always', always_until: t + 86400 }, { mode: 'always', always_until: t + 3600 }), true);
  assert.equal(widensAlways({ mode: 'always', always_until: null }, { mode: 'always', always_until: t + 3600 }), true);
  assert.equal(widensAlways({ mode: 'always', always_until: t + 600 }, { mode: 'always', always_until: t + 3600 }), false);
  assert.equal(widensAlways({ mode: 'always', always_until: t + 600 }, { mode: 'always', always_until: null }), false);
  assert.equal(widensAlways({ mode: 'ask', always_until: null }, { mode: 'ask' }), false);
});

test('submit: после always_until заявка ждёт решения, до — пропуск сразу', () => {
  const repo = createRepo(openDb(':memory:'));
  repo.createAgent({ id: 'a1', name: 'агент', token_hash: 'th', enabled: 1 });
  const base = { provider: 'telegram', label: 'бот', kind: 'path', host: 'api.telegram.org', injection: { type: 'path', template: '/bot{secret}' }, last4: 'abcd', approval: 'web_button' };
  repo.createCredential({ ...base, id: 'old', vault_param: 'cred/old', mode: 'always', always_until: nowSec() - 5 });
  repo.createCredential({ ...base, id: 'new', vault_param: 'cred/new', mode: 'always', always_until: nowSec() + 600 });
  const notify = { grantAuto: async () => {}, requestCreated: async () => {}, requestDecided: async () => {}, info: async () => {} };
  const grants = { issue: (req) => ({ grant: { id: 'g-' + req.id }, token: 'gwt_test' }) };
  const svc = createRequestService({ repo, grants, notify, tz: 'UTC', logger: { warn() {}, error() {} } });
  const agent = repo.getAgent('a1');

  assert.equal(svc.submit({ agent, credential: repo.getCredential('old'), ttl: 600, calls: 5, reason: '' }).kind, 'pending');
  assert.equal(svc.submit({ agent, credential: repo.getCredential('new'), ttl: 600, calls: 5, reason: '' }).kind, 'granted');
});

test('submit: автопропуск не живёт дольше режима «без вопросов»', () => {
  const repo = createRepo(openDb(':memory:'));
  repo.createAgent({ id: 'a1', name: 'агент', token_hash: 'th', enabled: 1 });
  const base = { provider: 'telegram', label: 'бот', kind: 'path', host: 'api.telegram.org', injection: { type: 'path', template: '/bot{secret}' }, last4: 'abcd', approval: 'web_button', max_ttl: 86400 };
  repo.createCredential({ ...base, id: 'hour', vault_param: 'cred/hour', mode: 'always', always_until: nowSec() + 120 });
  repo.createCredential({ ...base, id: 'ever', vault_param: 'cred/ever', mode: 'always', always_until: null });
  const issued = [];
  const grants = { issue: (req) => { issued.push(req); return { grant: { id: 'g-' + req.id }, token: 'gwt_test' }; } };
  const notify = { grantAuto: async () => {}, requestCreated: async () => {} };
  const svc = createRequestService({ repo, grants, notify, tz: 'UTC', logger: { warn() {}, error() {} } });
  const agent = repo.getAgent('a1');
  svc.submit({ agent, credential: repo.getCredential('hour'), ttl: 86400, calls: 5 });
  assert.ok(issued[0].ttl <= 120 && issued[0].ttl >= 118, `ttl ${issued[0].ttl} обрезан до конца режима`);
  svc.submit({ agent, credential: repo.getCredential('ever'), ttl: 86400, calls: 5 });
  assert.equal(issued[1].ttl, 86400, 'бессрочный режим срок не режет');
});

test('weakensPolicy: код нужен на любое ослабление и не нужен на усиление', () => {
  const cur = { mode: 'ask', approval: 'web_code', max_ttl: 300, max_calls: 5, max_parallel: 1, window: { days: [1, 2], from: '09:00', to: '18:00' }, expires_at: 2000000000 };
  const same = { ...cur };
  assert.equal(weakensPolicy(same, cur), false);
  assert.equal(weakensPolicy({ ...same, approval: 'web_button' }, cur), true, 'подтверждение без кода');
  assert.equal(weakensPolicy({ ...same, max_ttl: 86400 }, cur), true);
  assert.equal(weakensPolicy({ ...same, max_calls: 100000 }, cur), true);
  assert.equal(weakensPolicy({ ...same, max_parallel: 2 }, cur), true);
  assert.equal(weakensPolicy({ ...same, window: null }, cur), true, 'окно снято');
  assert.equal(weakensPolicy({ ...same, expires_at: null }, cur), true, 'срок ключа снят');
  assert.equal(weakensPolicy({ ...same, expires_at: 2000000001 }, cur), true);
  assert.equal(weakensPolicy({ ...same, mode: 'always', always_until: null }, cur), true);
  assert.equal(weakensPolicy({ ...same, mode: 'ask' }, { ...cur, mode: 'deny' }), true, 'выход из «запретить»');
  // усиление
  assert.equal(weakensPolicy({ ...same, mode: 'deny', max_ttl: 300, max_calls: 1, expires_at: 1900000000 }, cur), false);
  assert.equal(weakensPolicy({ ...same, approval: 'tg_code', window: { days: [1, 2], from: '09:00', to: '18:00' } }, cur), false);
  assert.equal(weakensPolicy({ ...same, label: 'новое имя' }, cur), false);
});
