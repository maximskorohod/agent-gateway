// Регрессии по ревью codex 03.11 (ТЗ §21, группа A): чистые функции и сервис заявок без сети
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFilter, checkFilter, weakensFilter, normalizeFilter } from '../src/core/filter.js';
import { validateAgentPath } from '../src/core/ssrf.js';
import { createRequestService, inWindow } from '../src/core/requests.js';
import { isPrivateFromSelf } from '../src/tg/bot.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');

test('П-1: путь с «.» и пустыми сегментами не обходит deny ни в фильтре, ни в проверке пути', () => {
  const f = compileFilter({ enabled: true, entities: {}, methods: ['*'], fields: ['result'] }, bitrix);
  for (const p of ['/./batch.json', '/x/./crm.contact.list.json', '//batch.json', '/a//crm.contact.list', '/%62atch.json']) {
    assert.equal(f.allowMethod(p), false, p);
  }
  assert.equal(f.allowMethod('/crm.deal.list.json'), true);
  for (const p of ['/./batch.json', '/a//b', '/./']) assert.equal(validateAgentPath(p), false, p);
  for (const p of ['/crm.deal.list.json', '/v1/models/', '/']) assert.equal(validateAgentPath(p), true, p);
});

test('П-2: путь __proto__ отклоняется формой и не меняет прототип; фильтры ключей не влияют друг на друга', () => {
  const bad = { enabled: true, entities: {}, methods: ['crm.deal.list'], fields: ['__proto__.result.PHONE', 'result.constructor'] };
  assert.equal(checkFilter(bad, bitrix).length, 2);
  compileFilter(bad, bitrix);
  assert.equal(Object.prototype.result, undefined);
  assert.equal({}.PHONE, undefined);
  const g = compileFilter({ enabled: true, entities: {}, methods: ['crm.deal.list'], fields: ['result.ID'] }, bitrix);
  assert.deepEqual(g.filterBody({ result: { ID: 1, PHONE: 'x' } }, '/crm.deal.list').json, { result: { ID: 1 } });
  // ключ "__proto__" в ответе сервиса — обычное поле: не разрешено, значит вырезано
  const r = g.filterBody(JSON.parse('{"result":{"ID":1,"__proto__":{"PHONE":"x"}}}'), '/crm.deal.list');
  assert.equal(JSON.stringify(r.json), '{"result":{"ID":1}}');
});

test('П-3: удалить тип при ручном правиле — ослабление; без ручного правила — нет', () => {
  const cur = normalizeFilter({ enabled: true, entities: { deals: ['result.ID'] }, methods: ['crm.deal.*'], fields: ['result'] }, bitrix);
  const next = { ...cur, entities: {} };
  assert.equal(weakensFilter(next, cur), true);
  const plain = normalizeFilter({ enabled: true, entities: { deals: ['result.ID'], leads: ['result.ID'] }, methods: [], fields: [] }, bitrix);
  assert.equal(weakensFilter({ ...plain, entities: { deals: ['result.ID'] } }, plain), false);
});

test('П-12: окно через полночь — часть после полуночи относится к дню начала', () => {
  const win = { days: [1], from: '22:00', to: '06:00' }; // понедельник 22:00 – вторник 06:00
  assert.equal(inWindow(win, 'UTC', new Date('2026-11-02T23:00:00Z')), true, 'пн 23:00');
  assert.equal(inWindow(win, 'UTC', new Date('2026-11-03T01:00:00Z')), true, 'вт 01:00');
  assert.equal(inWindow(win, 'UTC', new Date('2026-11-02T01:00:00Z')), false, 'пн 01:00 — это окно воскресенья');
  assert.equal(inWindow(win, 'UTC', new Date('2026-11-03T23:00:00Z')), false, 'вт 23:00');
});

test('П-8: бот слушает только личный чат его хозяина', () => {
  assert.equal(isPrivateFromSelf({ id: 42, type: 'private' }, { id: 42 }), true);
  assert.equal(isPrivateFromSelf({ id: -100, type: 'group' }, { id: 42 }), false);
  assert.equal(isPrivateFromSelf({ id: -100, type: 'supergroup' }, { id: -100 }), false);
  assert.equal(isPrivateFromSelf({ id: 42, type: 'private' }, { id: 7 }), false);
  assert.equal(isPrivateFromSelf({ id: 42, type: 'private' }, undefined), false);
});

/** Сервис заявок на заглушках: одна заявка, один ключ, один агент. */
function stubService({ cred, verify = async () => false, approveOk = true }) {
  const now = Math.floor(Date.now() / 1000);
  const state = { req: { id: 'r', status: 'pending', expires_at: now + 300, agent_id: 'a', credential_id: 'c', ttl: 86400, calls: 100000 }, cred, grants: [] };
  const repo = {
    getRequest: () => state.req, getCredential: () => state.cred, getAgent: () => ({ id: 'a', enabled: 1 }), agentCanUse: () => true,
    decideRequest: (id, status) => { state.req = { ...state.req, status }; return true; },
    approveRequest: (id, via, g) => { if (!approveOk || state.req.status !== 'pending') return false; state.req = { ...state.req, status: 'approved' }; state.grants.push(g); return true; },
    getGrant: (id) => state.grants.find((g) => g.id === id), audit() {}, expireRequests() {},
  };
  const grants = { issue: (r, c, persist) => { const g = { id: 'g' + state.grants.length, ttl: r.ttl, calls: r.calls, max_calls: r.calls, expires_at: now + r.ttl }; return persist(g) ? { grant: g } : null; } };
  const svc = createRequestService({ repo, grants, notify: { requestDecided: async () => {} }, tz: 'UTC', verifyTotp: verify, logger: { warn() {}, error() {} } });
  return { svc, state };
}
const baseCred = { id: 'c', mode: 'ask', approval: 'web_code', max_ttl: 300, max_calls: 5, max_parallel: 1, window: null, expires_at: null };

test('П-5: заявку с кодом нельзя одобрить без кода ни через сайт, ни через бота', async () => {
  for (const approval of ['web_code', 'tg_code']) {
    const { svc, state } = stubService({ cred: { ...baseCred, approval } });
    assert.deepEqual(await svc.decide({ requestId: 'r', approve: true, via: 'web' }), { ok: false, error: 'bad_code' }, approval);
    assert.equal(state.req.status, 'pending');
    assert.equal(state.grants.length, 0);
  }
  const { svc } = stubService({ cred: { ...baseCred, approval: 'tg_code' }, verify: null });
  assert.equal((await svc.decide({ requestId: 'r', approve: true, via: 'tg', totp: '123456' })).error, 'bad_code', 'нет проверки — отказ');
});

test('П-5: при одобрении лимиты обрезаются текущим ключом, запрещённый ключ не одобряется', async () => {
  const { svc, state } = stubService({ cred: baseCred, verify: async (c) => c === '111111' });
  const res = await svc.decide({ requestId: 'r', approve: true, via: 'web', totp: '111111' });
  assert.equal(res.ok, true);
  assert.equal(state.grants[0].ttl, 300); assert.equal(state.grants[0].calls, 5);
  const denied = stubService({ cred: { ...baseCred, approval: 'web_button', mode: 'deny' } });
  assert.equal((await denied.svc.decide({ requestId: 'r', approve: true, via: 'web' })).error, 'unavailable');
  assert.equal(denied.state.grants.length, 0);
});

test('П-10: одобрение без записи пропуска не оставляет «approved» и не выдаёт пропуск', async () => {
  const { svc, state } = stubService({ cred: { ...baseCred, approval: 'web_button' }, approveOk: false });
  const res = await svc.decide({ requestId: 'r', approve: true, via: 'web' });
  assert.deepEqual(res, { ok: false, error: 'not_pending' });
  assert.equal(state.grants.length, 0);
});
