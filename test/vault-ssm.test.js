// П-31: гонка кэша SSM. Без сети и AWS: подставной клиент с ручным управлением порядком ответов.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createSsmVault } from '../src/vault/ssm.js';

const rnd = () => randomBytes(6).toString('hex');
const notFound = () => Object.assign(new Error('nf'), { name: 'ParameterNotFound' });

// Подставной клиент: хранилище + отложенные ответы. hold=true копит запросы в очереди.
function fakeClient(initial) {
  const store = new Map(initial ? [['p/k', initial]] : []);
  const calls = [];
  const pending = []; // { kind, resolve }
  let hold = false;
  return {
    calls, pending, store,
    setHold(v) { hold = v; },
    async send(cmd) {
      const kind = cmd.constructor.name;
      calls.push(kind);
      const name = cmd.input.Name;
      // Значение для Get снимается в момент отправки (запрос «прочитал» старое)
      const snapshot = kind === 'GetParameterCommand' ? store.get(name) : undefined;
      const finish = () => {
        if (kind === 'GetParameterCommand') {
          if (snapshot === undefined) throw notFound();
          return { Parameter: { Value: snapshot } };
        }
        if (kind === 'PutParameterCommand') { store.set(name, cmd.input.Value); return {}; }
        if (store.has(name)) { store.delete(name); return {}; }
        throw notFound();
      };
      if (!hold) return finish();
      return new Promise((resolve, reject) => {
        pending.push({ kind, release: () => { try { resolve(finish()); } catch (e) { reject(e); } } });
      });
    },
  };
}

const cfg = { vaultPrefix: 'p', ssmRegion: 'eu-west-1' };
const tick = () => new Promise((r) => setImmediate(r));

test('кэш: второй get не ходит в SSM', async () => {
  const c = fakeClient(rnd());
  const v = createSsmVault(cfg, { client: c });
  const a = await v.get('k');
  const b = await v.get('k');
  assert.equal(a, b);
  assert.equal(c.calls.length, 1);
});

test('TTL: после истечения get идёт в SSM снова', async () => {
  const c = fakeClient(rnd());
  let t = 1000;
  const v = createSsmVault(cfg, { client: c, ttlMs: 100, now: () => t });
  await v.get('k');
  t += 99; await v.get('k');
  assert.equal(c.calls.length, 1);
  t += 2; await v.get('k');
  assert.equal(c.calls.length, 2);
});

test('П-31: get стартовал до put и завершился после - старое не попадает в кэш', async () => {
  const oldV = rnd(), newV = rnd();
  const c = fakeClient(oldV);
  const v = createSsmVault(cfg, { client: c });
  c.setHold(true);
  const slowGet = v.get('k'); // прочитал старое, ждёт
  await tick();
  const putP = v.put('k', newV);
  await tick();
  c.pending.find((p) => p.kind === 'PutParameterCommand').release();
  await putP;
  c.pending.find((p) => p.kind === 'GetParameterCommand').release();
  assert.equal(await slowGet, oldV); // свой вызывающий мог получить старое (запрос был до записи)
  c.setHold(false);
  assert.equal(await v.get('k'), newV); // но кэш старое не помнит
});

test('П-31: get во время незавершённого put не кэшируется', async () => {
  const oldV = rnd(), newV = rnd();
  const c = fakeClient(oldV);
  const v = createSsmVault(cfg, { client: c });
  c.setHold(true);
  const putP = v.put('k', newV);
  await tick();
  const midGet = v.get('k');
  await tick();
  c.pending.find((p) => p.kind === 'GetParameterCommand').release();
  await midGet;
  c.pending.find((p) => p.kind === 'PutParameterCommand').release();
  await putP;
  c.setHold(false);
  assert.equal(await v.get('k'), newV);
});

test('П-31: del после старого get - следующий get идёт в SSM и получает null', async () => {
  const c = fakeClient(rnd());
  const v = createSsmVault(cfg, { client: c });
  c.setHold(true);
  const slowGet = v.get('k');
  await tick();
  const delP = v.del('k');
  await tick();
  c.pending.find((p) => p.kind === 'DeleteParameterCommand').release();
  await delP;
  c.pending.find((p) => p.kind === 'GetParameterCommand').release();
  await slowGet;
  c.setHold(false);
  assert.equal(await v.get('k'), null);
});

test('П-31: del ничего не кэширует, ParameterNotFound кэшируется только без гонки', async () => {
  const c = fakeClient(rnd());
  const v = createSsmVault(cfg, { client: c });
  await v.del('k');
  assert.equal(await v.get('k'), null);
  const n = c.calls.length;
  assert.equal(await v.get('k'), null); // null закэширован (гонки не было)
  assert.equal(c.calls.length, n);
  // put сбрасывает закэшированный null
  const nv = rnd();
  await v.put('k', nv);
  assert.equal(await v.get('k'), nv);
});

test('П-31: ParameterNotFound от старого get не кэшируется после put', async () => {
  const newV = rnd();
  const c = fakeClient(null);
  const v = createSsmVault(cfg, { client: c });
  c.setHold(true);
  const slowGet = v.get('k'); // увидит «нет параметра»
  await tick();
  const putP = v.put('k', newV);
  await tick();
  c.pending.find((p) => p.kind === 'PutParameterCommand').release();
  await putP;
  c.pending.find((p) => p.kind === 'GetParameterCommand').release();
  assert.equal(await slowGet, null);
  c.setHold(false);
  assert.equal(await v.get('k'), newV);
});

test('П-31: параллельные get после put видят новое значение', async () => {
  const newV = rnd();
  const c = fakeClient(rnd());
  const v = createSsmVault(cfg, { client: c });
  await v.get('k');
  await v.put('k', newV);
  const res = await Promise.all([v.get('k'), v.get('k'), v.get('k')]);
  assert.deepEqual(res, [newV, newV, newV]);
  assert.equal(await v.get('k'), newV);
});

test('П-31: упавший put тоже сбрасывает кэш', async () => {
  const oldV = rnd();
  const c = fakeClient(oldV);
  const v = createSsmVault(cfg, { client: c });
  await v.get('k');
  const orig = c.send.bind(c);
  c.send = async (cmd) => {
    if (cmd.constructor.name === 'PutParameterCommand') throw new Error('boom');
    return orig(cmd);
  };
  await assert.rejects(v.put('k', rnd()), /boom/);
  const n = c.calls.length;
  await v.get('k');
  assert.equal(c.calls.length, n + 1);
});
