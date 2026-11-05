// Фильтр: П-26 (select во всех формах), П-27 (скаляры, keep, object), П-28 (линейный матчер и лимиты)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { compileFilter, checkFilter, checkJsonDepth, globProblem, FILTER_LIMITS } from '../src/core/filter.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
const deals = { enabled: true, entities: { deals: ['result.ID', 'result.COMMENTS', 'result.TITLE'] }, methods: [], fields: [] };
const f = compileFilter(deals, bitrix);
const allowed = ['ID', 'COMMENTS', 'TITLE'];

// ---- П-26: select во всех формах
test('П-26: query — select в любом регистре и с любым индексом заменяется', () => {
  for (const key of ['select[]', 'SELECT[]', 'select', 'SELECT', 'select[0]', 'select[1]', 'Select[7]', 'SELECT[3]', 'select%5B%5D', 'select[0][x]']) {
    const r = f.rewriteSelect('/crm.deal.list.json', `?${key}=PHONE&start=5`);
    const sp = new URLSearchParams(r.query.slice(1));
    assert.deepEqual([...sp.keys()].filter((k) => k !== 'select[]' && k !== 'start'), [], key);
    assert.deepEqual(sp.getAll('select[]'), allowed, key);
    assert.equal(sp.get('start'), '5', key);
  }
});

test('П-26: JSON-тело — select, SELECT, объект с числовыми ключами, select[0]', () => {
  for (const sel of [{ select: ['PHONE'] }, { SELECT: ['PHONE'] }, { Select: { 0: 'PHONE', 1: 'EMAIL' } }, { 'select[0]': 'PHONE' }, { select: 'PHONE' }, { select: ['PHONE'], SELECT: ['EMAIL'] }]) {
    const r = f.rewriteSelect('/crm.deal.list', '', Buffer.from(JSON.stringify({ ...sel, order: { ID: 'DESC' } })), 'application/json; charset=utf-8');
    assert.equal(r.error, undefined);
    const body = JSON.parse(r.body.toString());
    assert.deepEqual(body.select, allowed, JSON.stringify(sel));
    assert.deepEqual(Object.keys(body).filter((k) => /^select/i.test(k)), ['select'], JSON.stringify(sel));
    assert.deepEqual(body.order, { ID: 'DESC' });
  }
});

test('П-26: urlencoded-тело — те же формы, что и в query', () => {
  for (const key of ['select[]', 'SELECT', 'select[2]', 'Select']) {
    const r = f.rewriteSelect('/crm.deal.list', '', Buffer.from(`${key}=PHONE&start=50`), 'application/x-www-form-urlencoded');
    const sp = new URLSearchParams(r.body.toString());
    assert.deepEqual(sp.getAll('select[]'), allowed, key);
    assert.deepEqual([...sp.keys()].filter((k) => k !== 'select[]' && k !== 'start'), [], key);
    assert.equal(sp.get('start'), '50');
  }
});

test('П-26: неизвестная или битая форма тела у метода со select — ошибка body_not_allowed', () => {
  assert.equal(f.rewriteSelect('/crm.deal.list', '', Buffer.from('{broken'), 'application/json').error, 'body_not_allowed');
  assert.equal(f.rewriteSelect('/crm.deal.list', '', Buffer.from('["select"]'), 'application/json').error, 'body_not_allowed');
  assert.equal(f.rewriteSelect('/crm.deal.list', '', Buffer.from('select=PHONE'), 'application/octet-stream').error, 'body_not_allowed');
  assert.equal(f.rewriteSelect('/crm.deal.list', '', Buffer.from('select=PHONE'), '').error, 'body_not_allowed');
  assert.equal(f.rewriteSelect('/crm.deal.list', '', Buffer.from('--x'), 'multipart/form-data; boundary=x').error, 'body_not_allowed');
  // метод без списка полей и пустое тело не затрагиваются
  assert.equal(f.rewriteSelect('/crm.deal.get', '?id=1', Buffer.from('x'), 'text/plain').error, undefined);
  assert.equal(f.rewriteSelect('/crm.deal.list', '?select=PHONE', Buffer.alloc(0), '').error, undefined);
});

// ---- П-27: скаляры, keep, object
test('П-27: поле-объект без object:true вырезается, скаляр остаётся', () => {
  const r = f.filterBody({ result: [{ ID: '1', COMMENTS: { a: 1 }, TITLE: ['x'] }, { ID: 2, COMMENTS: null, TITLE: true }] }, '/crm.deal.list');
  assert.deepEqual(r.json, { result: [{ ID: '1' }, { ID: 2, COMMENTS: null, TITLE: true }] });
  assert.equal(r.removed, 2);
});

test('П-27: строка в разрешённом поле обрезается до maxFieldLen, в keep — до keepMaxLen (256)', () => {
  const r = f.filterBody({ result: { ID: 'x'.repeat(5000) }, error_description: 'e'.repeat(5000), total: 3 }, '/crm.deal.get');
  assert.equal(r.json.result.ID.length, FILTER_LIMITS.maxFieldLen);
  assert.equal(r.json.error_description.length, FILTER_LIMITS.keepMaxLen);
  assert.equal(r.json.total, 3);
  assert.equal(r.removed, 2);
});

test('П-27: keep — только скаляры; объект time вырезается, скаляры time.* остаются', () => {
  const r = f.filterBody({ total: { x: 1 }, next: [1, 2], error: 'E', time: { start: 1.5, finish: 2, duration: 0.5, processing: 0.1, date_start: 'a', date_finish: 'b', operating: 3, extra: { y: 1 } } }, '/crm.deal.list');
  assert.deepEqual(r.json, { error: 'E', time: { start: 1.5, finish: 2, duration: 0.5, processing: 0.1, date_start: 'a', date_finish: 'b' } });
  // time целиком скаляром или объектом в неожиданном виде не пролезает
  assert.deepEqual(f.filterBody({ time: 'now' }, '/crm.deal.list').json, {});
  assert.deepEqual(f.filterBody({ time: { start: { a: 1 } } }, '/crm.deal.list').json, { time: {} });
  // keepMaxLen из каталога
  const custom = compileFilter(deals, { ...bitrix, filter: { ...bitrix.filter, keepMaxLen: 5 } });
  assert.equal(custom.filterBody({ error: '1234567890' }, '/crm.deal.list').json.error, '12345');
});

test('П-27: вложенное под скалярным полем не проходит; PHONE/EMAIL с object:true сохраняют массив', () => {
  const r = f.filterBody({ result: [{ ID: { VALUE: 'x' } }] }, '/crm.deal.list');
  assert.deepEqual(r.json, { result: [{}] });
  const leads = compileFilter({ enabled: true, entities: { leads: ['result.ID', 'result.PHONE', 'result.EMAIL', 'result.NAME'] }, methods: [], fields: [] }, bitrix);
  const phone = [{ ID: '9', VALUE: '+700', VALUE_TYPE: 'WORK' }];
  const out = leads.filterBody({ result: [{ ID: '1', PHONE: phone, EMAIL: [{ VALUE: 'a@x' }], NAME: ['x'] }] }, '/crm.lead.list');
  assert.deepEqual(out.json, { result: [{ ID: '1', PHONE: phone, EMAIL: [{ VALUE: 'a@x' }] }] });
  // то же поле в ручном правиле владельца object не получает
  const manual = compileFilter({ enabled: true, entities: {}, methods: ['crm.lead.*'], fields: ['result.PHONE'] }, bitrix);
  assert.deepEqual(manual.filterBody({ result: [{ PHONE: phone }] }, '/crm.lead.list').json, { result: [{}] });
});

test('П-27: loadCatalog принимает object:true и keepMaxLen, отвергает остальное', () => {
  const entity = (extra = '') => `  x:\n    name: X\n    host: x.example.com\n    kind: static\n    injection: { type: header, name: authorization }\n    filter:\n${extra}      keep: [a]\n      deny: []\n      entities:\n        e:\n          name: E\n          methods: [m.get]\n          fields:\n            - { path: result.ID, label: ID }\n          defaults: [result.ID]\n`;
  const head = 'defaults:\n  maxBody: 1000\n  timeout: 10\n  kind: static\n  fields: [key]\nproviders:\n';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-limits-'));
  const load = (yaml) => {
    const file = path.join(tmp, `c-${crypto.randomBytes(4).toString('hex')}.yaml`);
    fs.writeFileSync(file, yaml);
    try { loadCatalog(file); return null; } catch (e) { return e.message; }
  };
  assert.equal(load(head + entity('      keepMaxLen: 100\n')), null);
  assert.match(load(head + entity('      keepMaxLen: 0\n')), /keepMaxLen/);
  assert.match(load(head + entity('      keepMaxLen: 99999\n')), /keepMaxLen/);
  assert.match(load(head + entity().replace('label: ID }', 'label: ID, object: yes }')), /object/);
  assert.match(load(head + entity().replace('deny: []', 'deny: [a*b*c*d]')), /deny/);
  assert.match(load(head + entity().replace('methods: [m.get]', 'methods: [a/b/c/d/e/f/g/h/i/j/k/l/m]')), /methods/);
  assert.match(load(head + entity().replace('path: result.ID', 'path: a.b.c.d.e.f.g.h.i')), /deeper than/);
  const many = Array.from({ length: 201 }, (_, i) => `            - { path: result.F${i}, label: F }`).join('\n');
  assert.match(load(head + entity().replace('            - { path: result.ID, label: ID }', many).replace('[result.ID]', '[]')), /at most 200/);
});

// ---- П-28: линейный матчер и лимиты
const measure = (fn, runs = 5) => { let max = 0; for (let i = 0; i < runs; i++) { const s = process.hrtime.bigint(); fn(); max = Math.max(max, Number(process.hrtime.bigint() - s) / 1e6); } return max; };

test('П-28: время — 12-сегментный шаблон и a*a* против длинных путей (контракт 9)', () => {
  const seg = compileFilter({ enabled: true, entities: {}, methods: [Array(12).fill('a').join('/')], fields: ['result.ID'] }, bitrix);
  const longPath = `/${'a/'.repeat(12)}x`;
  assert.equal(seg.allowMethod(longPath), false);
  assert.equal(seg.allowMethod(`/${Array(12).fill('a').join('/')}`), true);
  assert.ok(measure(() => seg.allowMethod(longPath)) < 5, '12 сегментов < 5 мс');
  const star = compileFilter({ enabled: true, entities: {}, methods: ['a*a*'], fields: ['result.ID'] }, bitrix);
  const hay = `/${'a'.repeat(100000)}`;
  assert.equal(star.allowMethod(hay), true);
  assert.ok(measure(() => star.allowMethod(hay)) < 50, 'a*a* на 100 000 символов < 50 мс');
  const miss = `/${'a'.repeat(100000)}b`;
  assert.ok(measure(() => star.allowMethod(miss)) < 50, 'промах тоже линеен');
});

test('П-28: звёзды работают как раньше (середина, начало, конец, одиночная)', () => {
  const g = (m) => compileFilter({ enabled: true, entities: {}, methods: [m], fields: ['result.ID'] }, bitrix);
  assert.equal(g('crm.deal.*').allowMethod('/crm.deal.update'), true);
  assert.equal(g('*.get').allowMethod('/status.entity.get'), true);
  assert.equal(g('*.get').allowMethod('/status.entity.getx'), false);
  assert.equal(g('a*c').allowMethod('/abbbc'), true);
  assert.equal(g('a*c').allowMethod('/abbbd'), false);
  assert.equal(g('*').allowMethod('/anything.at.all'), true);
  assert.equal(g('a*b*c').allowMethod('/xa'), false);
  assert.equal(g('a*b*c').allowMethod('/a1b2c'), true);
});

test('П-28: шаблон с более чем двумя звёздами, длинный или с лишними сегментами не принимается', () => {
  assert.equal(globProblem('a*b*c'), null);
  assert.equal(globProblem('a*b*c*d'), 'stars');
  assert.equal(globProblem(Array(13).fill('a').join('/')), 'segments');
  assert.equal(globProblem('a'.repeat(201)), 'length');
  const form = (m) => checkFilter({ enabled: true, entities: {}, methods: [m], fields: ['result.ID'] }, bitrix).join();
  assert.match(form('a*b*c*d'), /at most 2 asterisks/);
  assert.match(form(Array(13).fill('a').join('/')), /at most 12/);
  assert.match(form('a'.repeat(201)), /Latin letters/);
  assert.equal(form('a*b*c'), '');
  // при выполнении негодный шаблон ничего не открывает
  assert.equal(compileFilter({ enabled: true, entities: {}, methods: ['a*b*c*d'], fields: ['result.ID'] }, bitrix).allowMethod('/axbxcxd'), false);
});

test('П-28: лимиты полей и правил в checkFilter', () => {
  const many = Array.from({ length: 201 }, (_, i) => `result.F${i}`);
  assert.match(checkFilter({ enabled: true, entities: { deals: many }, methods: [], fields: [] }, bitrix).join(), /at most 200/);
  assert.match(checkFilter({ enabled: true, entities: {}, methods: ['a'], fields: many }, bitrix).join(), /at most 200/);
  assert.equal(checkFilter({ enabled: true, entities: {}, methods: ['a'], fields: many.slice(0, 200) }, bitrix).join(), '');
  assert.match(checkFilter({ enabled: true, entities: {}, methods: ['a'], fields: ['a.b.c.d.e.f.g.h.i'] }, bitrix).join(), /deeper than 8/);
  assert.equal(checkFilter({ enabled: true, entities: {}, methods: ['a'], fields: ['a.b.c.d.e.f.g.h'] }, bitrix).join(), '');
  const rules = Array.from({ length: 65 }, (_, i) => `m${i}`);
  assert.match(checkFilter({ enabled: true, entities: {}, methods: rules, fields: ['result.ID'] }, bitrix).join(), /at most 64/);
  // русский словарь с теми же ключами
  initI18n('ru');
  assert.match(checkFilter({ enabled: true, entities: {}, methods: ['a*b*c*d'], fields: ['result.ID'] }, bitrix).join(), /звёздочек/);
  initI18n('en');
  // правил больше лимита при выполнении: лишние закрыты
  const g = compileFilter({ enabled: true, entities: {}, methods: rules, fields: ['result.ID'] }, bitrix);
  assert.equal(g.allowMethod('/m0'), true);
  assert.equal(g.allowMethod('/m64'), false);
});

test('П-28: глубина JSON 33 — отказ, 32 проходит, скобки в строках и экранирование не считаются', () => {
  const nest = (n) => Buffer.from('['.repeat(n) + ']'.repeat(n));
  assert.equal(checkJsonDepth(nest(32)), true);
  assert.equal(checkJsonDepth(nest(33)), false);
  const objs = (n) => Buffer.from('{"a":'.repeat(n) + '1' + '}'.repeat(n));
  assert.equal(checkJsonDepth(objs(32)), true);
  assert.equal(checkJsonDepth(objs(33)), false);
  assert.equal(checkJsonDepth(Buffer.from(JSON.stringify({ s: '['.repeat(500) + '{'.repeat(500), t: 'a\\"[[[[' + '"', u: '\\' }))), true);
  assert.equal(checkJsonDepth(Buffer.from(`{"k":"\\"${'['.repeat(100)}"}`)), true);
  // кавычка после экранированного обратного слеша закрывает строку
  assert.equal(checkJsonDepth(Buffer.from(`{"k":"\\\\"}${'['.repeat(40)}`)), false);
  // линейно: 5 МБ вложенных пар
  assert.ok(measure(() => checkJsonDepth(Buffer.alloc(5 * 1024 * 1024, 0x20)), 2) < 200);
});

test('П-28: prune сам останавливается на 33-м уровне', () => {
  let deep = { ID: '1' };
  for (let i = 0; i < 40; i++) deep = { result: [deep] };
  const g = compileFilter({ enabled: true, entities: { deals: ['result.ID'] }, methods: [], fields: [] }, bitrix);
  const r = g.filterBody(deep, '/crm.deal.list');
  assert.ok(JSON.stringify(r.json).length < 200);
});
