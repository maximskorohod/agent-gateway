// Фильтр данных (ТЗ v1.3): модуль core/filter.js и разбор формы
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFilter, normalizeMethod, normalizeFilter, checkFilter, weakensFilter } from '../src/core/filter.js';
import { parseFilter } from '../src/web/policy.js';
import { loadCatalog } from '../src/catalog.js';
import { initI18n } from '../src/i18n.js';

initI18n('ru');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
const dealFields = ['result.ID', 'result.TITLE', 'result.STAGE_ID', 'result.COMMENTS', 'result.DATE_CREATE'];
const deals = { enabled: true, entities: { deals: dealFields }, methods: [], fields: [] };

test('выключенный фильтр не компилируется', () => {
  assert.equal(compileFilter(null, bitrix), null);
  assert.equal(compileFilter({ ...deals, enabled: false }, bitrix), null);
});

test('имя метода: регистр, .json, косые черты', () => {
  assert.equal(normalizeMethod('/CRM.Deal.List.json'), 'crm.deal.list');
  assert.equal(normalizeMethod('crm.deal.get.xml'), 'crm.deal.get');
  assert.equal(normalizeMethod('/crm/v3/objects/deals/'), 'crm/v3/objects/deals');
});

test('методы: белый список, deny сильнее любого шаблона', () => {
  const f = compileFilter(deals, bitrix);
  assert.equal(f.allowMethod('/crm.deal.list.json'), true);
  assert.equal(f.allowMethod('/crm.deal.get'), true);
  assert.equal(f.allowMethod('/crm.contact.get.json'), false);
  assert.equal(f.allowMethod('/crm.deal.update'), false);
  assert.equal(f.allowMethod('/crm.deal.list/x'), false);
  const wide = compileFilter({ ...deals, methods: ['*'], fields: ['result.ID'] }, bitrix);
  assert.equal(wide.allowMethod('/crm.deal.update'), true);
  for (const m of ['/batch.json', '/crm.contact.list', '/crm.item.list', '/telephony.externalcall.searchcrmentities', '/crm.activity.list', '/disk.file.get']) {
    assert.equal(wide.allowMethod(m), false, m);
  }
});

test('поля: остаются только разрешённые и служебные, массивы проходятся насквозь', () => {
  const f = compileFilter(deals, bitrix);
  const list = { result: [{ ID: '1', TITLE: 'Окна', COMMENTS: 'перезвонить', NAME: 'Иван', PHONE: [{ VALUE: '+79991234567' }] }, { ID: '2', CONTACT_ID: '7' }], total: 2, next: 50, time: { start: 1 } };
  const { json, removed } = f.filterBody(list, '/crm.deal.list.json');
  assert.deepEqual(json, { result: [{ ID: '1', TITLE: 'Окна', COMMENTS: 'перезвонить' }, { ID: '2' }], total: 2, next: 50, time: { start: 1 } });
  assert.equal(removed, 3);
  // crm.deal.get: result — объект, тот же путь работает
  assert.deepEqual(f.filterBody({ result: { ID: '5', PHONE: 'x' } }, '/crm.deal.get').json, { result: { ID: '5' } });
  // ошибка сервиса доходит до агента
  assert.deepEqual(f.filterBody({ error: 'ACCESS_DENIED', error_description: 'нет прав' }, '/crm.deal.list').json, { error: 'ACCESS_DENIED', error_description: 'нет прав' });
  // скаляр вместо объекта не отдаётся
  assert.deepEqual(f.filterBody({ result: 'строка с телефоном' }, '/crm.deal.list').json, {});
  // метод вне правил — только служебные поля
  assert.deepEqual(f.filterBody({ result: [{ ID: '1' }], total: 1 }, '/crm.lead.list').json, { total: 1 });
});

test('сделки и лиды: у каждого типа свои поля и свой select', () => {
  const f = compileFilter({ enabled: true, entities: { deals: ['result.ID', 'result.COMMENTS'], leads: ['result.ID', 'result.PHONE'] }, methods: [], fields: [] }, bitrix);
  const row = { result: [{ ID: '1', COMMENTS: 'к', PHONE: '+7' }] };
  assert.deepEqual(f.filterBody(row, '/crm.deal.list').json, { result: [{ ID: '1', COMMENTS: 'к' }] });
  assert.deepEqual(f.filterBody(row, '/crm.lead.list.json').json, { result: [{ ID: '1', PHONE: '+7' }] });
  assert.deepEqual(new URLSearchParams(f.rewriteSelect('/crm.lead.list', '').query.slice(1)).getAll('select[]'), ['ID', 'PHONE']);
  assert.equal(f.allowMethod('/user.get'), false, 'имена менеджеров не отмечены');
  assert.deepEqual(f.methods, ['crm.deal.list', 'crm.deal.get', 'crm.lead.list', 'crm.lead.get']);
});

test('имена менеджеров: user.get отдаёт только имя, запись сотрудников закрыта', () => {
  const f = compileFilter({ enabled: true, entities: { users: ['result.ID', 'result.NAME', 'result.LAST_NAME'] }, methods: [], fields: [] }, bitrix);
  const u = { result: [{ ID: '7', NAME: 'Анна', LAST_NAME: 'К', EMAIL: 'a@x', PERSONAL_MOBILE: '+7' }], total: 1 };
  assert.deepEqual(f.filterBody(u, '/user.get.json').json, { result: [{ ID: '7', NAME: 'Анна', LAST_NAME: 'К' }], total: 1 });
  const wide = compileFilter({ enabled: true, entities: {}, methods: ['user.*'], fields: ['result.ID'] }, bitrix);
  for (const m of ['/user.update', '/user.add', '/user.search', '/user.current']) assert.equal(wide.allowMethod(m), false, m);
  assert.equal(wide.allowMethod('/user.get'), true);
});

test('select: агентский заменяется разрешённым (query, JSON, форма), прочие методы не трогаются', () => {
  const f = compileFilter(deals, bitrix);
  const r = f.rewriteSelect('/crm.deal.list.json', '?select[]=PHONE&select[1]=NAME&filter[>ID]=5');
  const sp = new URLSearchParams(r.query.slice(1));
  assert.deepEqual(sp.getAll('select[]'), dealFields.map((x) => x.split('.')[1]));
  assert.equal(sp.get('filter[>ID]'), '5');
  assert.equal(sp.get('select[1]'), null);
  const j = f.rewriteSelect('/crm.deal.list', '', Buffer.from('{"select":["PHONE"],"order":{"ID":"DESC"}}'), 'application/json');
  const body = JSON.parse(j.body.toString());
  assert.ok(!body.select.includes('PHONE')); assert.ok(body.select.includes('COMMENTS')); assert.deepEqual(body.order, { ID: 'DESC' });
  const fm = f.rewriteSelect('/crm.deal.list', '', Buffer.from('select%5B%5D=PHONE&start=50'), 'application/x-www-form-urlencoded');
  const fsp = new URLSearchParams(fm.body.toString());
  assert.ok(!fsp.getAll('select[]').includes('PHONE')); assert.equal(fsp.get('start'), '50');
  assert.deepEqual(f.rewriteSelect('/crm.deal.get', '?id=5'), { query: '?id=5', body: null });
});


test('по умолчанию: фильтр выключен, у типов отмечены менеджер, сумма, даты; свободный текст выключен', () => {
  const d = normalizeFilter(null, bitrix);
  assert.equal(d.enabled, false);
  assert.deepEqual(Object.keys(d.entities), ['deals', 'leads', 'users']);
  for (const ent of ['deals', 'leads']) {
    for (const p of ['result.ASSIGNED_BY_ID', 'result.OPPORTUNITY', 'result.CURRENCY_ID', 'result.DATE_CREATE', 'result.MOVED_TIME']) assert.ok(d.entities[ent].includes(p), `${ent} ${p}`);
    // в названии и комментарии менеджеры пишут имена и телефоны клиентов
    for (const p of ['result.TITLE', 'result.COMMENTS']) assert.ok(!d.entities[ent].includes(p), `${ent} ${p}`);
  }
  assert.ok(!d.entities.leads.includes('result.PHONE'));
  assert.deepEqual(checkFilter({ ...d, enabled: true }, bitrix), []);
});

test('старая запись с пресетом читается как тип данных', () => {
  const old = { enabled: true, preset: 'deals', methods: ['crm.deal.list', 'crm.deal.get'], fields: ['result.ID', 'result.UF_CRM_1'] };
  assert.deepEqual(normalizeFilter(old, bitrix), { enabled: true, entities: { deals: ['result.ID', 'result.UF_CRM_1'] }, methods: [], fields: [] });
  const mixed = normalizeFilter({ enabled: true, preset: 'custom', methods: ['crm.deal.list', 'crm.deal.get', 'crm.status.list'], fields: ['result.ID'] }, bitrix);
  assert.deepEqual(mixed.methods, ['crm.status.list']); assert.deepEqual(mixed.fields, ['result.ID']);
  assert.equal(compileFilter(old, bitrix).allowMethod('/crm.deal.get'), true);
  // пустая выключенная запись старого вида — как ненастроенный фильтр
  assert.deepEqual(normalizeFilter({ enabled: false, preset: null, methods: [], fields: [] }, bitrix), normalizeFilter(null, bitrix));
});

test('проверка формы: deny нельзя разрешить, пустые типы и списки — ошибка', () => {
  assert.deepEqual(checkFilter(deals, bitrix), []);
  assert.match(checkFilter({ ...deals, methods: ['batch'], fields: ['result.ID'] }, bitrix).join(), /batch.*закрыт всегда/);
  assert.match(checkFilter({ ...deals, methods: ['CRM.Contact.Get'], fields: ['result.ID'] }, bitrix).join(), /закрыт всегда/);
  assert.match(checkFilter({ enabled: true, entities: {}, methods: [], fields: [] }, bitrix).join(), /хотя бы один тип/);
  assert.match(checkFilter({ enabled: true, entities: { leads: [] }, methods: [], fields: [] }, bitrix).join(), /«Лиды»: отметьте/);
  assert.match(checkFilter({ ...deals, methods: ['crm.status.list'] }, bitrix).join(), /укажите поля/);
  assert.match(checkFilter({ ...deals, entities: { deals: ['result.<script>'] } }, bitrix).join(), /Поле/);
  assert.deepEqual(checkFilter({ enabled: false }, bitrix), []);
});

test('ослабление: выключение, новый тип, поле или метод; ужесточение и первое включение — нет', () => {
  assert.equal(weakensFilter(deals, normalizeFilter(null, bitrix)), false);
  assert.equal(weakensFilter({ ...deals, enabled: false }, deals), true);
  assert.equal(weakensFilter({ ...deals, entities: { deals: [...dealFields, 'result.OPPORTUNITY'] } }, deals), true);
  assert.equal(weakensFilter({ ...deals, entities: { ...deals.entities, leads: ['result.ID'] } }, deals), true);
  assert.equal(weakensFilter({ ...deals, methods: ['crm.status.list'], fields: ['result.ID'] }, deals), true);
  assert.equal(weakensFilter({ ...deals, entities: { deals: ['result.ID'] } }, deals), false);
  assert.equal(weakensFilter({ ...deals, entities: {} , methods: [], fields: [] }, deals), false);
});

test('форма: галочки типов и полей, свои поля, выключатель без формы сохраняет настройки', () => {
  const body = { entities_form: '1', enabled: '1', ent_deals: '1', f_deals: ['result.ID', 'result.COMMENTS'], x_deals: 'result.UF_CRM_1', f_leads: 'result.ID', methods: '', fields_extra: '' };
  const on = parseFilter(body, bitrix, null);
  assert.deepEqual(on, { enabled: true, entities: { deals: ['result.ID', 'result.COMMENTS', 'result.UF_CRM_1'] }, methods: [], fields: [] }, 'лиды без галочки типа закрыты');
  const off = parseFilter({ ...body, enabled: undefined }, bitrix, on);
  assert.equal(off.enabled, false); assert.deepEqual(off.entities, on.entities);
  assert.deepEqual(parseFilter({ enabled: '1' }, bitrix, off), on, 'только выключатель');
  assert.deepEqual(parseFilter({}, bitrix, on), { ...on, enabled: false });
});
