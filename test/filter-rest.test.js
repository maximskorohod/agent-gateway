// Фильтр REST (П-17, П-18, П-27, П-28): «HTTP-метод + маршрут», линейный матчер, запись только явным флагом.
// REST-провайдер задан фикстурой (свой yaml во временном каталоге), реальные HubSpot/Pipedrive/Zendesk не трогаем.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { compileFilter, checkFilter, checkJsonDepth, weakensFilter, normalizeFilter, parseRoute } from '../src/core/filter.js';
import { parseFilter } from '../src/web/policy.js';
import { loadCatalog } from '../src/catalog.js';
import { buildApp } from '../src/app.js';
import { initI18n } from '../src/i18n.js';

initI18n('en');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-rest-'));
const HOST = 'api.restfx.test';

const HEAD = 'defaults:\n  maxBody: 2097152\n  timeout: 10\n  kind: static\n  fields: [key]\nproviders:\n';
/** Фикстура REST-провайдера; over подменяет куски текста для негативных проверок загрузки каталога. */
const fixture = (over = {}) => {
  const s = {
    deny: `[ 'ANY /crm/v3/objects/contacts/**', 'ANY /crm/v3/objects/companies/**', 'ANY /crm/v3/objects/*/batch/**', 'ANY /crm/v3/exports/**' ]`,
    routes: `[ 'GET /crm/v3/objects/deals', 'GET /crm/v3/objects/deals/:id' ]`,
    extras: `          extras:\n            search:\n              label: Search deals\n              routes: [ 'POST /crm/v3/objects/deals/search' ]\n`,
    style: 'rest',
    ...over,
  };
  return `${HEAD}  restfx:
    name: REST fixture
    host: ${HOST}
    injection: { type: header, name: authorization, prefix: 'Bearer ' }
    filter:
      style: ${s.style}
      keep: [status, message, category, correlationId, total, time, paging.next.after]
      deny: ${s.deny}
      denyQuery: [associations, propertiesWithHistory, archived]
      selectParam: properties
      selectFormat: comma
      selectFor: [ 'GET /crm/v3/objects/deals' ]
      entities:
        deals:
          name: Deals without contacts
          routes: ${s.routes}
${s.extras}          fields:
            - { paths: ['results[].id', 'id'], label: ID }
            - { paths: ['results[].properties.dealname', 'properties.dealname'], label: Title }
            - { paths: ['results[].properties.dealstage', 'properties.dealstage'], label: Stage }
            - { paths: ['results[].properties.createdate', 'properties.createdate'], label: Created }
          defaults: ['results[].id', 'id', 'results[].properties.dealstage', 'properties.dealstage']
`;
};
const writeYaml = (text) => { const file = path.join(tmp, `c-${crypto.randomBytes(4).toString('hex')}.yaml`); fs.writeFileSync(file, text); return file; };
const load = (text) => { try { return loadCatalog(writeYaml(text)); } catch (e) { return e.message; } };

const catalog = load(fixture());
if (typeof catalog === 'string') throw new Error(`фикстура не загружается: ${catalog}`);
const prov = catalog.get('restfx');

const SEL = ['results[].id', 'results[].properties.dealname', 'results[].properties.dealstage', 'results[].properties.createdate'];
const dealsOnly = { enabled: true, entities: { deals: SEL }, methods: [], fields: [] };
const compile = (over = {}) => compileFilter({ ...dealsOnly, ...over }, prov);
const f = compile();

// ---- 1. маршруты типа
test('1: GET deals и deals/:id разрешены типом, лишний или пропущенный сегмент и соседние маршруты — нет', () => {
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals'), true);
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/123'), true);
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/123/'), true, 'один хвостовой / отбрасывается');
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/123/associations/contacts'), false);
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/123/456'), false, ':id — ровно один сегмент');
  assert.equal(f.allowMethod('GET', '/crm/v3/objects'), false);
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/tickets'), false);
  assert.equal(f.allowMethod('HEAD', '/crm/v3/objects/deals/123'), true, 'HEAD совпадает с правилом GET');
  for (const m of ['OPTIONS', 'TRACE', 'CONNECT', 'FOO']) assert.equal(f.allowMethod(m, '/crm/v3/objects/deals'), false, m);
  assert.equal(f.allowMethod('GET', '//crm/v3/objects/deals'), false, '«//» в начале не равен одному «/»');
  assert.equal(f.allowMethod('GET', `/crm/v3/objects/deals/${'x'.repeat(129)}`), false, 'значение :id длиннее 128');
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/a$b'), false, 'значение :id вне [A-Za-z0-9_.~-]');
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/deals/a.b~c_d-e'), true);
  assert.deepEqual(f.methods, ['GET /crm/v3/objects/deals', 'GET /crm/v3/objects/deals/:id']);
});

// ---- 2. запись никогда не открывается типом или ручным правилом
test('2: POST/PATCH/DELETE → write_not_allowed и при типе, и при ручном GET /crm/v3/objects/*; ручное правило с POST — ошибка checkFilter', () => {
  for (const g of [f, compile({ entities: {}, methods: ['GET /crm/v3/objects/*'], fields: ['results[].id'] })]) {
    for (const [m, p] of [['POST', '/crm/v3/objects/deals'], ['PATCH', '/crm/v3/objects/deals/123'], ['DELETE', '/crm/v3/objects/deals/123'], ['PUT', '/crm/v3/objects/deals/123']]) {
      assert.equal(g.allowMethod(m, p), false, `${m} ${p}`);
      assert.equal(g.denyReason(m, p), 'write_not_allowed', `${m} ${p}`);
    }
  }
  assert.equal(f.denyReason('GET', '/crm/v3/objects/tickets'), 'method_not_allowed');
  assert.equal(f.denyReason('POST', '/crm/v3/objects/contacts/1'), 'method_not_allowed', 'deny сильнее');
  assert.equal(f.denyReason('GET', '/crm/v3/objects/deals'), null);
  // ручное правило с методом записи: ошибка формы; даже если запись всё же попала в хранилище, она не открывается
  const form = (m) => checkFilter({ enabled: true, entities: {}, methods: [m], fields: ['results[].id'] }, prov).join();
  assert.match(form('POST /crm/v3/objects/deals'), /cannot open write/);
  assert.match(form('DELETE /crm/v3/objects/deals/:id'), /cannot open write/);
  assert.equal(form('GET /crm/v3/objects/deals/*'), '');
  assert.match(form('/crm/v3/objects/deals'), /METHOD \/path/, 'метод обязателен');
  const stored = compile({ entities: {}, methods: ['POST /crm/v3/objects/deals'], fields: ['results[].id'] });
  assert.equal(stored.allowMethod('POST', '/crm/v3/objects/deals'), false);
  // маршрут записи в routes типа — ошибка загрузки каталога (запись только через extras)
  assert.match(load(fixture({ routes: `[ 'GET /crm/v3/objects/deals', 'POST /crm/v3/objects/deals' ]` })), /write method/);
});

// ---- 3. search только с флагом
test('3: POST deals/search закрыт без флага, открыт с flags.deals=[search]; флаг — ослабление', () => {
  const sp = '/crm/v3/objects/deals/search';
  assert.equal(f.allowMethod('POST', sp), false);
  assert.equal(f.denyReason('POST', sp), 'write_not_allowed');
  const g = compile({ flags: { deals: ['search'] } });
  assert.equal(g.allowMethod('POST', sp), true);
  assert.equal(g.allowMethod('PUT', sp), false);
  assert.equal(g.allowMethod('PATCH', sp), false);
  assert.equal(g.allowMethod('POST', '/crm/v3/objects/deals'), false, 'флаг открывает только свои маршруты');
  assert.ok(g.methods.includes('POST /crm/v3/objects/deals/search'));
  // тело ответа search режется теми же полями типа
  assert.deepEqual(g.filterBody({ results: [{ id: '1', properties: { email: 'x@y.z', dealstage: 's' } }] }, sp, 'POST').json, { results: [{ id: '1', properties: { dealstage: 's' } }] });
  // слабее/строже
  const cur = normalizeFilter(dealsOnly, prov);
  const withFlag = normalizeFilter({ ...dealsOnly, flags: { deals: ['search'] } }, prov);
  assert.equal(weakensFilter(withFlag, cur), true, 'новый флаг — свежий 2FA');
  assert.equal(weakensFilter(cur, withFlag), false, 'снятие флага — ужесточение');
  assert.equal(weakensFilter(withFlag, withFlag), false);
  // флаги без extras и неизвестные отбрасываются; закрытый тип флагов не держит
  assert.equal(normalizeFilter({ ...dealsOnly, flags: { deals: ['batch', 'search'], nope: ['search'] } }, prov).flags.deals.join(), 'search');
  assert.equal(normalizeFilter({ ...dealsOnly, flags: { deals: ['batch'] } }, prov).flags, undefined);
  const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
  assert.equal(normalizeFilter({ enabled: true, entities: { deals: ['result.ID'] }, flags: { deals: ['search'] }, methods: [], fields: [] }, bitrix).flags, undefined);
  // форма: галочка fl_<тип>, чужие значения отбрасываются
  assert.deepEqual(parseFilter({ entities_form: '1', enabled: '1', ent_deals: '1', f_deals: SEL, fl_deals: ['search', 'batch'] }, prov).flags, { deals: ['search'] });
  assert.equal(parseFilter({ entities_form: '1', enabled: '1', ent_deals: '1', f_deals: SEL }, prov).flags, undefined);
});

// ---- 4. deny на любой глубине, «**» только в deny
test('4: ручное GET /crm/v3/objects/* не открывает contacts на любой глубине; «**» вне deny — ошибка', () => {
  const g = compile({ entities: {}, methods: ['GET /crm/v3/objects/*', 'GET /crm/v3/objects/*/*', 'GET /crm/v3/objects/*/*/*/*'], fields: ['results[].id'] });
  assert.equal(g.allowMethod('GET', '/crm/v3/objects/tickets'), true);
  assert.equal(g.allowMethod('GET', '/crm/v3/objects/tickets/5'), true);
  for (const p of ['/crm/v3/objects/contacts', '/crm/v3/objects/contacts/123', '/crm/v3/objects/contacts/123/x', '/crm/v3/objects/CONTACTS/1/2/3/4/5', '/crm/v3/objects/companies/1',
    '/crm/v3/objects/deals/batch/read', '/crm/v3/objects/tickets/batch/read', '/crm/v3/exports', '/crm/v3/exports/1/2']) {
    assert.equal(g.allowMethod('GET', p), false, p);
    assert.equal(g.allowMethod('POST', p), false, `POST ${p}`);
  }
  const form = (m) => checkFilter({ enabled: true, entities: {}, methods: [m], fields: ['results[].id'] }, prov).join();
  assert.match(form('GET /crm/v3/objects/**'), /only in always-blocked/);
  assert.match(form('GET /crm/v3/**/x'), /only in always-blocked/);
  assert.match(form('GET /crm/v3/objects/contacts/:id'), /always blocked/, 'ручное правило поверх deny — ошибка формы');
  assert.equal(form('GET /crm/v3/objects/tickets/:id'), '');
  // ** вне deny и «звезда внутри сегмента» не принимает и каталог
  assert.match(load(fixture({ routes: `[ 'GET /crm/v3/objects/**' ]` })), /route "GET \/crm\/v3\/objects\/\*\*" is not allowed \(rest\)/);
  assert.match(load(fixture({ routes: `[ 'GET /crm/v3/ob*ects' ]` })), /not allowed \(syntax\)/);
  assert.match(load(fixture({ deny: `[ 'ANY /a/**/b' ]` })), /not allowed \(syntax\)/);
  assert.equal(typeof load(fixture({ deny: `[ 'ANY /a/**', 'POST /b' ]` })), 'object');
  // негодный deny при выполнении закрывает всё
  const broken = { ...prov, filter: { ...prov.filter, deny: ['garbage'] } };
  assert.equal(compileFilter(dealsOnly, broken).allowMethod('GET', '/crm/v3/objects/deals'), false);
});

// ---- 5. plainPath
test('5: «.», «..», %-последовательности и пустые сегменты отклоняются', () => {
  for (const p of ['/crm/v3/objects/deals/./x', '/crm/v3/objects/deals/../contacts', '/crm/v3/objects/deals/%2e/x', '/crm/v3/objects/deals/%2e%2e/contacts',
    '/crm/v3/objects/deals//x', '/crm/v3/objects//deals', '/crm/v3/objects/deals/%2564']) {
    assert.equal(f.allowMethod('GET', p), false, p);
    assert.equal(compile({ entities: {}, methods: ['GET /crm/v3/objects/*/*'], fields: ['results[].id'] }).allowMethod('GET', p), false, `ручное ${p}`);
  }
  // значение :id «.» и «..» не совпадает и в обход plainPath
  assert.equal(compileFilter(dealsOnly, prov).allowMethod('GET', '/crm/v3/objects/deals/..'), false);
});

// ---- 6. регистр
test('6: литералы без учёта регистра, значения :id как есть', () => {
  assert.equal(f.allowMethod('GET', '/CRM/V3/Objects/Deals'), true);
  assert.equal(f.allowMethod('get', '/CRM/V3/Objects/Deals/AbC'), true, 'метод тоже без учёта регистра');
  assert.equal(f.allowMethod('GET', '/crm/v3/objects/CONTACTS'), false);
  const r = parseRoute('GET /Crm/V3/:Id');
  assert.deepEqual(r.segs, [{ t: 'lit', v: 'crm' }, { t: 'lit', v: 'v3' }, { t: 'param' }], 'шаблон хранит литералы в нижнем регистре, значение :id не хранится');
  // значение сегмента доходит до сервиса без изменений (проверяется сквозным вызовом ниже, тест 13: путь AbC)
});

// ---- 7. Bitrix24 не сломан
test('7: Bitrix24 (rpc, methodAgnostic): GET и POST равнозначны, запись типом не режется', () => {
  const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
  const g = compileFilter({ enabled: true, entities: { deals: ['result.ID'] }, methods: [], fields: [] }, bitrix);
  for (const m of ['GET', 'POST']) {
    assert.equal(g.allowMethod(m, '/crm.deal.list.json'), true, m);
    assert.equal(g.allowMethod(m, '/crm.deal.list'), true, m);
    assert.equal(g.allowMethod(m, '/crm.contact.list'), false, m);
    assert.equal(g.allowMethod(m, '/batch'), false, m);
    assert.equal(g.denyReason(m, '/crm.contact.list'), 'method_not_allowed');
  }
  assert.equal(g.allowMethod('/crm.deal.list.json'), true, 'старый вызов allowMethod(путь) работает');
  assert.equal(g.checkQuery('GET', '/crm.deal.list', '?select[]=PHONE'), null);
  assert.deepEqual(g.filterBody({ result: [{ ID: '1', PHONE: 'x' }] }, '/crm.deal.list', 'POST'), { json: { result: [{ ID: '1' }] }, removed: 1, masked: 0 });
  // select[] у Bitrix24 по-прежнему повторяющийся, а не через запятую
  assert.match(g.rewriteSelect('/crm.deal.list', '?select=PHONE', null, '', 'POST').query, /^\?select%5B%5D=ID$/);
});

// ---- 8. лимиты
test('8: 65 правил, 13 сегментов, шаблон 201 символ — ошибка каталога или checkFilter; rpc: три «*»', () => {
  const many = Array.from({ length: 65 }, (_, i) => `'GET /v1/r${i}'`).join(', ');
  assert.match(load(fixture({ routes: `[ ${many} ]` })), /at most 64 rules/);
  const ok64 = Array.from({ length: 64 }, (_, i) => `'GET /v1/r${i}'`).join(', ');
  assert.equal(typeof load(fixture({ routes: `[ ${ok64} ]`, extras: '' })), 'object');
  assert.match(load(fixture({ routes: `[ 'GET /${Array(13).fill('a').join('/')}' ]` })), /\(segments\)/);
  assert.match(load(fixture({ routes: `[ 'GET /${'a'.repeat(201)}' ]` })), /\(length\)/);
  assert.match(load(fixture({ deny: `[ 'ANY /${Array(13).fill('a').join('/')}' ]` })), /\(segments\)/);
  assert.match(load(fixture({ deny: `[ ${Array.from({ length: 65 }, (_, i) => `'ANY /d${i}'`).join(', ')} ]` })), /filter\.deny: at most 64/);
  assert.equal(typeof load(fixture({ routes: `[ 'GET /${Array(12).fill('a').join('/')}' ]` })), 'object', '12 сегментов можно');
  // метод и тип стиля
  assert.match(load(fixture({ routes: `[ 'FETCH /a' ]` })), /\(method\)/);
  assert.match(load(fixture({ routes: `[ '/a' ]` })), /\(syntax\)/);
  assert.match(load(fixture({ style: 'graphql' })), /style/);
  // ручные правила в checkFilter
  const form = (m) => checkFilter({ enabled: true, entities: {}, methods: [m], fields: ['results[].id'] }, prov).join();
  assert.match(form(`GET /${Array(13).fill('a').join('/')}`), /at most 12 segments/);
  assert.match(form(`GET /${'a'.repeat(201)}`), /at most 12 segments and 200/);
  assert.equal(form(`GET /${Array(12).fill('a').join('/')}`), '');
  // 65 ручных шаблонов
  const sixtyFive = Array.from({ length: 65 }, (_, i) => `GET /v1/r${i}`);
  assert.match(checkFilter({ enabled: true, entities: {}, methods: sixtyFive, fields: ['results[].id'] }, prov).join(), /Too many method patterns/);
  // rpc: три звезды (Bitrix24)
  const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
  assert.match(checkFilter({ enabled: true, entities: {}, methods: ['a*b*c*d'], fields: ['result.ID'] }, bitrix).join(), /at most 2 asterisks/);
  // при выполнении 65-е правило сверх лимита ничего не открывает
  const over = compile({ entities: {}, methods: sixtyFive, fields: ['results[].id'] });
  assert.equal(over.allowMethod('GET', '/v1/r0'), true);
  assert.equal(over.allowMethod('GET', '/v1/r64'), false);
});

// ---- 9. время
// лучший из прогонов: набор идёт параллельно с другими файлами, разовый скачок нагрузки не должен ронять тест (ReDoS медленный всегда)
const measure = (fn, runs = 5) => { let best = Infinity; for (let i = 0; i < runs; i++) { const s = process.hrtime.bigint(); fn(); best = Math.min(best, Number(process.hrtime.bigint() - s) / 1e6); } return best; };

test('9: 12-сегментный шаблон против 13-сегментного пути < 5 мс; rpc a*a* против 100 000 «a» < 50 мс (ReDoS, П-28)', () => {
  const twelve = Array(12).fill('a').join('/');
  const seg = compile({ entities: {}, methods: [`GET /${twelve}`, 'GET /*/*/*/*/*/*/*/*/*/*/*/*'], fields: ['results[].id'] });
  const longPath = `/${'a/'.repeat(12)}x`;
  assert.equal(seg.allowMethod('GET', longPath), false);
  assert.equal(seg.allowMethod('GET', `/${twelve}`), true);
  assert.ok(measure(() => seg.allowMethod('GET', longPath)) < 5, '12 сегментов < 5 мс');
  const longSeg = `/${'a'.repeat(100000)}`;
  assert.ok(measure(() => seg.allowMethod('GET', longSeg)) < 50, 'один очень длинный сегмент');
  assert.ok(measure(() => seg.allowMethod('GET', `/${Array(12).fill('a'.repeat(5000)).join('/')}`)) < 50, 'двенадцать длинных сегментов');
  const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
  const star = compileFilter({ enabled: true, entities: {}, methods: ['a*a*'], fields: ['result.ID'] }, bitrix);
  const hay = `/${'a'.repeat(100000)}`;
  assert.equal(star.allowMethod('POST', hay), true);
  assert.ok(measure(() => star.allowMethod('POST', hay)) < 50, 'a*a* на 100 000 символов < 50 мс');
  assert.ok(measure(() => star.allowMethod('POST', `${hay}b`)) < 50, 'промах тоже линеен');
});

// ---- 10 (глубина JSON), 11 (поля), 12 (скаляры), 13 (denyQuery), 14 (П-18): модуль и сквозной вызов
test('10: глубина JSON 33 — не проходит, 32 проходит, скобки внутри строк не считаются (проход по байтам)', () => {
  const arr = (n) => Buffer.from('['.repeat(n) + ']'.repeat(n));
  assert.equal(checkJsonDepth(arr(32)), true);
  assert.equal(checkJsonDepth(arr(33)), false);
  assert.equal(checkJsonDepth(Buffer.from(JSON.stringify({ a: '['.repeat(500) + '{'.repeat(500), b: '\\"[[[[' }))), true);
  assert.equal(checkJsonDepth(Buffer.from('{"a":' + '['.repeat(31) + '"]"' + ']'.repeat(31) + '}')), true);
});

test('11: results[].properties.dealstage остаётся, email/associations/contacts вырезаются, removed верный; одиночная форма тоже', () => {
  const list = f.filterBody({
    results: [{ id: '1', properties: { dealname: 'A', dealstage: 'won', email: 'x@y.z', createdate: 'd', hs_object_id: '1' }, associations: { contacts: { results: [{ id: '9' }] } }, contacts: [{ id: '9' }] }],
    total: 1, paging: { next: { after: '2', link: 'https://x' } },
  }, '/crm/v3/objects/deals', 'GET');
  assert.deepEqual(list.json, { results: [{ id: '1', properties: { dealname: 'A', dealstage: 'won', createdate: 'd' } }], total: 1, paging: { next: { after: '2' } } });
  assert.equal(list.removed, 5, 'email, hs_object_id, associations, contacts, paging.next.link');
  const one = f.filterBody({ id: '5', properties: { dealstage: 's', email: 'e' }, associations: { x: 1 } }, '/crm/v3/objects/deals/5', 'GET');
  assert.deepEqual(one.json, { id: '5', properties: { dealstage: 's' } });
  assert.equal(one.removed, 2);
  // отмеченное поле с paths открывает обе формы; без отметки закрыты обе
  const none = compile({ entities: { deals: ['results[].id'] } }).filterBody({ results: [{ id: '1', properties: { dealstage: 's' } }], id: '2', properties: { dealstage: 's' } }, '/crm/v3/objects/deals', 'GET');
  assert.deepEqual(none.json, { results: [{ id: '1' }], id: '2' });
});

test('12: П-27 — объект без object:true вырезается, строка 5000 обрезается, time в keep вырезается, status остаётся; PHONE Bitrix24 с object:true — массив', () => {
  const g = compileFilter({ enabled: true, entities: { deals: SEL }, methods: [], fields: [] }, { ...prov, filter: { ...prov.filter, keep: ['status', 'message'] } });
  const r = g.filterBody({
    status: 'error', message: { nested: true }, time: { start: 1 },
    results: [{ id: { x: 1 }, properties: { dealname: 'n'.repeat(5000), dealstage: ['a'], createdate: null } }],
  }, '/crm/v3/objects/deals', 'GET');
  assert.equal(r.json.status, 'error');
  assert.ok(!('message' in r.json) && !('time' in r.json));
  assert.ok(!('id' in r.json.results[0]));
  assert.equal(r.json.results[0].properties.dealname.length, 4000, 'maxFieldLen по умолчанию');
  assert.ok(!('dealstage' in r.json.results[0].properties));
  assert.equal(r.json.results[0].properties.createdate, null);
  assert.equal(r.removed, 5, 'message, time, results[].id, dealstage и обрезка dealname');
  const bitrix = loadCatalog(path.join(root, 'providers.yaml')).get('bitrix24');
  const leads = compileFilter({ enabled: true, entities: { leads: ['result.ID', 'result.PHONE'] }, methods: [], fields: [] }, bitrix);
  const phone = [{ VALUE: '+7 999', VALUE_TYPE: 'WORK' }];
  assert.deepEqual(leads.filterBody({ result: [{ ID: '1', PHONE: phone }] }, '/crm.lead.list', 'POST').json, { result: [{ ID: '1', PHONE: phone }] });
});

test('13 (модуль): denyQuery и selectFormat comma', () => {
  const p = '/crm/v3/objects/deals';
  for (const q of ['?associations=contacts', '?Associations=contacts', '?limit=5&associations[0]=contacts', '?associations%5B%5D=x', '?%61ssociations=1', '?propertiesWithHistory=email', '?archived=true', '?associations']) {
    assert.equal(f.checkQuery('GET', p, q), 'query_not_allowed', q);
  }
  for (const q of ['', '?limit=5', '?properties=email', '?after=abc']) assert.equal(f.checkQuery('GET', p, q), null, q);
  for (const q of ['?properties=email,phone&limit=5', '?properties[]=email&Properties=phone&properties[1]=x&limit=5', '?PROPERTIES=email&limit=5']) {
    const sp = new URLSearchParams(f.rewriteSelect(p, q, null, '', 'GET').query.slice(1));
    assert.equal(sp.get('properties'), 'dealname,dealstage,createdate', q);
    assert.deepEqual([...sp.keys()].filter((k) => /^properties/i.test(k)), ['properties'], 'других форм не осталось');
    assert.equal(sp.get('limit'), '5');
  }
  // у одиночной сделки и вне selectFor query не меняется (поля режет prune)
  assert.equal(f.rewriteSelect(`${p}/5`, '?properties=email', null, '', 'GET').query, '?properties=email');
  // нет ни одного поля properties — параметр убирается, а не пустой
  const noProps = compile({ entities: { deals: ['results[].id'] } });
  assert.equal(noProps.rewriteSelect(p, '?properties=email&limit=2', null, '', 'GET').query, '?limit=2');
});

test('14: П-18 — checkQuery по скрытым полям в 1.0 возвращает null (заглушка фиксирует контракт)', () => {
  const p = '/crm/v3/objects/deals';
  for (const q of ['?filter[email]=a@b.c', '?sort=email', '?filter_id=7', '?order=email&filterGroups[0][filters][0][propertyName]=email']) assert.equal(f.checkQuery('GET', p, q), null, q);
  assert.equal(compile({ flags: { deals: ['search'] } }).checkQuery('POST', `${p}/search`, '?sort=phone'), null);
});

// ---- сквозной вызов через proxy.call: порядок шагов, 403/400, лимит не тратится, поля, глубина
let app, mock, seen = [];
let seq = 0;
const SECRET = `tok_${crypto.randomBytes(12).toString('hex')}`; // фальшивый ключ собирается в рантайме
const nowSec = () => Math.floor(Date.now() / 1000);
const DEALS = { results: [{ id: '1', properties: { dealname: 'A', dealstage: 'won', email: 'x@y.z' }, associations: { contacts: { results: [{ id: '9' }] } } }], total: 1 };

before(async () => {
  mock = http.createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: data });
      res.setHeader('content-type', 'application/json');
      const mode = req.headers['x-mode'];
      if (mode === 'deep33') return res.end('['.repeat(33) + ']'.repeat(33));
      if (mode === 'deep32') return res.end('['.repeat(32) + ']'.repeat(32));
      if (mode === 'strbrackets') return res.end(JSON.stringify({ results: [{ id: '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[' }] }));
      res.end(JSON.stringify(DEALS));
    });
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-restapp-'));
  app = await buildApp({
    dataDir, dbPath: path.join(dataDir, 'gw.db'), vaultFile: path.join(dataDir, 'vault.json'), masterKeyFile: path.join(dataDir, 'master.key'),
    catalogPath: writeYaml(fixture()), lang: 'en', port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1', logLevel: 'silent',
    testUpstream: { [HOST]: `http://127.0.0.1:${mock.address().port}` },
  });
  await app.start();
});
after(async () => { await app.stop(); mock.close(); mock.closeAllConnections?.(); });

/** Агент + ключ restfx с фильтром + пропуск. */
async function mkGrant(filter) {
  const n = ++seq;
  const agentId = `ra${n}`; const credId = `rc${n}`;
  app.repo.createAgent({ id: agentId, name: `a${n}`, token_hash: crypto.createHash('sha256').update(`gwa_rest_${n}`).digest('hex'), enabled: 1 });
  app.repo.createCredential({
    id: credId, provider: 'restfx', label: `k${n}`, kind: 'static', host: HOST, injection: { type: 'header', name: 'authorization', prefix: 'Bearer ' },
    vault_param: `cred/${credId}`, last4: SECRET.slice(-4), max_parallel: 3,
  });
  if (filter) app.repo.updateCredentialFilter(credId, filter);
  await app.ctx.vault.put(`cred/${credId}`, SECRET);
  const req = { id: `rr${n}`, agent_id: agentId, credential_id: credId, ttl: 3000, calls: 1000, reason: '', expires_at: nowSec() + 3000 };
  app.repo.createRequest(req);
  const { grant, token } = app.ctx.grants.issue(req, app.repo.getCredential(credId));
  return { id: grant.id, token, agentId };
}
const call = (g, over = {}) => app.ctx.proxy.call({ token: g.token, provider: 'restfx', method: 'GET', path: '/crm/v3/objects/deals', query: '', headers: {}, body: null, contentLength: null, via: 'rest', ...over });
const text = async (r) => { const chunks = []; for await (const c of r.body) chunks.push(c); return Buffer.concat(chunks).toString('utf8'); };
const used = (g) => app.repo.getGrant(g.id).calls_used;

test('сквозной: чтение проходит, поля режутся, query/properties подменены, значение :id и регистр доходят до сервиса как есть', async () => {
  const g = await mkGrant(dealsOnly);
  seen = [];
  let r = await call(g, { query: '?properties=email,phone&limit=3' });
  assert.equal(r.ok, true);
  assert.deepEqual(JSON.parse(await text(r)), { results: [{ id: '1', properties: { dealname: 'A', dealstage: 'won' } }], total: 1 });
  const sp = new URLSearchParams(seen.at(-1).url.split('?')[1]);
  assert.equal(sp.get('properties'), 'dealname,dealstage,createdate');
  assert.equal(sp.get('limit'), '3');
  assert.equal(seen.at(-1).method, 'GET');
  r = await call(g, { path: '/CRM/v3/objects/Deals/AbC' });
  assert.equal(r.ok, true); await text(r);
  assert.equal(seen.at(-1).url, '/CRM/v3/objects/Deals/AbC', 'путь агента без изменений');
  const audit = app.repo.listAudit({ limit: 20 }).find((x) => x.action === 'proxy.call');
  assert.ok(JSON.parse(audit.meta_json).fields_removed >= 1);
});

test('сквозной: запись → 403 write_not_allowed, закрытый маршрут → 403 method_not_allowed, query → 400; лимит не тратится, сервис не вызван, audit proxy.denied', async () => {
  const g = await mkGrant(dealsOnly);
  seen = [];
  const before = used(g);
  const cases = [
    { method: 'POST', path: '/crm/v3/objects/deals', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { method: 'PATCH', path: '/crm/v3/objects/deals/1', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { method: 'DELETE', path: '/crm/v3/objects/deals/1', status: 403, error: 'write_not_allowed' },
    { method: 'POST', path: '/crm/v3/objects/deals/search', body: Buffer.from('{}'), status: 403, error: 'write_not_allowed' },
    { method: 'GET', path: '/crm/v3/objects/contacts', status: 403, error: 'method_not_allowed' },
    { method: 'GET', path: '/crm/v3/objects/deals/1/associations/contacts', status: 403, error: 'method_not_allowed' },
    { method: 'OPTIONS', path: '/crm/v3/objects/deals', status: 403, error: 'method_not_allowed' },
    { method: 'GET', path: '/crm/v3/objects/deals', query: '?associations=contacts', status: 400, error: 'query_not_allowed' },
    { method: 'GET', path: '/crm/v3/objects/deals/1', query: '?propertiesWithHistory=email', status: 400, error: 'query_not_allowed' },
  ];
  for (const c of cases) {
    const r = await call(g, c);
    assert.deepEqual([r.ok, r.status, r.error], [false, c.status, c.error], `${c.method} ${c.path}${c.query || ''}`);
    if (c.status === 403) assert.ok(r.extra.allowed.includes('GET /crm/v3/objects/deals'));
  }
  assert.equal(seen.length, 0, 'до сервиса не дошло');
  assert.equal(used(g), before, 'лимит не потрачен');
  const denied = app.repo.listAudit({ limit: 50 }).filter((x) => x.action === 'proxy.denied');
  assert.ok(denied.length >= 1);
  assert.ok(denied.some((x) => JSON.parse(x.meta_json).denied_reason === 'write_not_allowed'));
});

test('сквозной: search с флагом доходит до сервиса, ответ режется полями типа; без флага — 403', async () => {
  const g = await mkGrant({ ...dealsOnly, flags: { deals: ['search'] } });
  seen = [];
  const body = Buffer.from(JSON.stringify({ filterGroups: [] }));
  const r = await call(g, { method: 'POST', path: '/crm/v3/objects/deals/search', body, contentLength: body.length, headers: { 'content-type': 'application/json' } });
  assert.equal(r.ok, true);
  assert.equal(seen.at(-1).method, 'POST');
  assert.deepEqual(JSON.parse(await text(r)).results[0].properties, { dealname: 'A', dealstage: 'won' });
  const g2 = await mkGrant(dealsOnly);
  assert.equal((await call(g2, { method: 'POST', path: '/crm/v3/objects/deals/search', body, contentLength: body.length })).error, 'write_not_allowed');
});

test('сквозной (10): глубина ответа 33 → 502 filtered_too_deep, 32 и скобки в строках проходят', async () => {
  const g = await mkGrant(dealsOnly);
  let r = await call(g, { headers: { 'x-mode': 'deep33' } });
  assert.deepEqual([r.ok, r.status, r.error], [false, 502, 'filtered_too_deep']);
  r = await call(g, { headers: { 'x-mode': 'deep32' } });
  assert.equal(r.ok, true); await text(r);
  r = await call(g, { headers: { 'x-mode': 'strbrackets' } });
  assert.equal(r.ok, true);
  assert.match(JSON.parse(await text(r)).results[0].id, /^\[{40,}$/);
});

test('сквозной: фильтр выключен — запрос идёт как раньше (запись режет только readOnly, пункт 7.2; rpc-ветка проверена в 7 и filter-e2e)', async () => {
  const g = await mkGrant(null);
  const r = await call(g, { method: 'POST', path: '/crm/v3/objects/deals', body: Buffer.from('{}'), contentLength: 2, headers: { 'content-type': 'application/json' } });
  assert.equal(r.ok, true, 'фильтр выключен — запись не режется (отдельный слой readOnly, пункт 7.2)');
  await text(r);
});
