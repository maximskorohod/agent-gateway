// Встроенный сервис «Demo CRM» для демо-режима (GW_DEMO=1): отвечает в процессе, сокеты не открываются.
// Данные вымышленные (домен .invalid и номера из диапазона 555-01xx не принадлежат никому).
import { Readable } from 'node:stream';

/** Хост демо-сервиса: зарезервированный TLD .invalid не резолвится. */
export const DEMO_HOST = 'demo.invalid';
/** Заголовок, в который шлюз подставляет ключ (providers.yaml → demo). */
export const DEMO_KEY_HEADER = 'x-demo-key';
const KEY_RE = /^demo-[a-z0-9]{8,32}$/;
const MAX_BODY = 65536;

const DEALS = [
  { ID: '1', TITLE: 'Website redesign', STAGE_ID: 'NEW', OPPORTUNITY: '12000', CURRENCY_ID: 'USD', COMMENTS: 'Client asked for a call on Monday', CONTACT_ID: '1' },
  { ID: '2', TITLE: 'Annual support contract', STAGE_ID: 'PREPARATION', OPPORTUNITY: '4800', CURRENCY_ID: 'USD', COMMENTS: 'Waiting for the signed copy', CONTACT_ID: '2' },
  { ID: '3', TITLE: 'Mobile app pilot', STAGE_ID: 'WON', OPPORTUNITY: '30000', CURRENCY_ID: 'EUR', COMMENTS: 'Paid in full', CONTACT_ID: '3' },
  { ID: '4', TITLE: 'Data migration', STAGE_ID: 'LOSE', OPPORTUNITY: '7500', CURRENCY_ID: 'EUR', COMMENTS: 'Went with another vendor', CONTACT_ID: '1' },
];
const CONTACTS = [
  { ID: '1', NAME: 'Alice', LAST_NAME: 'Example', PHONE: '+1 555 0100', EMAIL: 'alice@example.invalid', COMMENTS: 'Prefers e-mail' },
  { ID: '2', NAME: 'Bob', LAST_NAME: 'Sample', PHONE: '+1 (555) 010-0111', EMAIL: 'bob@example.invalid', COMMENTS: 'Card on file 4111 1111 1111 1111 (fake)' },
  { ID: '3', NAME: 'Carol', LAST_NAME: 'Demo', PHONE: '+1 555 0122', EMAIL: 'carol@example.invalid', COMMENTS: '' },
];
const TABLES = { deals: DEALS, contacts: CONTACTS };

const json = (status, obj) => ({
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' },
  body: Readable.from([Buffer.from(JSON.stringify(obj), 'utf8')]),
});

/** Вычитывает тело запроса (поток, Buffer или ничего) не больше MAX_BODY: поток нужно дочитать, иначе зависнет конвейер прокси. */
async function drain(body) {
  if (body == null) return;
  if (Buffer.isBuffer(body) || typeof body === 'string') return;
  let n = 0;
  for await (const c of body) { n += c.length; if (n > MAX_BODY) throw Object.assign(new Error('body too large'), { code: 'EBODY' }); }
}

/**
 * Мок демо-сервиса. handle({ method, path, headers, body }) -> { status, headers, body: Readable }.
 * path — путь с query. Ключ проверяется по заголовку x-demo-key и в ответ не попадает.
 */
export function createDemoMock() {
  return {
    async handle({ method = 'GET', path = '/', headers = {}, body } = {}) {
      await drain(body);
      const key = String(headers[DEMO_KEY_HEADER] ?? '');
      if (!KEY_RE.test(key)) return json(401, { error: 'invalid_key' });
      const clean = String(path).split('?')[0].replace(/\/+$/, '') || '/';
      const [, name, id, ...rest] = clean.split('/');
      const m = String(method).toUpperCase();
      if (clean === '/ping') return json(200, { ok: true, service: 'demo' });
      const table = Object.hasOwn(TABLES, name ?? '') ? TABLES[name] : null;
      if (!table || rest.length) return json(404, { error: 'not_found' });
      if (m === 'GET' && id === undefined) return json(200, { result: table, total: table.length });
      if (m === 'GET') {
        const row = table.find((r) => r.ID === id);
        return row ? json(200, { result: row }) : json(404, { error: 'not_found' });
      }
      // записи демо-сервис принимает, но ничего не хранит
      if (m === 'POST' && id === undefined) return json(201, { result: { ID: String(table.length + 1) }, demo: true });
      return json(405, { error: 'method_not_allowed' });
    },
  };
}
