// Демо-режим GW_DEMO=1 (П-20): на публичном экземпляре физически нет реальных данных и нет исходящих соединений.
// Контракт: docs/contracts/rest-demo-notify.md, «Демо-режим». Слои: запуск (assertDemoIsolation), транспорт прокси
// (createDemoTransport), вторая линия сети (installNetworkGuard), allowlist запросов (demoRouteGuard); третья линия — сервер (docs/DEPLOY.md).
import fs from 'node:fs';
import net from 'node:net';
import dns from 'node:dns';
import path from 'node:path';
import { Agent, setGlobalDispatcher } from 'undici';
import { createRepo } from '../db/repo.js';
import { createLimiter } from '../core/ratelimit.js';
import { errorPage } from '../web/views/error.js';
import { clientKey } from '../web/client-key.js';
import { t } from '../i18n.js';
import { createDemoMock, DEMO_HOST } from './mock.js';
import { createDemoReset, DEMO_AGENT_ID, DEMO_CREDENTIAL_ID, DEMO_KEY_PATTERN } from './reset.js';

export { createDemoMock, createDemoReset };

export const DEMO_MARKER = '.demo-data';
const NET_DISABLED = 'demo_network_disabled';
const MAX_BODY = 64 * 1024;
// Лимиты создания считаются на посетителя (IP) с момента последнего сброса: сид (демо-ключ и демо-агент) не в счёт.
// Общий потолок в базе не закрывает создание: сверх него удаляются самые старые объекты посетителей (посевные остаются).
const MAX_KEYS = 3;
const MAX_AGENTS = 5;
const TOTAL_KEYS = 30;
const TOTAL_AGENTS = 50;
const TRACK_MAX = 10000;
// Общая частота создания на весь демо (любые адреса): только от потока, данные ограничивает потолок выше
const CREATE_GLOBAL_MAX = 120;
const CREATE_GLOBAL_WINDOW_SEC = 600;
const MAX_LABEL = 40;
// Файлы, которые шлюз сам создаёт в каталоге данных до проверки (openDb, createVault)
const OWN_FILES = new Set(['gw.db', 'gw.db-wal', 'gw.db-shm', 'gw.db-journal', 'master.key', 'vault.json', 'vault.json.tmp']);

const netDisabled = () => Object.assign(new Error(NET_DISABLED), { code: NET_DISABLED });

// ---- запуск: отказ при реальных данных

/**
 * Каталог данных пуст или помечен .demo-data. Вызывается в buildApp ДО openDb/createVault, пока шлюз ничего не создал.
 * @throws {Error} 'demo_isolation: data_dir_not_empty'
 */
export function assertDemoDataDirFresh(dataDir) {
  if (!fs.existsSync(dataDir)) return;
  if (fs.existsSync(path.join(dataDir, DEMO_MARKER))) return;
  if (fs.readdirSync(dataDir).length) throw new Error('demo_isolation: data_dir_not_empty');
}

/**
 * Проверка изоляции демо. Бросает Error('demo_isolation: <правило>') — bin/gateway.js выходит с кодом 1 до listen().
 * В тексте только имя правила и cred/<id>, значений секретов нет.
 * @param {{ cfg:object, db:object, vault:object, env?:object, repo?:object }} ctx env — переменные окружения (по умолчанию process.env)
 */
export async function assertDemoIsolation({ cfg, db, vault, env = process.env, repo = null }) {
  const refuse = (rule, extra = '') => { throw new Error(`demo_isolation: ${rule}${extra ? ` ${extra}` : ''}`); };
  // 1. сейф только file, никаких облачных переменных
  if (cfg.vault !== 'file') refuse('vault_not_file');
  if (Object.keys(env).some((k) => k.startsWith('AWS_') || k.startsWith('GW_SSM_') || k === 'GW_VAULT_PREFIX')) refuse('cloud_env');
  // 5. страховка: публичный адрес не из списка боевых хостов
  let host = '';
  try { host = new URL(cfg.publicUrl).hostname.toLowerCase(); } catch { /* пустой адрес не совпадёт ни с чем */ }
  if (host && (cfg.prodHosts || []).includes(host)) refuse('public_url_is_prod');
  // 2. каталог данных задан явно и либо чистый, либо с маркером
  if (!cfg.dataDirExplicit) refuse('data_dir_not_explicit');
  const marker = path.join(cfg.dataDir, DEMO_MARKER);
  if (!fs.existsSync(marker)) {
    if (fs.readdirSync(cfg.dataDir).some((n) => !OWN_FILES.has(n))) refuse('data_dir_not_empty');
    fs.writeFileSync(marker, 'demo\n', { mode: 0o600 });
  }
  // 3. сейф: только sys/* и cred/demo; каналы уведомлений и Telegram запрещены
  if (typeof vault.names !== 'function') refuse('vault_not_enumerable');
  const names = await vault.names();
  if (names.some((n) => n === 'sys/slack_webhook' || n === 'sys/smtp' || n.startsWith('sys/tg'))) refuse('vault_channel_secret');
  const store = repo ?? createRepo(db, { demo: true });
  // Ключ, добавленный посетителем до перезапуска: запись провайдера demo в базе и значение формата demo-…; сброс на старте его удалит
  const isVisitorKey = async (n) => {
    const m = /^cred\/([A-Za-z0-9_-]{1,64})$/.exec(n);
    if (!m || store.getCredential(m[1])?.provider !== 'demo') return false;
    return DEMO_KEY_PATTERN.test(String(await vault.get(n)));
  };
  const foreign = [];
  for (const n of names) {
    if (n.startsWith('sys/') || n === `cred/${DEMO_CREDENTIAL_ID}`) continue;
    if (!(await isVisitorKey(n))) foreign.push(n);
  }
  if (foreign.length) refuse('vault_foreign_name', foreign.filter((n) => /^cred\/[A-Za-z0-9_-]{1,64}$/.test(n)).join(' '));
  // 4. база: ни одного чужого ключа (даже удалённого), Telegram, каналов, пароля владельца
  const facts = store.demoIsolationFacts();
  if (facts.foreignCredentialIds.length) refuse('db_foreign_credential', facts.foreignCredentialIds.map((id) => `cred/${id}`).join(' '));
  if (facts.ownerTelegram) refuse('db_owner_telegram');
  if (facts.notifyMeta) refuse('db_notify_settings');
  if (facts.ownerPassword) refuse('db_owner_password');
}

// ---- сеть: вторая линия

let installed = null;

/**
 * Process-wide защита от исходящих соединений: любой net.Socket.connect (и loopback тоже), dns.lookup/resolve*
 * для имён, глобальный диспетчер undici. Входящий listen не затронут (accept не вызывает connect, lookup IP-литералов пропускается).
 * Повторный вызов ничего не меняет. -> { attempts() } — сколько попыток соединения заблокировано (тесты, диагностика).
 */
export function installNetworkGuard() {
  if (installed) return installed;
  let attempts = 0;
  net.Socket.prototype.connect = function blockedConnect() {
    attempts += 1;
    const e = netDisabled();
    process.nextTick(() => this.destroy(e));
    return this;
  };
  // lookup: IP-литералы проходят без сети (net.Server.listen вызывает lookup и для адреса прослушивания), имена блокируются
  const origLookup = dns.lookup;
  dns.lookup = function blockedLookup(hostname, ...rest) {
    if (net.isIP(String(hostname))) return origLookup.call(dns, hostname, ...rest);
    attempts += 1;
    const cb = rest.find((x) => typeof x === 'function');
    if (cb) { process.nextTick(cb, netDisabled()); return {}; }
    throw netDisabled();
  };
  const origPLookup = dns.promises.lookup;
  dns.promises.lookup = function blockedPLookup(hostname, ...rest) {
    if (net.isIP(String(hostname))) return origPLookup.call(dns.promises, hostname, ...rest);
    attempts += 1;
    return Promise.reject(netDisabled());
  };
  for (const m of ['resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveTxt', 'resolveSrv', 'resolvePtr', 'resolveNaptr', 'resolveSoa', 'resolveCaa', 'reverse']) {
    if (typeof dns[m] === 'function') dns[m] = (...a) => { attempts += 1; const cb = a.find((x) => typeof x === 'function'); if (cb) process.nextTick(cb, netDisabled()); else throw netDisabled(); };
    if (typeof dns.promises[m] === 'function') dns.promises[m] = () => { attempts += 1; return Promise.reject(netDisabled()); };
  }
  setGlobalDispatcher(new Agent({ connect: (_opts, cb) => { attempts += 1; cb(netDisabled()); } }));
  installed = { attempts: () => attempts };
  return installed;
}

// ---- транспорт прокси

/**
 * Замена undici.request в core/proxy.js: хост demo.invalid обслуживает мок в процессе (сокетов нет),
 * любой другой хост — demo_network_disabled.
 */
export function createDemoTransport({ mock = createDemoMock() } = {}) {
  return async function demoTransport(url, opts = {}) {
    let u;
    try { u = new URL(url); } catch { throw netDisabled(); }
    if (u.hostname !== DEMO_HOST) throw netDisabled();
    if (opts.signal?.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError', code: 'ABORT_ERR' });
    const r = await mock.handle({ method: opts.method, path: u.pathname + u.search, headers: opts.headers || {}, body: opts.body });
    return { statusCode: r.status, headers: r.headers, body: r.body };
  };
}

// ---- allowlist маршрутов

/** Запрос ломает сценарий на посевном ключе: запрет, срок и окно отключают пропуска, фильтр без сделок закрывает вызов шага 3. */
function seededKeyLocked(action, body) {
  const filled = (v) => v !== undefined && String(v).trim() !== '';
  if (action === 'filter') return body.enabled === '1' && body.ent_deals !== '1';
  return body.mode === 'deny' || ['days', 'from', 'to', 'expires_at'].some((k) => filled(body[k]));
}

/** Класс лимита по IP: free (без лимита), site, api, mcp. */
function classOf(pathname) {
  if (pathname === '/healthz' || pathname.startsWith('/public/')) return 'free';
  if (pathname === '/mcp') return 'mcp';
  if (pathname.startsWith('/v1/')) return 'api';
  return 'site';
}

/**
 * Единственный источник правды о том, что доступно в демо: таблица [методы, шаблон, условие]; всё вне таблицы — 404.
 * Хуки регистрируются первыми (до registerWeb/agentApi/mcp), проверка идёт по реальному пути до CSRF и роутера.
 * @param {object} fastify корневой экземпляр
 * @param {{ repo:object, reset?:{resetting:boolean}, logger?:object }} ctx
 */
export function demoRouteGuard(fastify, { repo, vault = null, reset = null, logger = null }) {
  const limiters = {
    site: createLimiter({ limit: 120, windowSec: 60 }),
    api: createLimiter({ limit: 60, windowSec: 60 }),
    mcp: createLimiter({ limit: 60, windowSec: 60 }),
    simulate: createLimiter({ limit: 6, windowSec: 60 }),
    requests: createLimiter({ limit: 10, windowSec: 60 }),
    login: createLimiter({ limit: 10, windowSec: 60 }), // /login создаёт сессию: иначе один адрес вытесняет сессии всех посетителей
    create: createLimiter({ limit: CREATE_GLOBAL_MAX, windowSec: CREATE_GLOBAL_WINDOW_SEC }),
  };
  fastify.decorateRequest('demoGeneration', 0);
  // Посетитель = IP (IPv6 сведён к /64, как на основном сайте): ротация адресов внутри сети лимиты не обходит
  const visitor = (req) => clientKey(req.ip);
  // сколько агентов и ключей создал посетитель с этого IP после последнего сброса
  const made = { agents: new Map(), keys: new Map() };
  let gen = reset?.generation ?? 0;
  const created = (kind, ip) => {
    if ((reset?.generation ?? 0) !== gen) { gen = reset.generation; made.agents.clear(); made.keys.clear(); }
    return made[kind].get(ip) || 0;
  };
  const dec = (s) => { try { return decodeURIComponent(s); } catch { return null; } };
  const isDemoKey = (id) => { const c = id === null ? null : repo.getCredential(id); return !!c && c.provider === 'demo'; };
  const GET = ['GET', 'HEAD'];
  const ANY = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
  // cond(match) -> true: условие выполнено; false: 404 (чужой объект); 'limit': 403 (предел демо)
  const TABLE = [
    [GET, /^\/healthz$/],
    [GET, /^\/public\/.+$/],
    [GET, /^\/$/],
    [GET, /^\/login$/], // автовход демо-владельца обрабатывает сайт
    [GET, /^\/keys$/],
    [GET, /^\/keys\/new$/], // выбор сервиса: в демо каталог из одного провайдера
    [GET, /^\/keys\/new\/demo$/],
    // Витрина: только показ, форм и записи нет; сами экраны настроек, онбординга и ключей остаются закрытыми
    [GET, /^\/showcase\/(connect|settings)$/],
    [GET, /^\/showcase\/connect\/[a-z-]+$/],
    [GET, /^\/showcase\/services\/[a-z0-9-]+$/],
    [GET, /^\/keys\/([^/]+)$/],
    [GET, /^\/(agents|stats|audit)$/],
    [['POST'], /^\/keys\/([^/]+)\/(policy|filter)$/, (m) => isDemoKey(dec(m[1]))],
    // Общий лимит здесь только сверяется, списание в onResponse: запрос без сессии и CSRF не должен тратить бюджет всех посетителей
    [['POST'], /^\/keys\/new\/demo$/, (m, req) => (created('keys', visitor(req)) < MAX_KEYS - 1 && limiters.create.peek('demo:create') ? true : 'limit')],
    [['POST'], /^\/agents$/, (m, req) => (created('agents', visitor(req)) < MAX_AGENTS - 1 && limiters.create.peek('demo:create') ? true : 'limit')],
    [['POST'], /^\/agents\/([^/]+)\/keys$/, (m) => { const id = dec(m[1]); return id !== null && !!repo.getAgent(id); }],
    [GET, /^\/requests\/([^/]+)$/], // экран заявки: только показ, решение ниже
    [['POST'], /^\/requests\/([^/]+)\/(approve|deny)$/],
    [['POST'], /^\/demo\/simulate$/],
    [['POST'], /^\/v1\/grants$/],
    [GET, /^\/v1\/grants\/([^/]+)$/],
    [ANY, /^\/v1\/proxy\/demo\/.*$/],
    [['GET', 'POST', 'DELETE'], /^\/mcp$/],
  ];

  const isApi = (p) => p === '/mcp' || p.startsWith('/v1/');
  const deny = (reply, p, status, errCode, textKey) => {
    reply.code(status);
    if (isApi(p)) reply.type('application/json').send({ error: errCode });
    else reply.type('text/html; charset=utf-8').send(errorPage(status, t(textKey)));
    return reply;
  };

  fastify.addHook('onSend', async (req, reply) => { reply.header('x-robots-tag', 'noindex'); });

  // Успешное создание агента или ключа записывается на IP посетителя и в общий лимит. Успех: агент — страница с токеном (200),
  // ключ — редирект на главную. Ошибки формы и редирект на вход в счёт не идут.
  fastify.addHook('onResponse', async (req, reply) => {
    if (req.method !== 'POST') return;
    const p = (req.raw.url || '').split('?')[0];
    const kind = p === '/agents' && reply.statusCode === 200 ? 'agents'
      : p === '/keys/new/demo' && reply.statusCode === 302 && reply.getHeader('location') === '/' ? 'keys' : null;
    if (!kind) return;
    limiters.create.take('demo:create');
    const key = visitor(req);
    created(kind, key); // сверка с номером сброса
    const map = made[kind];
    // карта заполнена: вытесняем самого старого посетителя, а не пропускаем нового без учёта
    if (map.size >= TRACK_MAX && !map.has(key)) map.delete(map.keys().next().value);
    map.set(key, (map.get(key) || 0) + 1);
    // Потолок базы: новый посетитель не получает отказ, уходят самые старые объекты посетителей. Только после настоящего создания
    try {
      if (kind === 'agents') {
        const list = repo.listAgents();
        for (const a of list.filter((x) => x.id !== DEMO_AGENT_ID).slice(0, Math.max(0, list.length - TOTAL_AGENTS))) repo.demoEvictAgent(a.id);
      } else {
        const list = repo.listCredentials();
        for (const c of list.filter((x) => x.id !== DEMO_CREDENTIAL_ID).slice(0, Math.max(0, list.length - TOTAL_KEYS))) {
          await vault?.del(`cred/${c.id}`); // сначала сейф: запись без значения безвредна, значение без записи остановит запуск
          repo.demoEvictCredential(c.id);
        }
      }
    } catch (e) { logger?.error({ err: e.message }, 'demo evict failed'); }
  });

  fastify.addHook('onRequest', async (req, reply) => {
    const url = req.raw.url || '/';
    const q = url.indexOf('?');
    const p = q < 0 ? url : url.slice(0, q);
    req.demoGeneration = reset?.generation ?? 0;
    // 1. сброс идёт: запросы получают 503 на время сброса (/healthz для проверок живости проходит)
    if (reset?.resetting && p !== '/healthz') {
      reply.header('retry-after', '2');
      return deny(reply, p, 503, 'demo_resetting', 'demo.err.resetting');
    }
    // 2. allowlist: вне таблицы — 404
    let hit = null;
    for (const [methods, re, cond] of TABLE) {
      if (!methods.includes(req.method)) continue;
      const m = re.exec(p);
      if (m) { hit = { cond, m }; break; }
    }
    if (!hit) return deny(reply, p, 404, 'not_found', 'error.page_not_found');
    // 3. тело запроса не больше 64 KiB (длина известна заранее; потоковые тела режет сам маршрут: bodyLimit, maxBody провайдера)
    const cl = Number(req.headers['content-length']);
    if (Number.isFinite(cl) && cl > MAX_BODY) return deny(reply, p, 413, 'payload_too_large', 'demo.err.too_long');
    // 4. лимиты по IP (ключ demo:<класс>:<ip>); за прокси IP берётся из trustProxy
    const cls = classOf(p);
    const classes = cls === 'free' ? [] : [cls];
    if (req.method === 'POST' && p === '/demo/simulate') classes.push('simulate');
    if (req.method === 'POST' && p === '/v1/grants') classes.push('requests');
    if (p === '/login') classes.push('login');
    for (const c of classes) {
      if (!limiters[c].take(`demo:${c}:${visitor(req)}`)) return deny(reply, p, 429, 'rate_limited', 'demo.err.rate_limited');
    }
    // 5. условия строки таблицы
    if (hit.cond) {
      const r = hit.cond(hit.m, req);
      if (r === 'limit') return deny(reply, p, 403, 'demo_limit', 'demo.err.limit');
      if (r !== true) return deny(reply, p, 404, 'not_found', 'error.page_not_found');
    }
  });

  // Пользовательские поля ограничены: имя агента и метка ключа до 40 символов, подтверждение только кнопкой на сайте
  fastify.addHook('preHandler', async (req, reply) => {
    const p = (req.raw.url || '').split('?')[0];
    // Тело дочитано: запрос, начатый до сброса, не должен менять данные нового поколения (сессия и проверки — от старого)
    if (reset && req.method !== 'GET' && req.method !== 'HEAD' && (reset.resetting || req.demoGeneration !== reset.generation)) {
      reply.header('retry-after', '2');
      return deny(reply, p, 503, 'demo_resetting', 'demo.err.resetting');
    }
    if (req.method !== 'POST' || !req.body || typeof req.body !== 'object') return;
    // Посевные ключ и агент держат сценарий для всех: то, что его ломает, можно пробовать только на своём ключе
    const seeded = /^\/keys\/([^/]+)\/(policy|filter)$/.exec(p);
    if (seeded && dec(seeded[1]) === DEMO_CREDENTIAL_ID && seededKeyLocked(seeded[2], req.body)) return deny(reply, p, 400, 'seeded_locked', 'demo.err.seeded');
    const agentKeys = /^\/agents\/([^/]+)\/keys$/.exec(p);
    if (agentKeys && dec(agentKeys[1]) === DEMO_AGENT_ID && req.body.keys_all !== '1') return deny(reply, p, 400, 'seeded_locked', 'demo.err.seeded');
    const long = (v) => typeof v === 'string' && Array.from(v).length > MAX_LABEL;
    if (p === '/agents' && long(req.body.name)) return deny(reply, p, 400, 'too_long', 'demo.err.too_long');
    if (p === '/keys/new/demo' || /^\/keys\/[^/]+\/policy$/.test(p)) {
      if (long(req.body.label)) return deny(reply, p, 400, 'too_long', 'demo.err.too_long');
      if (req.body.approval !== undefined && req.body.approval !== 'web_button') return deny(reply, p, 400, 'approval_not_available', 'demo.err.approval');
    }
  });
}
