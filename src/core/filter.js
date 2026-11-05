// Фильтр данных (ТЗ v1.3): какие методы агент может вызвать и какие поля ответа увидит.
// Чистые функции без I/O; прокси вызывает их до и после обращения к сервису.
import { t } from '../i18n.js';
import { maskJson } from './mask.js';

/** '/crm.deal.list.json' → 'crm.deal.list'; '/crm/v3/objects/deals/' → 'crm/v3/objects/deals' */
export function normalizeMethod(path) {
  return String(path || '').trim().toLowerCase().replace(/^\/+/, '').replace(/\/+$/, '').replace(/\.(json|xml)$/, '');
}

/** Лимиты фильтра (контракт П-28/П-27); их проверяют loadCatalog, checkFilter и сам фильтр при выполнении. */
export const FILTER_LIMITS = Object.freeze({
  rules: 64, segments: 12, patternLen: 200, stars: 2, fields: 200, fieldDepth: 8, jsonDepth: 32, keepMaxLen: 256, maxFieldLen: 4000,
});

/** Проблема шаблона метода: null — годится; иначе 'length' | 'segments' | 'stars'. */
export function globProblem(pattern) {
  const p = String(pattern ?? '');
  if (p.length > FILTER_LIMITS.patternLen) return 'length';
  if (normalizeMethod(p).split('/').length > FILTER_LIMITS.segments) return 'segments';
  let stars = 0;
  for (let i = 0; i < p.length; i++) if (p[i] === '*') stars++;
  return stars > FILTER_LIMITS.stars ? 'stars' : null;
}

/** Шаблон → нормализованная строка для globMatch; негодный шаблон — null (не совпадёт ни с чем). */
const globPat = (pattern) => (globProblem(pattern) ? null : normalizeMethod(pattern));

/**
 * Линейное сопоставление со «*» (любая последовательность, включая «/»): два указателя и запомненная
 * последняя звезда, без RegExp (П-28). Звёзд ≤ 2, поэтому откат ограничен.
 */
function globMatch(p, s, noSlash = false) {
  let pi = 0; let si = 0; let star = -1; let mark = 0;
  while (si < s.length) {
    if (pi < p.length && p[pi] === '*') { star = pi++; mark = si; }
    else if (pi < p.length && p[pi] === s[si]) { pi++; si++; }
    // noSlash (rpc, 9.1c): звезда не поглощает «/», слэш в имени метода возможен только литералом шаблона
    // L7: в rpc «*» не покрывает «;», «%», пробелы и прочее вне имени метода (crm.deal.add;.list не совпадает с crm.*.list);
    // noSlash === 'word' (шаблоны readOnly из каталога) — строже: только [A-Za-z0-9_], без точки
    else if (star >= 0) {
      if (noSlash && !(noSlash === 'word' ? /[a-z0-9_]/i : /[a-z0-9_.]/i).test(s[mark])) return false;
      pi = star + 1; si = ++mark;
    }
    else return false;
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

const matchesAny = (pats, method, noSlash = false) => pats.some((p) => globMatch(p, method, noSlash));
const tooDeepPath = (method) => method.split('/').length > FILTER_LIMITS.segments;

// ---- REST-маршруты (П-17, П-28): «МЕТОД /сегмент/:id/*/**» ----
// Шаблон разбирается один раз в массив сегментов [{t:'lit'|'param'|'star'|'rest', v?}]; путь режется по «/» один раз,
// сравнение идёт слева направо за один проход, без откатов и без RegExp на путях (П-28).
export const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const HTTP_METHODS = new Set(['GET', 'HEAD', ...WRITE_METHODS]);
const SEG_VALUE = /^[A-Za-z0-9_.~-]{1,128}$/;
const SEG_LITERAL = /^[A-Za-z0-9_.~-]+$/;
const SEG_PARAM = /^:[A-Za-z_][A-Za-z0-9_]*$/;
// Негодный шаблон в deny закрывает всё: безопаснее, чем пропустить
const CLOSE_ALL = Object.freeze({ method: 'ANY', segs: [{ t: 'rest' }], text: '' });

/**
 * Разбор шаблона маршрута. deny:true — разрешены метод ANY и «**» последним сегментом.
 * @returns {{problem:'length'|'segments'|'syntax'|'method'|'rest'}|{method:string, segs:object[], text:string}}
 *   rest — «**» вне deny; syntax — не «МЕТОД /путь», пустой сегмент, «.»/«..», «*» внутри сегмента
 */
export function parseRoute(pattern, { deny = false } = {}) {
  const s = String(pattern ?? '').trim();
  if (s.length > FILTER_LIMITS.patternLen) return { problem: 'length' };
  const i = s.indexOf(' ');
  if (i < 1) return { problem: 'syntax' };
  const method = s.slice(0, i).toUpperCase();
  if (!HTTP_METHODS.has(method) && !(deny && method === 'ANY')) return { problem: 'method' };
  let path = s.slice(i + 1).trim();
  if (!path.startsWith('/')) return { problem: 'syntax' };
  path = path.slice(1);
  if (path.endsWith('/')) path = path.slice(0, -1);
  const parts = path === '' ? [] : path.split('/');
  if (parts.length > FILTER_LIMITS.segments) return { problem: 'segments' };
  const segs = [];
  for (let k = 0; k < parts.length; k++) {
    const p = parts[k];
    if (p === '**') {
      if (!deny) return { problem: 'rest' };
      if (k !== parts.length - 1) return { problem: 'syntax' };
      segs.push({ t: 'rest' });
    } else if (p === '*') segs.push({ t: 'star' });
    else if (SEG_PARAM.test(p)) segs.push({ t: 'param' });
    else if (SEG_LITERAL.test(p) && p !== '.' && p !== '..') segs.push({ t: 'lit', v: p.toLowerCase() });
    else return { problem: 'syntax' };
  }
  return { method, segs, text: s };
}

/** Путь агента → сегменты; null — путь не может совпасть ни с чем (пустой сегмент, «//» в начале, глубже лимита). */
function pathSegs(path) {
  const p = String(path ?? '');
  if (p.startsWith('//')) return null;
  let s = p.startsWith('/') ? p.slice(1) : p;
  if (s.endsWith('/')) s = s.slice(0, -1); // один хвостовой «/» отбрасывается
  if (s === '') return [];
  const segs = s.split('/');
  return segs.length > FILTER_LIMITS.segments || segs.includes('') ? null : segs;
}

/**
 * Один проход слева направо. HEAD совпадает с правилом GET; ANY — любой метод.
 * lenient (deny): :имя и «*» принимают любой непустой сегмент, чтобы странный сегмент не обходил запрет.
 */
function matchRoute(rt, method, segs, lenient = false) {
  if (rt.method !== 'ANY' && rt.method !== method && !(method === 'HEAD' && rt.method === 'GET')) return false;
  const p = rt.segs;
  const open = p.length > 0 && p[p.length - 1].t === 'rest';
  const n = open ? p.length - 1 : p.length;
  if (open ? segs.length < n : segs.length !== n) return false;
  for (let i = 0; i < n; i++) {
    const v = segs[i];
    if (p[i].t === 'lit') { if (v.toLowerCase() !== p[i].v) return false; }
    else if (lenient ? v === '' : (!SEG_VALUE.test(v) || v === '.' || v === '..')) return false;
  }
  return true;
}

/**
 * Глубина JSON не больше max: линейный проход по байтам до JSON.parse, скобки внутри строк
 * и после экранирования не считаются. Невалидный JSON отсекает уже JSON.parse.
 * @param {Buffer|Uint8Array} buf
 * @returns {boolean} true — глубина в пределах лимита
 */
export function checkJsonDepth(buf, max = FILTER_LIMITS.jsonDepth) {
  let depth = 0; let inStr = false; let esc = false;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === 0x5c) esc = true;
      else if (c === 0x22) inStr = false;
    } else if (c === 0x22) inStr = true;
    else if (c === 0x5b || c === 0x7b) { if (++depth > max) return false; }
    else if (c === 0x5d || c === 0x7d) depth--;
  }
  return true;
}

// Имена, через которые JS-объект меняет прототип: в путях полей запрещены (П-2)
const RESERVED = new Set(['__proto__', 'prototype', 'constructor']);
const pathParts = (raw) => String(raw).split('.').map((s) => s.replace(/\[\]$/, '')).filter(Boolean);

/**
 * Путь агента однозначен: без сегментов «.» и пустых сегментов, без %-последовательностей
 * после декодирования. Иначе фильтр и сервис могут увидеть разные методы (П-1: /./batch.json).
 */
function plainPath(path) {
  const p = String(path || '');
  if (p.includes('%')) return false;
  const segs = p.replace(/^\/+/, '').split('/');
  return segs.every((s, i) => s !== '.' && s !== '..' && (s !== '' || i === segs.length - 1));
}

// Листья дерева: 's' — скаляр (поле каталога), 'k' — служебное поле keep (скаляр, строка ≤ keepMaxLen),
// 'o' — поле-контейнер из каталога с object: true (проходит целиком). Ветка — объект без прототипа.
const SCALAR = 's';
const KEEP = 'k';
const OBJ = 'o';

/** Пути полей [[путь, вид]] → дерево: { result: { COMMENTS: 's', ID: 's' }, total: 'k' }. */
function buildTree(entries) {
  const root = Object.create(null);
  for (const [raw, kind] of entries) {
    const parts = pathParts(raw);
    if (!parts.length || parts.length > FILTER_LIMITS.fieldDepth || parts.some((k) => RESERVED.has(k))) continue;
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const key = parts[i];
      if (typeof node[key] === 'string') break; // выше уже стоит лист
      if (i === parts.length - 1) { node[key] = kind; break; }
      node = node[key] = node[key] && typeof node[key] === 'object' ? node[key] : Object.create(null);
    }
  }
  return root;
}

/**
 * Оставляет только ветки дерева; массивы проходятся насквозь. ctx.counter.n — сколько ключей вырезано.
 * Скалярный лист пропускает только скаляр; глубже лимита ответ не обходится (П-28).
 */
function prune(value, node, ctx, depth = 0) {
  if (node === OBJ) return value;
  if (typeof node === 'string') {
    if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      const max = node === KEEP ? ctx.keepMax : ctx.fieldMax;
      if (value.length <= max) return value;
      ctx.counter.n++;
      return value.slice(0, max);
    }
    ctx.counter.n++; // объект или массив под скалярным полем
    return undefined;
  }
  if (depth >= FILTER_LIMITS.jsonDepth + 1) { ctx.counter.n++; return undefined; }
  if (Array.isArray(value)) return value.map((v) => prune(v, node, ctx, depth + 1)).filter((v) => v !== undefined);
  if (value && typeof value === 'object') {
    // defineProperty: ключ "__proto__" из ответа сервиса остаётся обычным полем, а не меняет прототип
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (Object.hasOwn(node, k)) {
        const r = prune(v, node[k], ctx, depth + 1);
        if (r !== undefined) Object.defineProperty(out, k, { value: r, enumerable: true, writable: true, configurable: true });
      }
      else ctx.counter.n++;
    }
    return out;
  }
  // скаляр там, где ожидался объект: не знаем, что это, — не отдаём
  ctx.counter.n++;
  return undefined;
}

/**
 * Имена полей для select. Bitrix24 (rpc): верхний уровень под result.
 * REST: имя сразу после сегмента selectParam (results[].properties.dealstage → dealstage).
 */
function selectFields(fields, restParam = null) {
  const out = new Set();
  for (const f of fields) {
    if (restParam) {
      const parts = pathParts(f);
      const i = parts.indexOf(restParam);
      if (i >= 0 && parts[i + 1]) out.add(parts[i + 1]);
      continue;
    }
    const [head, name] = String(f).split('.').map((s) => s.replace(/\[\]$/, ''));
    if (head === 'result' && name) out.add(name);
  }
  return [...out];
}

/** Имя параметра select в любой форме: select, SELECT, select[], select[0], Select[1][x] (П-26). */
const isSelectKey = (k, param) => {
  const l = String(k).toLowerCase();
  const p = param.toLowerCase();
  return l === p || l.startsWith(`${p}[`);
};

/**
 * Убирает из query-строки параметры select во всех формах и добавляет свои:
 * 'repeat[]' — select[]=a&select[]=b (Bitrix24), 'comma' — properties=a,b (HubSpot; пустой список параметр не добавляет).
 */
function rewriteQuery(query, param, names, format = 'repeat[]') {
  const sp = new URLSearchParams(query.startsWith('?') ? query.slice(1) : query);
  for (const k of [...sp.keys()]) if (isSelectKey(k, param)) sp.delete(k);
  if (format === 'comma') { if (names.length) sp.set(param, names.join(',')); }
  else for (const n of names) sp.append(`${param}[]`, n);
  const s = sp.toString();
  return s ? `?${s}` : '';
}

const strList = (v) => (Array.isArray(v) ? v.map(String) : []);

/**
 * Приводит запись фильтра к виду { enabled, entities, methods, fields }.
 * null — фильтр не настраивался: выключен, все типы каталога открыты с полями по умолчанию.
 * Старая запись { preset, methods, fields }: тип, все методы которого разрешены, получает её поля;
 * методы, не покрытые типами, остаются дополнительным правилом.
 * readOnly и mask (слой 1, п. 7.2) хранятся только когда включены: ключа нет ≡ false.
 */
export function normalizeFilter(filter, provider) {
  const f = normalizeCore(filter, provider);
  return { ...f, ...(filter?.readOnly === true && { readOnly: true }), ...(filter?.mask === true && { mask: true }) };
}

/**
 * Что провайдер умеет в слое 1. readOnly: в каталоге описано, какие запросы читают (providers.yaml → readOnly);
 * mask: доступна у всех, кроме провайдеров с mask: false (LLM и потоковые, где ответ нельзя держать в памяти).
 */
export function protectionOf(provider) {
  const ro = provider?.readOnly;
  return { readOnly: !!ro && typeof ro === 'object', mask: !!provider && provider.mask !== false };
}

/** Фильтр нового ключа: у провайдера с readOnly.default (CRM) чтение включено сразу, иначе null (фильтра нет). */
export function defaultFilterFor(provider) {
  if (!provider?.readOnly || typeof provider.readOnly !== 'object' || provider.readOnly.default !== true) return null;
  return { ...normalizeCore(null, provider), readOnly: true };
}

function normalizeCore(filter, provider) {
  const ents = provider?.filter?.entities || {};
  if (!filter) {
    return { enabled: false, entities: Object.fromEntries(Object.entries(ents).map(([id, e]) => [id, [...(e.defaults || [])]])), methods: [], fields: [] };
  }
  const methods = strList(filter.methods);
  const fields = strList(filter.fields);
  if (filter.entities && typeof filter.entities === 'object') {
    const entities = {};
    for (const [id, fs] of Object.entries(filter.entities)) if (ents[id]) entities[id] = strList(fs);
    // flags[тип] = ['search']: только известные extras открытых типов; пустые не храним (≡ [])
    const flags = {};
    if (filter.flags && typeof filter.flags === 'object') {
      for (const [id, fl] of Object.entries(filter.flags)) {
        const known = entities[id] ? [...new Set(strList(fl))].filter((x) => Object.hasOwn(ents[id].extras || {}, x)) : [];
        if (known.length) flags[id] = known;
      }
    }
    return { enabled: !!filter.enabled, entities, ...(Object.keys(flags).length && { flags }), methods, fields };
  }
  // пустая старая запись (фильтр так и не настраивали) — как null: типы с полями по умолчанию
  if (!methods.length) return { ...normalizeFilter(null, provider), enabled: !!filter.enabled };
  const have = new Set(methods.map(normalizeMethod));
  const entities = {};
  const covered = new Set();
  for (const [id, e] of Object.entries(ents)) {
    const ms = (e.methods ?? []).map(normalizeMethod);
    if (ms.length && ms.every((m) => have.has(m))) { entities[id] = [...fields]; ms.forEach((m) => covered.add(m)); }
  }
  const rest = methods.filter((m) => !covered.has(normalizeMethod(m)));
  return { enabled: !!filter.enabled, entities, methods: rest, fields: rest.length ? fields : [] };
}

/**
 * @param {import('../../docs/ARCHITECTURE.md').DataFilter|null} filter
 * @param {object} provider — запись каталога
 * @returns {null|{allowMethod:(path:string)=>boolean, rewriteSelect:Function, filterBody:Function, methods:string[]}}
 */
export function compileFilter(filter, provider) {
  if (!filter) return null;
  const ro = filter.readOnly === true;
  const mk = filter.mask === true;
  const on = !!filter.enabled;
  // фильтр полей выключен, но включён readOnly или mask: методы и поля не фильтруются, работают только они
  if (!on && !ro && !mk) return null;
  const f = normalizeFilter(filter, provider);
  const pf = provider?.filter || {};
  const rest = pf.style === 'rest';
  const ents = pf.entities || {};
  const fmt = pf.selectFormat === 'comma' ? 'comma' : 'repeat[]';
  // rest: негодный шаблон deny закрывает всё; rpc: тоже («*» на любой метод)
  const deny = rest ? (pf.deny || []).map((p) => { const r = parseRoute(p, { deny: true }); return r.problem ? CLOSE_ALL : r; })
    : (pf.deny || []).map((p) => globPat(p) ?? '*');
  const keep = pf.keep || [];
  let selectFor = null;
  if (pf.selectParam && pf.selectFor?.length) {
    selectFor = rest ? pf.selectFor.map((p) => parseRoute(p)).filter((r) => !r.problem) : pf.selectFor.map(globPat).filter((p) => p !== null);
  }
  const ctx = { keepMax: pf.keepMaxLen ?? FILTER_LIMITS.keepMaxLen, fieldMax: pf.maxFieldLen ?? FILTER_LIMITS.maxFieldLen };
  const keepEntries = keep.map((p) => [p, KEEP]);

  // шаблоны разрешённых методов: не больше лимита, дальше отбрасываются (закрыто)
  let budget = FILTER_LIMITS.rules;
  const allowOf = (methods) => {
    const out = [];
    for (const m of methods) { const p = globPat(m); if (p !== null && budget > 0) { out.push(p); budget--; } }
    return out;
  };
  // REST: маршруты типа и ручного правила — только чтение (запись отбрасывается даже при ошибке каталога);
  // запись возможна лишь у маршрутов extras включённого флага (writeOk)
  const allowRoutes = (patterns, writeOk) => {
    const out = [];
    for (const m of patterns) {
      const r = parseRoute(m);
      if (r.problem || (!writeOk && WRITE_METHODS.has(r.method)) || budget <= 0) continue;
      out.push(r); budget--;
    }
    return out;
  };
  // правило = методы + поля; тип данных идёт раньше дополнительного правила владельца.
  // Контейнер (массив/объект) проходит только у полей каталога с object: true.
  const rule = (methods, fields, objects, extraRoutes = []) => ({
    allow: rest ? [...allowRoutes(methods, false), ...allowRoutes(extraRoutes, true)] : allowOf(methods),
    tree: buildTree([...keepEntries, ...fields.map((x) => [x, objects.has(pathParts(x).join('.')) ? OBJ : SCALAR])]),
    names: selectFields(fields, rest ? pf.selectParam : null),
  });
  const objectsOf = (e) => new Set((e.fields || []).filter((x) => x.object === true).flatMap((x) => [x.path, ...(x.paths || [])]).filter(Boolean).map((x) => pathParts(x).join('.')));
  const entRoutes = (e) => (rest ? e.routes : e.methods) || [];
  // отмеченное поле с несколькими формами ответа (paths) открывает все формы
  const expandOf = (e, fields) => {
    const groups = new Map();
    for (const x of e.fields || []) { const g = x.paths ?? (x.path ? [x.path] : []); for (const p of g) groups.set(p, g); }
    return [...new Set(fields.flatMap((p) => groups.get(p) ?? [p]))];
  };
  const extrasOf = (id) => (f.flags?.[id] || []).flatMap((fl) => ents[id].extras?.[fl]?.routes || []);
  const rules = Object.entries(on ? f.entities : {}).map(([id, fields]) => rule(entRoutes(ents[id]), expandOf(ents[id], fields).slice(0, FILTER_LIMITS.fields), objectsOf(ents[id]), rest ? extrasOf(id) : []));
  if (on && f.methods.length) rules.push(rule(f.methods, f.fields.slice(0, FILTER_LIMITS.fields), new Set()));
  const ruleFor = (method, path) => {
    if (rest) {
      const segs = pathSegs(path);
      return segs ? rules.find((r) => r.allow.some((rt) => matchRoute(rt, method, segs))) ?? null : null;
    }
    const m = normalizeMethod(path);
    if (tooDeepPath(m)) return null;
    return rules.find((r) => matchesAny(r.allow, m, noSlash)) ?? null;
  };
  const isDenied = (method, path) => {
    if (rest) { const segs = pathSegs(path); return !segs || deny.some((rt) => matchRoute(rt, method, segs, true)); }
    return matchesAny(deny, normalizeMethod(path));
  };
  const keepOnly = buildTree(keepEntries);

  // ---- readOnly (п. 7.2): только чтение. REST — GET/HEAD и перечисленные в каталоге POST-маршруты чтения (extraRoutes);
  // RPC — методы из readMethods. Сильнее типов данных и флагов: запись не откроет ни тип, ни флаг, ни ручное правило.
  const spec = provider?.readOnly && typeof provider.readOnly === 'object' ? provider.readOnly : null;
  // провайдер без описания чтения (правка базы в обход формы): REST — GET/HEAD, RPC — ничего; закрыто, а не открыто
  const roRest = spec ? spec.style !== 'rpc' : rest || !provider?.filter;
  const roRoutes = (spec?.extraRoutes || []).map((p) => parseRoute(p)).filter((r) => !r.problem);
  const roPats = (spec?.readMethods || []).map(globPat).filter((p) => p !== null);
  // rpc: «*» разрешающих шаблонов не покрывает «/» (путь /crm.deal.add/x.list не должен совпасть с crm.*.list, 9.1c).
  // Только провайдеры со readOnly.style: rpc (Bitrix24, Telegram); демо-каталог с 'deals/*' не затронут.
  // deny остаётся с «*» через «/»: для запрета шире значит безопаснее.
  const noSlash = spec?.style === 'rpc';
  const roAllows = (method, path) => {
    if (!ro) return true;
    if (roRest) {
      if (method === 'GET' || method === 'HEAD') return true;
      if (!HTTP_METHODS.has(method)) return false;
      const segs = pathSegs(path);
      return !!segs && roRoutes.some((rt) => matchRoute(rt, method, segs));
    }
    const m = normalizeMethod(path);
    return plainPath(path) && !tooDeepPath(m) && matchesAny(roPats, m, noSlash && 'word');
  };

  const methods = !on
    ? (ro ? (roRest ? ['GET', 'HEAD', ...roRoutes.map((rt) => rt.text)] : [...(spec?.readMethods || [])]) : [])
    : rest
      ? [...new Set(rules.flatMap((r) => r.allow.map((rt) => rt.text)))]
      : [...new Set([...Object.keys(f.entities).flatMap((id) => ents[id].methods), ...f.methods])];
  // allowMethod(путь) — совместимый вызов для rpc без HTTP-метода (метод не участвует)
  const split = (a, b) => (b === undefined ? ['GET', a] : [String(a ?? '').toUpperCase(), b]);
  const allow = (method, path) => {
    if (!on) return roAllows(method, path);
    if (!plainPath(path)) return false;
    if (rest) {
      if (!HTTP_METHODS.has(method)) return false;
      if (!pathSegs(path)) return false;
    } else if (tooDeepPath(normalizeMethod(path))) return false;
    if (isDenied(method, path)) return false;
    if (!roAllows(method, path)) return false;
    return !!ruleFor(method, path);
  };
  const denyQuery = new Set((pf.denyQuery || []).map((n) => String(n).toLowerCase()));

  return {
    methods,
    enabled: on,
    readOnly: ro,
    mask: mk,
    needsBuffer: on || mk,
    allowMethod(a, b) { const [m, p] = split(a, b); return allow(m, p); },
    denyReason(a, b) {
      const [m, p] = split(a, b);
      if (allow(m, p)) return null;
      if (!on) return 'write_not_allowed';
      // readOnly: запрос не из списка чтения на путь, который не закрыт deny
      if (ro && plainPath(p) && !isDenied(m, p) && !roAllows(m, p)) return 'write_not_allowed';
      // запись на путь, который не закрыт deny и не открыт флагом: write_not_allowed
      if (rest && WRITE_METHODS.has(m) && plainPath(p) && !isDenied(m, p)) return 'write_not_allowed';
      return 'method_not_allowed';
    },
    // denyQuery каталога (associations и т.п.): параметр в любом регистре и виде name[...] закрыт. hidden_field_filter — хук П-18, в 1.0 null
    checkQuery(_method, _path, query = '') {
      if (!on || !denyQuery.size) return null;
      const sp = new URLSearchParams(String(query).startsWith('?') ? String(query).slice(1) : String(query));
      for (const k of sp.keys()) if (denyQuery.has(k.trim().toLowerCase().split('[')[0])) return 'query_not_allowed';
      return null;
    },
    rewriteSelect(path, query, body = null, contentType = '', httpMethod = 'GET') {
      if (!on) return { query, body };
      const method = String(httpMethod || 'GET').toUpperCase();
      const r = ruleFor(method, path);
      const hit = () => (rest ? selectFor.some((rt) => matchRoute(rt, method, pathSegs(path))) : matchesAny(selectFor, normalizeMethod(path)));
      if (!r || !selectFor || !hit()) return { query, body };
      const param = pf.selectParam;
      const names = r.names;
      const q = rewriteQuery(query, param, names, fmt);
      if (body == null || !body.length) return { query: q, body };
      const ct = String(contentType).toLowerCase();
      if (ct.includes('application/json')) {
        let obj;
        try { obj = JSON.parse(body.toString('utf8')); } catch { return { query: q, body, error: 'body_not_allowed' }; }
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { query: q, body, error: 'body_not_allowed' };
        // select в любом регистре и виде (массив, объект с числовыми ключами, select[0]) заменяется своим
        for (const k of Object.keys(obj)) if (isSelectKey(k, param)) delete obj[k];
        obj[param] = names;
        return { query: q, body: Buffer.from(JSON.stringify(obj)) };
      }
      if (ct.includes('application/x-www-form-urlencoded')) {
        return { query: q, body: Buffer.from(rewriteQuery(body.toString('utf8'), param, names, fmt).replace(/^\?/, '')) };
      }
      // неизвестный вид тела у метода со списком полей: select мог быть спрятан в нём
      return { query: q, body, error: 'body_not_allowed' };
    },
    filterBody(json, path, httpMethod = 'GET') {
      const counter = { n: 0 };
      let out = json;
      if (on) {
        // метод вне правил сюда не доходит (allowMethod), но на всякий случай — только служебные поля
        out = prune(json, ruleFor(String(httpMethod || 'GET').toUpperCase(), path)?.tree ?? keepOnly, { ...ctx, counter });
        if (out === undefined) out = {};
      }
      // маскировка идёт после вырезания полей и касается и разрешённых полей, и keep
      let masked = 0;
      if (mk) { const m = maskJson(out); out = m.json; masked = m.n; }
      return { json: out, removed: counter.n, masked };
    },
  };
}

// ---- описание фильтра для агента и владельца (п. 7.3): без секретов, только типы, методы и имена полей ----

/**
 * Что агент увидит по ключу: { types:[{id,name,fields[,flags]}], methods[], read_only?, mask? }.
 * null — у ключа нет ни фильтра полей, ни readOnly, ни mask (агент видит ответ сервиса целиком).
 * types есть только при включённом фильтре полей; поля — пути из каталога (result.ID), не значения.
 */
export function describeFilter(filter, provider) {
  const flt = compileFilter(filter, provider);
  if (!flt) return null;
  const f = normalizeFilter(filter, provider);
  const ents = provider?.filter?.entities || {};
  return {
    ...(flt.enabled && {
      types: Object.entries(f.entities).map(([id, fields]) => ({ id, name: ents[id]?.name || id, fields: [...fields], ...(f.flags?.[id]?.length && { flags: [...f.flags[id]] }) })),
      ...(f.fields.length && { extra_fields: [...f.fields] }),
    }),
    methods: [...flt.methods],
    ...(flt.readOnly && { read_only: true }),
    ...(flt.mask && { mask: true }),
  };
}

const oneLine = (s) => String(s ?? '').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/g, ' ').trim();
const LINE_FIELDS = 6; // сколько полей типа показать в строке, остальные — «+N»
const LINE_MAX = 400;

/**
 * Строка «Агент увидит: …» для заявки (Telegram, Slack, e-mail, сайт). Одна строка без управляющих
 * символов, не длиннее LINE_MAX; разметки нет, поэтому её можно вставлять в текст любого канала.
 */
export function filterLine(filter, provider) {
  const d = describeFilter(filter, provider);
  const ents = provider?.filter?.entities || {};
  const labelOf = (id, path) => {
    const x = (ents[id]?.fields || []).find((y) => y.path === path || (y.paths || []).includes(path));
    return oneLine(x?.label || pathParts(path).at(-1) || path);
  };
  const parts = [];
  if (d?.types) {
    for (const ty of d.types) {
      const labels = ty.fields.map((p) => labelOf(ty.id, p));
      const more = labels.length - LINE_FIELDS;
      parts.push(`${oneLine(ty.name)} (${labels.slice(0, LINE_FIELDS).join(', ')}${more > 0 ? `, +${more}` : ''})`);
    }
    if (d.extra_fields?.length) parts.push(t('filter.line.extra', { n: d.extra_fields.length }));
    if (!parts.length) parts.push(t('filter.line.none'));
  } else parts.push(t('filter.line.all'));
  if (d?.read_only) parts.push(t('filter.line.read_only'));
  if (d?.mask) parts.push(t('filter.line.mask'));
  return Array.from(oneLine(t('filter.line', { what: parts.join('; ') }))).slice(0, LINE_MAX).join('');
}

/**
 * Первый читающий вызов для «Проверить на одном вызове»: GET первого маршрута без параметров у первого
 * включённого типа (фильтр выключен — у первого типа каталога) с limit=1. null — подходящего маршрута нет.
 */
export function previewRoute(filter, provider) {
  const pf = provider?.filter;
  if (!pf?.entities) return null;
  const f = normalizeFilter(filter, provider);
  const rest = pf.style === 'rest';
  for (const id of f.enabled ? Object.keys(f.entities) : Object.keys(pf.entities)) {
    for (const m of (rest ? pf.entities[id]?.routes : pf.entities[id]?.methods) || []) {
      if (rest) {
        const r = parseRoute(m);
        if (r.problem || r.method !== 'GET' || r.segs.some((s) => s.t !== 'lit')) continue;
        // путь берём из исходного текста маршрута (регистр сегментов важен сервису), parseRoute уже проверил форму
        const text = String(m).trim();
        return { method: 'GET', path: text.slice(text.indexOf(' ') + 1).trim().replace(/\/+$/, '') || '/', query: '?limit=1' };
      }
      if (/^[A-Za-z0-9_.-]{1,120}$/.test(m)) return { method: 'GET', path: `/${m}.json`, query: '?limit=1' };
    }
  }
  return null;
}

const NAMES_MAX = 500;
const NAME_PART = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * Имена полей JSON без значений: пути через точку, массивы прозрачны (result.ID). Ключ из одних цифр
 * (идентификатор записи) → «*», необычный ключ → «?»: имена не должны нести данные. Не больше NAMES_MAX.
 * Глубину ответа проверяет вызывающий (checkJsonDepth).
 */
export function fieldNames(json) {
  const out = new Set();
  const walk = (v, prefix, depth) => {
    if (out.size >= NAMES_MAX || depth > FILTER_LIMITS.jsonDepth) return;
    if (Array.isArray(v)) { for (const x of v) walk(x, prefix, depth + 1); return; }
    if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        const key = /^\d+$/.test(k) ? '*' : NAME_PART.test(k) ? k : '?';
        walk(x, prefix ? `${prefix}.${key}` : key, depth + 1);
      }
      return;
    }
    if (prefix) out.add(prefix);
  };
  walk(json, '', 0);
  return [...out].sort();
}

/** Ошибки сохранения фильтра (для формы на странице ключа). */
export function checkFilter(filter, provider) {
  const errors = [];
  // readOnly и mask доступны не у каждого сервиса (OpenAI: запись неотличима от чтения)
  const avail = protectionOf(provider);
  if (filter?.readOnly === true && !avail.readOnly) errors.push(t('filter.err.read_only_unavailable'));
  if (filter?.mask === true && !avail.mask) errors.push(t('filter.err.mask_unavailable'));
  if (!filter?.enabled) return errors;
  const f = normalizeFilter(filter, provider);
  const ents = provider?.filter?.entities || {};
  const rest = provider?.filter?.style === 'rest';
  const deny = rest ? [] : (provider?.filter?.deny || []).map((p) => globPat(p) ?? '*');
  const denyRoutes = rest ? (provider?.filter?.deny || []).map((p) => { const r = parseRoute(p, { deny: true }); return r.problem ? CLOSE_ALL : r; }) : [];
  if (!Object.keys(f.entities).length && !f.methods.length) errors.push(t('filter.err.no_entity'));
  for (const [id, fields] of Object.entries(f.entities)) {
    if (!fields.length) errors.push(t('filter.err.no_fields', { name: ents[id].name }));
    else if (fields.length > FILTER_LIMITS.fields) errors.push(t('filter.err.too_many_fields', { max: FILTER_LIMITS.fields }));
  }
  if (f.fields.length > FILTER_LIMITS.fields) errors.push(t('filter.err.too_many_fields', { max: FILTER_LIMITS.fields }));
  const flagRoutes = (id) => (f.flags?.[id] || []).reduce((n, fl) => n + (ents[id].extras?.[fl]?.routes?.length || 0), 0);
  const patterns = Object.keys(f.entities).reduce((n, id) => n + ((rest ? ents[id].routes : ents[id].methods)?.length || 0) + (rest ? flagRoutes(id) : 0), 0) + f.methods.length;
  if (patterns > FILTER_LIMITS.rules) errors.push(t('filter.err.too_many_rules', { max: FILTER_LIMITS.rules }));
  if (f.methods.length && !f.fields.length) errors.push(t('filter.err.methods_need_fields'));
  if (!f.methods.length && f.fields.length) errors.push(t('filter.err.fields_need_methods'));
  for (const m of f.methods) {
    if (rest) {
      // ручное правило REST: «GET /путь/*»; запись и «**» вне deny не принимаются (ТЗ §9.4)
      const r = parseRoute(m);
      if (r.problem === 'length' || r.problem === 'segments') errors.push(t('filter.err.route_size', { m, max: FILTER_LIMITS.segments, len: FILTER_LIMITS.patternLen }));
      else if (r.problem === 'rest') errors.push(t('filter.err.route_rest', { m }));
      else if (r.problem) errors.push(t('filter.err.route_syntax', { m }));
      else if (WRITE_METHODS.has(r.method)) errors.push(t('filter.err.route_write', { m }));
      else {
        // «:id» и «*» заменяются обычным значением: закрыт ли такой путь целиком
        const probe = r.segs.map((s) => (s.t === 'lit' ? s.v : 'x'));
        if (denyRoutes.some((rt) => matchRoute(rt, r.method, probe, true))) errors.push(t('filter.err.method_denied', { m }));
      }
    } else if (!/^[A-Za-z0-9_.*/-]{1,200}$/.test(m)) errors.push(t('filter.err.method_chars', { m }));
    else {
      const problem = globProblem(m);
      if (problem === 'stars') errors.push(t('filter.err.method_stars', { m, max: FILTER_LIMITS.stars }));
      else if (problem) errors.push(t('filter.err.method_segments', { m, max: FILTER_LIMITS.segments }));
      else if (matchesAny(deny, normalizeMethod(m))) errors.push(t('filter.err.method_denied', { m }));
    }
  }
  for (const x of [...Object.values(f.entities).flat(), ...f.fields]) {
    if (!/^[A-Za-z0-9_.[\]-]{1,200}$/.test(x)) errors.push(t('filter.err.field_chars', { x }));
    else if (pathParts(x).some((k) => RESERVED.has(k))) errors.push(t('filter.err.field_chars', { x }));
    else if (pathParts(x).length > FILTER_LIMITS.fieldDepth) errors.push(t('filter.err.field_depth', { x, max: FILTER_LIMITS.fieldDepth }));
  }
  return errors;
}

/**
 * Новый фильтр открывает больше текущего — нужен свежий код 2FA. Оба — в виде normalizeFilter.
 * Метод попадает под первое подходящее правило: тип данных раньше ручного. Поэтому удаление типа
 * при непустом ручном правиле тоже ослабление — его методы могут уйти под ручные поля (П-3).
 */
export function weakensFilter(next, current) {
  // снятие readOnly или mask открывает запись и персональные данные: свежий 2FA, даже если фильтр полей выключен
  if ((current?.readOnly && !next?.readOnly) || (current?.mask && !next?.mask)) return true;
  if (!current?.enabled) return false;
  if (!next?.enabled) return true;
  const ce = current.entities || {};
  const ne = next.entities || {};
  for (const [id, fields] of Object.entries(ne)) {
    if (!ce[id] || fields.some((x) => !ce[id].includes(x))) return true;
  }
  // новый флаг (search и т.п.) открывает больше; снятие — ужесточение
  const cfl = current.flags || {};
  for (const [id, fl] of Object.entries(next.flags || {})) if ((fl || []).some((x) => !(cfl[id] || []).includes(x))) return true;
  if ((next.methods || []).length && Object.keys(ce).some((id) => !ne[id])) return true;
  const cm = new Set(current.methods || []);
  const cf = new Set(current.fields || []);
  return (next.methods || []).some((m) => !cm.has(m)) || (next.fields || []).some((x) => !cf.has(x));
}
