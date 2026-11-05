// Каталог сервисов (ARCHITECTURE.md → catalog.js, ТЗ §4). Читает providers.yaml,
// валидирует его и нормализует ввод владельца в параметры подстановки.
import fs from 'node:fs';
import { parse } from 'yaml';
import { t, hasKey, providerHint } from './i18n.js';
import { globProblem, parseRoute, WRITE_METHODS, FILTER_LIMITS } from './core/filter.js';

const OWNER = 'owner';
const FIELDS = ['key', 'webhook_url', 'account', 'email', 'host', 'header'];
const OWNER_INPUT_FIELDS = ['webhook_url', 'account', 'host'];
const BUILDERS = ['static', 'webhook', 'subdomain', 'basic', 'other'];
const LABEL_RE = /^[a-z0-9-]{1,63}$/i;
const EMAIL_RE = /^[^\s:@/]+@[^\s:@/]+\.[^\s:@/]+$/;
const FIXED_REDACT = ['authorization', 'cookie', 'x-api-key'];
// Заголовки, которые владелец не может задать для «другого» сервиса: они ломают запрос шлюза.
const FORBIDDEN_OWNER_HEADERS = ['host', 'content-length', 'transfer-encoding', 'connection'];
const RESERVED_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain'];
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

function fail(message) {
  throw new Error(message);
}

function normHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.+$/, '');
}

/**
 * Проверка адреса владельца: доменное имя с точкой, не IP-адрес и не localhost.
 * Принимает голое имя хоста (без протокола и порта). Возвращает true/false.
 * @param {string} host
 * @returns {boolean}
 */
export function isValidOwnerHost(host) {
  if (typeof host !== 'string') return false;
  const h = normHost(host);
  if (h.length === 0 || h.length > 253) return false;
  if (RESERVED_SUFFIXES.some((suffix) => h.endsWith(suffix))) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return false;
  // Последняя метка из букв: отсекает IPv4 (10.0.0.1) и прочие числовые адреса.
  return /^[a-z]{2,}$/.test(labels[labels.length - 1]);
}

/** Разбор адреса: при отсутствии протокола подставляет https://. */
function parseAddress(s, { requireScheme = false, errText }) {
  const hasScheme = SCHEME_RE.test(s);
  if (!hasScheme && requireScheme) fail(errText);
  try {
    return new URL(hasScheme ? s : `https://${s}`);
  } catch {
    fail(errText);
  }
}

function checkUrlSafety(u) {
  if (u.username || u.password) fail(t('catalog.err.url_credentials'));
  if (u.port && u.port !== '443') fail(t('catalog.err.port'));
}

function checkOwnerHost(provider, host) {
  if (!isValidOwnerHost(host)) {
    fail(t('catalog.err.owner_host'));
  }
  if (provider.hostPattern && !new RegExp(provider.hostPattern).test(host)) {
    fail(t('catalog.err.host_mismatch', { name: provider.name }));
  }
}

/** Ключ: обрезка по краям, пустой или с пробелами внутри — ошибка. */
function cleanKey(raw) {
  const k = typeof raw === 'string' ? raw.trim() : '';
  if (!k) fail(t('catalog.err.key_empty'));
  if (/\s/.test(k)) fail(t('catalog.err.key_spaces'));
  return k;
}

function result(host, injection, kind, secret, last4) {
  return {
    host: normHost(host),
    injection: { ...injection },
    kind,
    last4: last4 ?? secret.slice(-4),
    secret,
  };
}

function buildStatic(provider, input) {
  const secret = cleanKey(input.key);
  return result(provider.host, provider.injection, provider.kind, secret);
}

function buildBitrix(provider, input) {
  const raw = typeof input.webhook_url === 'string' ? input.webhook_url.trim() : '';
  if (!raw) fail(t('catalog.err.webhook_empty'));
  if (/\s/.test(raw)) fail(t('catalog.err.webhook_spaces'));
  const errText = t('catalog.err.webhook_paste');
  const u = parseAddress(raw, { requireScheme: true, errText });
  if (u.protocol !== 'https:') fail(t('catalog.err.webhook_https'));
  checkUrlSafety(u);
  const host = normHost(u.hostname);
  checkOwnerHost(provider, host);
  const m = /^\/rest\/(\d+)\/([A-Za-z0-9]+)\/?/.exec(u.pathname);
  if (!m) fail(t('catalog.err.webhook_path'));
  const [, userId, code] = m;
  // Ссылку-пример из подсказки не принимаем: это не настоящий вебхук.
  if (provider.keyHint?.includes(`/rest/${userId}/${code}/`)) {
    fail(t('catalog.err.webhook_example'));
  }
  // Остаток пути после секрета игнорируется.
  return result(host, provider.injection, provider.kind, `${userId}/${code}`, code.slice(-4));
}

/**
 * Адрес аккаунта по шаблону провайдера: метка DNS («mycompany») подставляется в hostTemplate,
 * иначе принимается полный адрес/URL; итог обязан пройти hostPattern.
 */
function subdomainHost(provider, raw) {
  const s = typeof raw === 'string' ? raw.trim() : '';
  const errText = t('catalog.err.account_prompt');
  if (!s || /\s/.test(s)) fail(errText);
  let host;
  if (LABEL_RE.test(s)) {
    host = normHost(provider.hostTemplate.replace('{account}', s.toLowerCase()));
  } else {
    const u = parseAddress(s, { errText });
    if (u.protocol !== 'https:') fail(t('catalog.err.account_https'));
    checkUrlSafety(u);
    host = normHost(u.hostname);
  }
  checkOwnerHost(provider, host);
  return host;
}

function buildSubdomain(provider, input) {
  const host = subdomainHost(provider, input.account);
  const secret = cleanKey(input.key);
  return result(host, provider.injection, provider.kind, secret);
}

/** Логин Basic из ввода: Account SID (фиксированный хост) или `email/token` (Zendesk). */
function basicLogin(provider, input) {
  const tpl = provider.basicLogin || '{account}';
  let account = '';
  let email = '';
  if (tpl.includes('{account}')) {
    account = typeof input.account === 'string' ? input.account.trim() : '';
    const ok = account && !/[\s:]/.test(account)
      && (!provider.accountPattern || new RegExp(provider.accountPattern).test(account));
    if (!ok) fail(t('catalog.err.account_format', { hint: providerHint(provider) || t('catalog.err.key_format_default') }));
  }
  if (tpl.includes('{email}')) {
    email = typeof input.email === 'string' ? input.email.trim() : '';
    if (!email || email.length > 254 || !EMAIL_RE.test(email)) fail(t('catalog.err.email'));
  }
  return tpl.replace('{account}', () => account).replace('{email}', () => email);
}

/** HTTP Basic (encode: base64): в сейфе `логин:ключ`, прокси ставит prefix + base64(секрет). */
function buildBasic(provider, input) {
  // Хост — только из каталога либо из account по hostTemplate; у фиксированного хоста account в адрес не попадает.
  const host = provider.host === OWNER ? subdomainHost(provider, input.account) : provider.host;
  const login = basicLogin(provider, input);
  const key = cleanKey(input.key);
  return result(host, provider.injection, provider.kind, `${login}:${key}`, key.slice(-4));
}

/** Адрес API для «другого» сервиса: только https, порт 443, доменное имя. Путь игнорируется. */
function otherHost(raw) {
  const s = typeof raw === 'string' ? raw.trim() : '';
  const errText = t('catalog.err.api_prompt');
  if (!s || /\s/.test(s)) fail(errText);
  const u = parseAddress(s, { errText });
  if (u.protocol !== 'https:') fail(t('catalog.err.api_https'));
  checkUrlSafety(u);
  const host = normHost(u.hostname);
  if (!isValidOwnerHost(host)) {
    fail(t('catalog.err.api_domain'));
  }
  return host;
}

function headerName(raw) {
  const s = typeof raw === 'string' ? raw.trim() : '';
  if (!/^[A-Za-z0-9-]{1,64}$/.test(s)) {
    fail(t('catalog.err.header_name'));
  }
  const name = s.toLowerCase();
  if (FORBIDDEN_OWNER_HEADERS.includes(name)) fail(t('catalog.err.header_forbidden', { name }));
  return name;
}

function buildOther(provider, input) {
  const host = otherHost(input.host);
  const name = headerName(input.header);
  const secret = cleanKey(input.key);
  const injection = { type: 'header', name };
  if (name === 'authorization' && !/^(Bearer|Token|Basic) /i.test(secret)) {
    injection.prefix = 'Bearer ';
  }
  return result(host, injection, provider.kind, secret);
}

/**
 * Собирает параметры подстановки из ввода владельца.
 * @param {object} provider — запись каталога (см. Provider в ARCHITECTURE.md)
 * @param {{key?:string, webhook_url?:string, account?:string, host?:string, header?:string}} ownerInput
 * @returns {{host:string, injection:object, kind:string, last4:string, secret:string}}
 * @throws {Error} с текстом для владельца на языке интерфейса
 */
export function buildInjection(provider, ownerInput) {
  const build = BUILDERS_IMPL[provider.builder || 'static'];
  if (!build) fail(`providers.yaml, "${provider.slug}": unknown builder`);
  return build(provider, ownerInput || {});
}

// Выбор разбора — по типу провайдера (builder), а не по набору полей (П-23).
const BUILDERS_IMPL = {
  static: buildStatic,
  webhook: buildBitrix,
  subdomain: buildSubdomain,
  basic: buildBasic,
  other: buildOther,
};

/** Формы секрета, которые нужно вычищать из ответов: сырая, URL-кодированная, base64; для Basic ещё отдельно ключ. */
function secretForms(provider, secret) {
  if (typeof secret !== 'string' || !secret) return [];
  const bases = [secret];
  if (provider?.builder === 'basic') {
    const i = secret.indexOf(':');
    if (i >= 0) bases.push(secret.slice(i + 1));
  }
  // Вебхук «id/код»: сам код и есть секрет, сервис может вернуть его отдельно от id
  if (provider?.builder === 'webhook') {
    const i = secret.lastIndexOf('/');
    if (i >= 0) bases.push(secret.slice(i + 1));
  }
  const out = new Set();
  for (const s of bases) {
    out.add(s);
    out.add(encodeURIComponent(s));
    out.add(Buffer.from(s, 'utf8').toString('base64'));
    // JSON-экранированная форма (", \, управляющие) и вариант с \uXXXX для не-ASCII: сервис может отдать секрет в JSON-строке
    const j = JSON.stringify(s).slice(1, -1);
    const u = (hex) => j.replace(/[^\x00-\x7f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')[hex]()}`);
    // PHP json_encode по умолчанию пишет «/» как «\/», так отвечает Bitrix24
    for (const form of [j, u('toLowerCase'), u('toUpperCase')]) {
      out.add(form);
      out.add(form.replaceAll('/', '\\/'));
    }
  }
  // Длинные формы первыми: короткая не должна разрезать длинную до замены.
  return [...out].filter((s) => s.length >= 4).sort((a, b) => b.length - a.length);
}

/**
 * Проверяет формат ключа по keyPattern каталога.
 * @returns {string|null} null — формат подходит или шаблона нет
 */
export function validateKeyFormat(provider, key) {
  if (!provider.keyPattern) return null;
  const k = typeof key === 'string' ? key.trim() : '';
  if (new RegExp(provider.keyPattern).test(k)) return null;
  return t('catalog.err.wrong_key', { hint: providerHint(provider) || t('catalog.err.key_format_default') });
}

function normalizeProvider(slug, raw, defaults) {
  const p = { ...defaults, ...(raw || {}) };
  const bad = (msg) => fail(`providers.yaml, "${slug}": ${msg}`);

  if (!/^[a-z][a-z0-9-]*$/.test(slug)) bad('invalid slug');
  if (typeof p.name !== 'string' || !p.name.trim()) bad('name is missing');
  if (typeof p.host !== 'string') bad('host is missing');
  const host = p.host === OWNER ? OWNER : normHost(p.host);
  if (host !== OWNER && !isValidOwnerHost(host)) bad('host must be a domain name');

  const inj = p.injection;
  if (!inj || typeof inj !== 'object') bad('injection is missing');
  if (inj.type === 'header') {
    if (typeof inj.name !== 'string' || !/^[A-Za-z0-9-]+$/.test(inj.name)) bad('invalid header name');
  } else if (inj.type === 'path') {
    if (typeof inj.template !== 'string' || !inj.template.includes('{secret}')) {
      bad('path template must contain {secret}');
    }
  } else {
    bad('injection.type must be header or path');
  }

  if (!['static', 'path'].includes(p.kind)) bad('kind must be static or path');
  if (!Number.isFinite(p.maxBody) || p.maxBody <= 0) bad('maxBody must be a positive number');
  if (!Number.isFinite(p.timeout) || p.timeout <= 0) bad('timeout must be a positive number');
  if (!Array.isArray(p.fields) || p.fields.some((f) => !FIELDS.includes(f))) {
    bad('fields must be an array of allowed fields');
  }
  if (host === OWNER && !p.fields.some((f) => OWNER_INPUT_FIELDS.includes(f))) {
    bad('host: owner requires an address input field');
  }

  // Тип разбора ввода (П-23). 'other' — только у slug other.
  const builder = p.builder === undefined ? (slug === 'other' ? 'other' : 'static') : p.builder;
  if (!BUILDERS.includes(builder)) bad(`builder must be one of: ${BUILDERS.join(', ')}`);
  if ((builder === 'other') !== (slug === 'other')) bad("builder 'other' is allowed only for slug other");
  if (host !== OWNER) {
    // Инвариант: фиксированный хост не зависит от ввода владельца.
    if (p.fields.includes('host') || p.fields.includes('webhook_url')) bad('a fixed host is incompatible with the host/webhook_url field');
    if (['subdomain', 'webhook', 'other'].includes(builder)) bad(`a fixed host is incompatible with builder ${builder}`);
    if (p.hostTemplate !== undefined || p.hostPattern !== undefined) bad('hostTemplate/hostPattern are only for host: owner');
    if (builder === 'static' && p.fields.some((f) => f !== 'key')) bad('static accepts only the key field');
  } else {
    if (builder === 'static') bad('host: owner is incompatible with builder static');
    if (builder === 'webhook' && !p.fields.includes('webhook_url')) bad('builder webhook requires the webhook_url field');
    if (builder === 'other' && !['host', 'header', 'key'].every((f) => p.fields.includes(f))) bad('builder other requires the host, header, key fields');
    if (builder === 'subdomain' || builder === 'basic') {
      if (!p.fields.includes('account')) bad(`builder ${builder} with host: owner requires the account field`);
      if (typeof p.hostTemplate !== 'string' || !/^\{account\}\.[a-z0-9.-]+\.[a-z]{2,}$/.test(p.hostTemplate)) {
        bad('hostTemplate must look like "{account}.example.com"');
      }
      if (typeof p.hostPattern !== 'string') bad('hostPattern is required');
    }
  }
  if (builder === 'basic') {
    if (inj.type !== 'header' || inj.encode !== 'base64') bad('basic requires injection: header with encode: base64');
    if (!p.fields.includes('key')) bad('basic requires the key field');
    const tpl = p.basicLogin || '{account}';
    if (!/^(\{account\}|\{email\}\/token|\{email\})$/.test(tpl)) bad('basicLogin must be {account}, {email}/token or {email}');
    if (tpl.includes('{account}') && host !== OWNER && typeof p.accountPattern !== 'string') bad('accountPattern is required');
    if (tpl.includes('{email}') && !p.fields.includes('email')) bad('{email} in basicLogin requires the email field');
    if (tpl.includes('{account}') && !p.fields.includes('account')) bad('{account} in basicLogin requires the account field');
  } else if (inj.encode !== undefined || p.basicLogin !== undefined || p.accountPattern !== undefined || p.fields.includes('email')) {
    bad('encode/basicLogin/accountPattern/email are allowed only with builder basic');
  }
  if (inj.encode !== undefined && inj.encode !== 'base64') bad('encode can only be base64');

  // Подсказки получения ключа и флаги (ТЗ §4)
  if (p.getKeyUrl !== undefined) {
    let u;
    try { u = new URL(p.getKeyUrl); } catch { bad('getKeyUrl is not a valid URL'); }
    if (u.protocol !== 'https:' || u.username || u.password) bad('getKeyUrl must be an https URL without credentials');
  }
  if (p.getKeyHint !== undefined && typeof p.getKeyHint !== 'string') bad('getKeyHint must be a string');
  if (p.onboarding !== undefined && typeof p.onboarding !== 'boolean') bad('onboarding must be a boolean');
  if (p.accountPlaceholder !== undefined) {
    if (typeof p.accountPlaceholder !== 'string' || !p.accountPlaceholder.trim() || p.accountPlaceholder.length > 60) bad('accountPlaceholder must be a short string (up to 60 characters)');
    if (!p.fields.includes('account')) bad('accountPlaceholder is only for the account field');
  }
  for (const flag of ['sensitive', 'warning', 'demoOnly']) {
    if (p[flag] !== undefined && typeof p[flag] !== 'boolean') bad(`${flag} must be true or false`);
  }
  if (p.filterFrom !== undefined && (typeof p.filterFrom !== 'string' || p.filter !== undefined)) {
    bad('filterFrom must be the slug of another provider, with no own filter');
  }
  for (const key of ['keyPattern', 'hostPattern', 'accountPattern']) {
    if (p[key] === undefined) continue;
    try {
      new RegExp(p[key]);
    } catch {
      bad(`${key} is not a valid regular expression`);
    }
  }

  if (p.filter !== undefined) checkProviderFilter(p.filter, bad);
  const readOnly = normalizeReadOnly(p.readOnly, bad);
  if (p.mask !== undefined && typeof p.mask !== 'boolean') bad('mask must be true or false');

  const key = `catalog.name.${slug}`;
  const filter = p.filter === undefined ? undefined : translateFilter(slug, p.filter);
  const { readOnly: _ro, ...rest } = p;
  return { ...rest, name: hasKey(key) ? t(key) : p.name, slug, host, builder, icon: slug, ...(filter && { filter }), ...(readOnly && { readOnly }) };
}

/**
 * Описание чтения для readOnly (п. 7.2). Нет поля или false — readOnly у сервиса недоступен (запись неотличима от чтения).
 * true — REST: разрешены GET и HEAD. Объект: style 'rest' (extraRoutes — POST-маршруты чтения вида "POST /v1/search")
 * или 'rpc' (readMethods — шаблоны методов, у Bitrix24 и Telegram); default: true — у новых ключей чтение включено сразу.
 */
function normalizeReadOnly(v, bad) {
  if (v === undefined || v === false) return undefined;
  if (v === true) return { style: 'rest', extraRoutes: [], readMethods: [], default: false };
  if (!v || typeof v !== 'object' || Array.isArray(v)) bad('readOnly must be true, false or an object');
  const style = v.style === undefined ? 'rest' : v.style;
  if (!['rest', 'rpc'].includes(style)) bad("readOnly.style must be 'rest' or 'rpc'");
  const strings = (x) => Array.isArray(x) && x.every((s) => typeof s === 'string' && s.length > 0);
  if (v.default !== undefined && typeof v.default !== 'boolean') bad('readOnly.default must be true or false');
  const extraRoutes = v.extraRoutes ?? [];
  const readMethods = v.readMethods ?? [];
  if (!strings(extraRoutes) || !strings(readMethods)) bad('readOnly.extraRoutes and readOnly.readMethods must be lists of strings');
  if (style === 'rpc') {
    if (extraRoutes.length) bad('readOnly.extraRoutes is only for style: rest');
    if (!readMethods.length) bad('readOnly.readMethods is required for style: rpc');
    if (readMethods.length > FILTER_LIMITS.rules) bad(`readOnly.readMethods: at most ${FILTER_LIMITS.rules} rules`);
    for (const m of readMethods) { const pr = globProblem(m); if (pr) bad(`readOnly.readMethods: pattern "${m}" is not allowed (${pr})`); }
  } else {
    if (readMethods.length) bad('readOnly.readMethods is only for style: rpc');
    if (extraRoutes.length > FILTER_LIMITS.rules) bad(`readOnly.extraRoutes: at most ${FILTER_LIMITS.rules} rules`);
    for (const r of extraRoutes) { const pr = parseRoute(r); if (pr.problem) bad(`readOnly.extraRoutes: route "${r}" is not allowed (${pr.problem})`); }
  }
  return { style, extraRoutes: [...extraRoutes], readMethods: [...readMethods], default: v.default === true };
}

/** Подписи типов и полей фильтра: словарь `catalog.filter.<slug>.<тип>` и `catalog.field.<slug>.<тип>.<путь>`, запасной вариант — из providers.yaml */
function translateFilter(slug, f) {
  const tr = (key, fallback) => (hasKey(key) ? t(key) : fallback);
  const entities = Object.fromEntries(Object.entries(f.entities).map(([id, e]) => [id, {
    ...e,
    name: tr(`catalog.filter.${slug}.${id}`, e.name),
    // у поля с несколькими формами ответа (paths) идентификатором для галочки служит первая форма
    fields: e.fields.map((x) => {
      const path = x.path ?? x.paths[0];
      return { ...x, path, label: tr(`catalog.field.${slug}.${id}.${path}`, x.label) };
    }),
    ...(e.extras && { extras: Object.fromEntries(Object.entries(e.extras).map(([fl, x]) => [fl, { ...x, label: tr(`catalog.filter.${slug}.${id}.${fl}`, x.label) }])) }),
  }]));
  return { ...f, entities };
}

/** Фильтр данных в каталоге (ТЗ v1.3): списки строк, типы данных с полями, defaults только из своих полей. */
function checkProviderFilter(f, bad) {
  const strings = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  if (!f || typeof f !== 'object') bad('filter must be an object');
  for (const k of ['keep', 'deny', 'selectFor', 'denyQuery']) if (!strings(f[k] ?? [])) bad(`filter.${k} must be a list of strings`);
  if (!f.entities || typeof f.entities !== 'object' || !Object.keys(f.entities).length) bad('filter.entities: at least one data type is required');
  // стиль правил (П-17): rpc — шаблоны методов Bitrix24, rest — «МЕТОД /маршрут»
  if (f.style !== undefined && !['rpc', 'rest'].includes(f.style)) bad("filter.style must be 'rpc' or 'rest'");
  const rest = f.style === 'rest';
  if (f.methodAgnostic !== undefined && typeof f.methodAgnostic !== 'boolean') bad('filter.methodAgnostic must be true or false');
  if (rest && f.methodAgnostic === true) bad('filter.methodAgnostic is not allowed with style: rest');
  if (f.selectFormat !== undefined && !['repeat[]', 'comma'].includes(f.selectFormat)) bad("filter.selectFormat must be 'repeat[]' or 'comma'");
  if (f.denyQuery !== undefined && !rest) bad('filter.denyQuery is only for style: rest');
  // unverified: поля взяты из документации, живой проверки не было (интерфейс показывает пометку)
  if (f.unverified !== undefined && typeof f.unverified !== 'boolean') bad('filter.unverified must be true or false');
  // лимиты матчера и полей (П-27, П-28)
  const depth = (p) => String(p).split('.').filter(Boolean).length;
  const lim = (name, v, max) => { if (v !== undefined && (!Number.isInteger(v) || v < 1 || v > max)) bad(`filter.${name}: integer from 1 to ${max}`); };
  lim('keepMaxLen', f.keepMaxLen, FILTER_LIMITS.maxFieldLen);
  lim('maxFieldLen', f.maxFieldLen, FILTER_LIMITS.maxFieldLen);
  // rest: deny и selectFor разбирает parseRoute; метод записи допустим только в deny и extras
  const routeCheck = (where, p, { deny = false, write = false } = {}) => {
    const r = parseRoute(p, { deny });
    if (r.problem) bad(`${where}: route "${p}" is not allowed (${r.problem}); form "METHOD /path/:id/*", at most ${FILTER_LIMITS.segments} segments, ${FILTER_LIMITS.patternLen} characters${deny ? '' : ', "**" only in deny'}`);
    if (!write && WRITE_METHODS.has(r.method)) bad(`${where}: route "${p}" uses a write method; open it only through extras`);
  };
  if (f.deny && f.deny.length > FILTER_LIMITS.rules) bad(`filter.deny: at most ${FILTER_LIMITS.rules} rules`);
  for (const p of f.deny ?? []) {
    if (rest) routeCheck('filter.deny', p, { deny: true, write: true });
    else { const pr = globProblem(p); if (pr) bad(`filter.deny: pattern "${p}" is not allowed (${pr}); at most ${FILTER_LIMITS.stars} stars, ${FILTER_LIMITS.segments} segments, ${FILTER_LIMITS.patternLen} characters`); }
  }
  for (const p of f.selectFor ?? []) {
    if (rest) routeCheck('filter.selectFor', p);
    else { const pr = globProblem(p); if (pr) bad(`filter.selectFor: pattern "${p}" is not allowed (${pr}); at most ${FILTER_LIMITS.stars} stars, ${FILTER_LIMITS.segments} segments, ${FILTER_LIMITS.patternLen} characters`); }
  }
  for (const p of f.keep ?? []) if (depth(p) > FILTER_LIMITS.fieldDepth) bad(`filter.keep: path "${p}" is deeper than ${FILTER_LIMITS.fieldDepth} levels`);
  const fieldPaths = (x) => (Array.isArray(x?.paths) ? x.paths : []).concat(typeof x?.path === 'string' ? [x.path] : []);
  for (const [id, e] of Object.entries(f.entities)) {
    if (rest) {
      if (e?.methods !== undefined) bad(`filter.entities.${id}: methods is only for style: rpc; use routes`);
      if (!strings(e?.routes ?? []) || !(e?.routes ?? []).length) bad(`filter.entities.${id}: routes are required (list of "METHOD /path")`);
      for (const p of e.routes) routeCheck(`filter.entities.${id}.routes`, p);
      const extras = e.extras ?? {};
      if (!extras || typeof extras !== 'object' || Array.isArray(extras)) bad(`filter.entities.${id}.extras must be an object`);
      let total = e.routes.length;
      for (const [fl, x] of Object.entries(extras)) {
        if (!['search', 'batch', 'export'].includes(fl)) bad(`filter.entities.${id}.extras: unknown flag "${fl}"`);
        if (typeof x?.label !== 'string' || !x.label.trim() || !strings(x.routes) || !x.routes.length) bad(`filter.entities.${id}.extras.${fl}: label and routes are required`);
        for (const p of x.routes) routeCheck(`filter.entities.${id}.extras.${fl}`, p, { write: true });
        total += x.routes.length;
      }
      if (total > FILTER_LIMITS.rules) bad(`filter.entities.${id}: at most ${FILTER_LIMITS.rules} rules (routes and extras)`);
    } else {
      if (e?.routes !== undefined || e?.extras !== undefined) bad(`filter.entities.${id}: routes and extras are only for style: rest`);
      for (const p of e?.methods ?? []) { const pr = globProblem(p); if (pr) bad(`filter.entities.${id}.methods: pattern "${p}" is not allowed (${pr})`); }
      if ((e?.methods ?? []).length > FILTER_LIMITS.rules) bad(`filter.entities.${id}.methods: at most ${FILTER_LIMITS.rules} rules`);
    }
    if (Array.isArray(e?.fields) && e.fields.length > FILTER_LIMITS.fields) bad(`filter.entities.${id}.fields: at most ${FILTER_LIMITS.fields} fields`);
    for (const x of Array.isArray(e?.fields) ? e.fields : []) {
      if (x?.object !== undefined && x.object !== true) bad(`filter.entities.${id}.fields: object can only be true`);
      for (const p of fieldPaths(x)) if (depth(p) > FILTER_LIMITS.fieldDepth) bad(`filter.entities.${id}.fields: path "${p}" is deeper than ${FILTER_LIMITS.fieldDepth} levels`);
    }
  }
  for (const [id, e] of Object.entries(f.entities)) {
    if (!/^[a-z0-9_]+$/.test(id)) bad(`filter.entities.${id}: type name must be lowercase latin`);
    if (typeof e?.name !== 'string' || (!rest && !strings(e.methods))) bad(`filter.entities.${id}: name and methods are required`);
    // поле: path или paths (несколько форм ответа: список и одиночный объект) и подпись
    const okField = (x) => typeof x?.label === 'string' && (typeof x.path === 'string' || (Array.isArray(x.paths) && x.paths.length && x.paths.every((p) => typeof p === 'string' && p)));
    if (!Array.isArray(e.fields) || !e.fields.length || !e.fields.every(okField)) {
      bad(`filter.entities.${id}.fields: must be a list of {path|paths, label}`);
    }
    if (!rest && e.fields.some((x) => x.paths !== undefined)) bad(`filter.entities.${id}.fields: paths is only for style: rest`);
    const known = new Set(e.fields.flatMap(fieldPaths));
    if (!strings(e.defaults ?? [])) bad(`filter.entities.${id}.defaults must be a list of strings`);
    const unknown = (e.defaults ?? []).find((x) => !known.has(x));
    if (unknown) bad(`filter.entities.${id}: defaults field ${unknown} is not described in fields`);
  }
}

/**
 * Загружает и валидирует каталог.
 * @param {string} yamlPath
 * @param {{ demo?: boolean }} [opts] demo (GW_DEMO=1): в каталоге остаются только провайдеры с demoOnly: true;
 *   вне демо такие провайдеры скрыты
 * @returns {{providers: Map<string, object>, get: (slug:string) => object|undefined,
 *   list: () => object[], redactHeaders: () => string[]}}
 */
export function loadCatalog(yamlPath, { demo = false } = {}) {
  const doc = parse(fs.readFileSync(yamlPath, 'utf8')) || {};
  const defaults = doc.defaults || {};
  const all = new Map();
  for (const [slug, raw] of Object.entries(doc.providers || {})) {
    all.set(slug, normalizeProvider(slug, raw, defaults));
  }
  // filterFrom: копия уже переведённого фильтра другого провайдера (bitrix24-box ← bitrix24)
  for (const p of all.values()) {
    if (p.filterFrom === undefined) continue;
    const src = all.get(p.filterFrom);
    if (!src || src === p || !src.filter) fail(`providers.yaml, "${p.slug}": filterFrom has no provider "${p.filterFrom}" with a filter`);
    p.filter = structuredClone(src.filter);
    if (src.readOnly && !p.readOnly) p.readOnly = structuredClone(src.readOnly);
  }
  // демо-каталог: только demoOnly; обычный: demoOnly скрыт
  const providers = new Map([...all].filter(([, p]) => (p.demoOnly === true) === demo));
  if (demo && !providers.size) fail('providers.yaml: demo mode requires a provider with demoOnly: true');

  return {
    providers,
    /** Формы секрета для редактора ответов и логов (Н-7): сырая, URL-кодированная, base64, для Basic ещё ключ. */
    secretForms,
    get: (slug) => providers.get(slug),
    list: () => [...providers.values()],
    redactHeaders() {
      const names = new Set(FIXED_REDACT);
      for (const p of providers.values()) {
        if (p.injection.type === 'header') names.add(p.injection.name.toLowerCase());
      }
      return [...names];
    },
  };
}
