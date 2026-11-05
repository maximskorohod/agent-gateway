import { t } from '../i18n.js';

// Разбор формы политики ключа (ТЗ §7)
import { normalizeFilter } from '../core/filter.js';

const TTL_ALLOWED = [300, 900, 3600, 7200, 28800, 86400];
const ALWAYS_FOR = [3600, 86400, 604800];

/** Новый срок «без вопросов» шире текущего (дольше или бессрочно) — такое включение требует свежего кода 2FA. */
export function widensAlways(policy, current = {}) {
  if (policy.mode !== 'always') return false;
  if (current.mode !== 'always') return true;
  if (current.always_until == null) return false;
  return policy.always_until == null || policy.always_until > current.always_until;
}

/**
 * Чувствительный сервис (sensitive: true в каталоге): включение или расширение режима «без вопросов»
 * требует отдельного подтверждения с текстом предупреждения (поле confirm_sensitive=1).
 * Свежий код 2FA на то же действие требует weakensPolicy/widensAlways — проверка кода остаётся в обработчике.
 * @returns {boolean} true — подтверждение нужно, а его нет
 */
export function sensitiveNeedsConfirm(policy, current, provider, body = {}) {
  if (!provider?.sensitive) return false;
  return widensAlways(policy, current ?? {}) && body.confirm_sensitive !== '1';
}

/**
 * Политика стала слабее текущей: такое сохранение требует свежего кода 2FA.
 * Слабее — шире «без вопросов», выход из «запретить», подтверждение без кода, выше лимиты,
 * снято или изменено окно, срок ключа продлён или снят.
 */
export function weakensPolicy(policy, current = {}) {
  if (widensAlways(policy, current)) return true;
  if (current.mode === 'deny' && policy.mode !== 'deny') return true;
  if (String(current.approval ?? '').endsWith('_code') && !String(policy.approval ?? '').endsWith('_code')) return true;
  for (const k of ['max_ttl', 'max_calls', 'max_parallel']) if (Number(policy[k]) > Number(current[k])) return true;
  if ('window' in policy && current.window && JSON.stringify(policy.window) !== JSON.stringify(current.window)) return true;
  if ('expires_at' in policy && current.expires_at != null && (policy.expires_at == null || policy.expires_at > current.expires_at)) return true;
  return false;
}

const lines = (v) => String(v ?? '').split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]).map((s) => String(s).trim()).filter(Boolean);
/**
 * Форма «Что видит агент» (ТЗ v1.3): выключатель, по каждому типу данных — галочка типа (ent_<id>),
 * галочки полей (f_<id>) и свои поля текстом (x_<id>); внизу другие методы и поля.
 * Запрос без скрытого поля entities_form (только выключатель) меняет лишь enabled, остальное берёт из current.
 * @returns {object} DataFilter
 */
export function parseFilter(body, provider, current = null) {
  const ents = provider?.filter?.entities || {};
  const cur = normalizeFilter(current, provider);
  // readOnly и mask (слой 1): галочки приходят вместе со скрытым полем protect_form, без него остаются как были
  const prot = body.protect_form === '1'
    ? { ...(body.read_only === '1' && { readOnly: true }), ...(body.mask === '1' && { mask: true }) }
    : { ...(cur.readOnly && { readOnly: true }), ...(cur.mask && { mask: true }) };
  // форма только с защитой (у сервиса нет типов данных) выключатель фильтра не шлёт: он остаётся как был
  const enabled = body.enabled === undefined && body.entities_form !== '1' && body.protect_form === '1' ? cur.enabled : body.enabled === '1';
  const { readOnly: _r, mask: _m, ...base } = cur;
  if (body.entities_form !== '1') return { ...base, enabled, ...prot };
  const entities = {};
  const flags = {};
  for (const id of Object.keys(ents)) {
    if (body[`ent_${id}`] !== '1') continue;
    entities[id] = [...new Set([...list(body[`f_${id}`]), ...lines(body[`x_${id}`])])];
    // явные флаги типа (fl_<id>: search, batch, export) — только те, что описаны в каталоге; пустые не храним
    const fl = [...new Set(list(body[`fl_${id}`]))].filter((x) => Object.hasOwn(ents[id].extras || {}, x));
    if (fl.length) flags[id] = fl;
  }
  return { enabled, entities, ...(Object.keys(flags).length && { flags }), methods: [...new Set(lines(body.methods))], fields: [...new Set(lines(body.fields_extra))], ...prot };
}

export function parsePolicy(body, { telegramConnected, current = {} }) {
  const out = {};
  const errors = [];
  const label = String(body.label ?? current.label ?? '').trim().slice(0, 60);
  out.label = label;
  const mode = body.mode ?? current.mode ?? 'ask';
  if (!['always', 'ask', 'deny'].includes(mode)) errors.push(t('policy.err.mode')); else out.mode = mode;
  // «Без вопросов на время»: always_for — секунды из списка, 'forever' или 'keep' (оставить текущий срок).
  // Без поля (старые формы, API) — бессрочно, как раньше.
  if (mode !== 'always') out.always_until = null;
  else {
    const f = String(body.always_for ?? 'forever');
    if (f === 'keep' && current.mode === 'always') out.always_until = current.always_until ?? null;
    else if (f === 'forever' || f === 'keep') out.always_until = null;
    else if (ALWAYS_FOR.includes(Number(f))) out.always_until = Math.floor(Date.now() / 1000) + Number(f);
    else errors.push(t('policy.err.always_for'));
  }
  let approval = body.approval ?? current.approval ?? (telegramConnected ? 'tg_button' : 'web_button');
  if (!['tg_button', 'tg_code', 'web_button', 'web_code'].includes(approval)) errors.push(t('policy.err.approval'));
  if (approval.startsWith('tg_') && !telegramConnected) approval = approval === 'tg_code' ? 'web_code' : 'web_button';
  out.approval = approval;
  const ttl = Number(body.max_ttl ?? current.max_ttl ?? 3600);
  out.max_ttl = TTL_ALLOWED.includes(ttl) ? ttl : 3600;
  const calls = Number(body.max_calls ?? current.max_calls ?? 100);
  if (!Number.isInteger(calls) || calls < 1 || calls > 100000) errors.push(t('policy.err.calls')); else out.max_calls = calls;
  const par = Number(body.max_parallel ?? current.max_parallel ?? 2);
  if (!Number.isInteger(par) || par < 1 || par > 20) errors.push(t('policy.err.parallel')); else out.max_parallel = par;
  // окно
  // Форма всегда шлёт from/to (даже пустые), а days не шлёт, когда все галочки сняты: это «окна нет», а не «не менять».
  let days = body.days;
  if (days === undefined && (body.from !== undefined || body.to !== undefined)) days = [];
  if (days === undefined) out.window = current.window ?? null;
  else {
    days = (Array.isArray(days) ? days : [days]).map(Number).filter((d) => d >= 1 && d <= 7);
    const hm = (v, def) => (/^\d{2}:\d{2}$/.test(String(v || '')) ? String(v) : def);
    out.window = days.length && days.length < 7 || body.from || body.to ? { days: days.length ? days : [1, 2, 3, 4, 5, 6, 7], from: hm(body.from, '00:00'), to: hm(body.to, '23:59') } : null;
    if (days.length === 0 && body.days !== undefined && (Array.isArray(body.days) ? body.days.length : body.days)) out.window = null;
  }
  // срок годности ключа
  const exp = String(body.expires_at ?? '').trim();
  if (!exp) out.expires_at = body.expires_at === undefined ? (current.expires_at ?? null) : null;
  else { const ts = Date.parse(exp + 'T23:59:59'); if (Number.isNaN(ts)) errors.push(t('policy.err.date')); else out.expires_at = Math.floor(ts / 1000); }
  return { policy: out, errors };
}
