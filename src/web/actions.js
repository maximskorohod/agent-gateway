// Общий реестр действий сайта, которым может понадобиться свежий код 2FA (П-19).
// Маршрут и исполнение черновика вызывают одну и ту же запись реестра: проверки не дублируются.
// apply синхронный (без await): его вызывают и внутри транзакции pending.apply.
// Контракт: docs/contracts/drafts-team-auth.md, раздел «Общий реестр действий».
import crypto from 'node:crypto';
import { parsePolicy, parseFilter, widensAlways, weakensPolicy, sensitiveNeedsConfirm } from './policy.js';
import { checkFilter, weakensFilter, normalizeFilter, protectionOf } from '../core/filter.js';
import { sha256hex } from '../auth/links.js';
import { errorPage } from './views/error.js';
import { agentCreated } from './views/agents.js';
import { welcomeAgentCreated } from './views/welcome.js';
import { isKind, agentNameOf } from './onboarding.js';
import { fmtDate, keyName } from './views/html.js';
import { t, hasKey } from '../i18n.js';
import { EVENTS, readChannelMeta, writeChannelMeta } from '../notify.js';

/**
 * @typedef {{ userId:string, user:object, sessionHash:string, hasRecentTotp:boolean, repo:object, catalog:object,
 *   now:()=>number, csrf?:string, telegramConnected?:boolean }} ActionCtx
 * csrf нужен только действиям с html-ответом (agent.create), telegramConnected — разбору политики.
 */

const digest = (v) => sha256hex(JSON.stringify(v));
const DASH = '—';
const yes = (b) => t(b ? 'pending.yes' : 'pending.no');

// ---- ключи: политика и фильтр

const POLICY_KEYS = ['label', 'mode', 'approval', 'max_ttl', 'max_calls', 'max_parallel', 'window', 'expires_at', 'always_until'];
const policyState = (c) => POLICY_KEYS.map((k) => c[k] ?? null);

/** Политика → { подпись: значение } для страницы «было → стало». */
function policyView(p) {
  const win = p.window ? `${(p.window.days || []).join(',')} ${p.window.from}-${p.window.to}` : t('pending.window_none');
  return {
    [t('pending.f.label')]: p.label || DASH,
    [t('pending.f.mode')]: hasKey(`policy.mode.${p.mode}`) ? t(`policy.mode.${p.mode}`) : String(p.mode),
    [t('pending.f.always_until')]: p.mode === 'always' ? (p.always_until ? fmtDate(p.always_until) : t('pending.forever')) : DASH,
    [t('pending.f.approval')]: hasKey(`policy.approval.${p.approval}`) ? t(`policy.approval.${p.approval}`) : String(p.approval),
    [t('pending.f.max_ttl')]: `${p.max_ttl} ${t('unit.s')}`,
    [t('pending.f.max_calls')]: String(p.max_calls),
    [t('pending.f.max_parallel')]: String(p.max_parallel),
    [t('pending.f.window')]: win,
    [t('pending.f.expires_at')]: p.expires_at ? fmtDate(p.expires_at) : t('pending.no_expiry'),
  };
}

/** Оставляет только отличающиеся поля: на странице видно ровно то, что изменится. */
function changed(before, after) {
  const b = {}; const a = {};
  for (const k of Object.keys(after)) if (before[k] !== after[k]) { b[k] = before[k] ?? DASH; a[k] = after[k]; }
  return { before: b, after: a };
}

const keyNotFound = () => ({ code: 404, html: errorPage(404, t('error.key_not_found')) });
const keyBack = (id) => `/keys/${encodeURIComponent(id)}`;

const keyPolicy = {
  type: 'key.policy',
  perm: 'key.policy',
  fields: ['label', 'mode', 'always_for', 'approval', 'max_ttl', 'max_calls', 'max_parallel', 'days', 'from', 'to', 'expires_at', 'confirm_sensitive'],
  targetOf: (params) => String(params.id ?? ''),
  version(ctx, id) {
    const c = ctx.repo.getCredential(id);
    return c ? digest(policyState(c)) : null; // удалённый ключ (deleted_at) = нет цели
  },
  parse(ctx, id, body) {
    const cred = ctx.repo.getCredential(id);
    const { policy, errors } = parsePolicy(body, { telegramConnected: !!ctx.telegramConnected, current: cred });
    // стёртое имя ключа — имя сервиса, как при создании (пустое имя: «Key “”» в заголовках и списках)
    if (!policy.label) policy.label = ctx.catalog.get(cred.provider)?.name || cred.provider;
    // «без вопросов» на чувствительном сервисе — только с отдельным подтверждением (до проверки кода 2FA)
    if (!errors.length && sensitiveNeedsConfirm(policy, cred, ctx.catalog.get(cred.provider), body)) errors.push(t('flash.sensitive_needs_confirm'));
    return { input: { policy }, errors };
  },
  needsFresh: (ctx, id, input) => weakensPolicy(input.policy, ctx.repo.getCredential(id)),
  apply(ctx, id, input, { fromDraft = false } = {}) {
    ctx.repo.updateCredentialPolicy(id, input.policy);
    ctx.repo.audit(ctx.userId, 'credential.policy', id, fromDraft ? { ...input.policy, via: 'draft' } : input.policy);
    return { redirect: keyBack(id), flash: { type: 'ok', text: t('flash.settings_saved') } };
  },
  summary(ctx, id, input) {
    const cred = ctx.repo.getCredential(id);
    const d = changed(policyView(cred), policyView(input.policy));
    return { title: t('pending.title.key_policy', { name: keyName(cred, ctx.catalog.list()) }), ...d };
  },
  back: keyBack,
  notFound: keyNotFound,
};

const filterProvider = (ctx, id) => { const c = ctx.repo.getCredential(id); return c ? ctx.catalog.get(c.provider) : null; };

const keyFilter = {
  type: 'key.filter',
  perm: 'key.filter',
  // типы данных приходят как ent_<id>, f_<id>, x_<id>: имена зависят от каталога сервиса
  fields: ['enabled', 'entities_form', 'protect_form', 'read_only', 'mask', 'methods', 'fields_extra', /^(?:ent|f|x|fl)_[A-Za-z0-9_.-]{1,64}$/],
  targetOf: (params) => String(params.id ?? ''),
  version(ctx, id) {
    const c = ctx.repo.getCredential(id);
    const p = filterProvider(ctx, id);
    // слой 1 действует у любого провайдера: форма сохраняется всегда, недоступное (readOnly у OpenAI) отклоняет checkFilter
    if (!c || !p) return null;
    return digest(c.filter ?? null);
  },
  parse(ctx, id, body) {
    const cred = ctx.repo.getCredential(id);
    const provider = ctx.catalog.get(cred.provider);
    const next = parseFilter(body, provider, cred.filter);
    return { input: { next }, errors: checkFilter(next, provider) };
  },
  needsFresh(ctx, id, input) {
    const cred = ctx.repo.getCredential(id);
    return weakensFilter(input.next, normalizeFilter(cred.filter, ctx.catalog.get(cred.provider)));
  },
  apply(ctx, id, input, { fromDraft = false } = {}) {
    const cred = ctx.repo.getCredential(id);
    const weakened = weakensFilter(input.next, normalizeFilter(cred.filter, ctx.catalog.get(cred.provider)));
    ctx.repo.updateCredentialFilter(id, input.next);
    if (weakened) ctx.notify?.security(t('notify.sec.filter_weakened', { name: keyName(cred, ctx.catalog.list()) }));
    ctx.repo.audit(ctx.userId, 'filter.changed', id, { before: cred.filter, after: input.next, ...(fromDraft ? { via: 'draft' } : {}) });
    return { redirect: keyBack(id), flash: { type: 'ok', text: input.next.enabled || input.next.readOnly || input.next.mask ? t('flash.filter_saved') : t('flash.filter_off') } };
  },
  summary(ctx, id, input) {
    const cred = ctx.repo.getCredential(id);
    const provider = ctx.catalog.get(cred.provider);
    const ents = provider?.filter?.entities || {};
    const view = (f) => {
      const out = {};
      // слой 1 показываем только у сервисов, где он доступен; «было → стало» покажет, что именно меняется
      if (protectionOf(provider).readOnly) out[t('pending.f.read_only')] = yes(!!f.readOnly);
      if (protectionOf(provider).mask) out[t('pending.f.mask')] = yes(!!f.mask);
      if (provider?.filter) out[t('pending.f.filter')] = yes(f.enabled);
      for (const eid of Object.keys(ents)) {
        out[ents[eid].name || eid] = f.entities?.[eid] ? (f.entities[eid].join(', ') || DASH) : t('pending.hidden');
        if (f.flags?.[eid]?.length) out[`${ents[eid].name || eid}: ${t('pending.f.flags')}`] = f.flags[eid].map((x) => ents[eid].extras?.[x]?.label || x).join(', ');
      }
      out[t('pending.f.methods')] = (f.methods || []).join(', ') || DASH;
      out[t('pending.f.fields_extra')] = (f.fields || []).join(', ') || DASH;
      return out;
    };
    return { title: t('pending.title.key_filter', { name: keyName(cred, ctx.catalog.list()) }), ...changed(view(normalizeFilter(cred.filter, provider)), view(normalizeFilter(input.next, provider))) };
  },
  back: keyBack,
  notFound: keyNotFound,
};

// ---- агенты

const agentBack = () => '/agents';
const agentNotFound = () => ({ redirect: '/agents' });
const MAX_IDS = 500;
/** Привязка из тела черновика: all='1'|'0', ids[] (маршрут приводит форму keys_all/keys к этому виду). */
function bindingOf(body) {
  const ids = body.ids === undefined ? [] : (Array.isArray(body.ids) ? body.ids : [body.ids]);
  return { all: String(body.all ?? '1') !== '0', ids: ids.map(String).slice(0, MAX_IDS) };
}
function bindingText(ctx, { all, ids }) {
  if (all) return t('agents.keys_all');
  const known = new Set(ids);
  const names = ctx.repo.listCredentials().filter((c) => known.has(c.id)).map((c) => keyName(c, ctx.catalog.list()));
  return names.length ? names.join(', ') : t('agents.keys_none');
}

const agentCreate = {
  type: 'agent.create',
  perm: 'agent.create',
  fields: ['name', 'all', 'ids', 'kind'], // kind — карточка онбординга (allowlist в KINDS), без него — обычное создание
  targetOf: () => '',
  version: () => '', // существование ключей проверяется при исполнении
  parse(ctx, id, body) {
    const kind = isKind(body.kind) ? body.kind : '';
    const name = (kind ? agentNameOf(kind) : String(body.name || '')).trim().slice(0, 60);
    if (!name) return { input: null, errors: [t('flash.agent_name_required')] };
    return { input: { name, kind, ...bindingOf(body) }, errors: [] };
  },
  needsFresh: () => true, // новый агент — новый токен доступа к ключам
  apply(ctx, id, input, { fromDraft = false } = {}) {
    const token = 'gwa_' + crypto.randomBytes(32).toString('base64url');
    const agent = { id: crypto.randomBytes(8).toString('base64url'), name: input.name, token_hash: sha256hex(token), all_credentials: input.all ? 1 : 0 };
    ctx.repo.createAgent(agent);
    ctx.repo.setAgentCredentials(agent.id, { all: input.all, ids: input.ids });
    ctx.repo.audit(ctx.userId, 'agent.create', agent.id, { name: input.name, keys: input.all ? 'all' : ctx.repo.listAgentCredentials(agent.id), ...(fromDraft ? { via: 'draft' } : {}) });
    ctx.notify?.security(t('notify.sec.agent_created', { name: input.name }));
    const created = ctx.repo.getAgent(agent.id);
    if (input.kind) return { html: welcomeAgentCreated({ csrf: ctx.csrf || '', agent: created, token, kind: input.kind, publicUrl: ctx.publicUrl || '' }) };
    return { html: agentCreated({ csrf: ctx.csrf || '', agent: created, token }) }; // токен показывается один раз и нигде не хранится
  },
  summary: (ctx, id, input) => ({ title: t('pending.title.agent_create'), after: { [t('pending.f.name')]: input.name, [t('pending.f.keys')]: bindingText(ctx, input) } }),
  back: agentBack,
  notFound: agentNotFound,
};

const agentKeys = {
  type: 'agent.keys',
  perm: 'agent.keys',
  fields: ['all', 'ids'],
  targetOf: (params) => String(params.id ?? ''),
  version(ctx, id) {
    const a = ctx.repo.getAgent(id);
    return a ? digest([a.all_credentials ? 1 : 0, [...ctx.repo.listAgentCredentials(id)].sort(), a.enabled ? 1 : 0]) : null;
  },
  parse: (ctx, id, body) => ({ input: bindingOf(body), errors: [] }),
  // сузить доступ можно сразу, расширить — только со свежим кодом
  needsFresh(ctx, id, input) {
    const a = ctx.repo.getAgent(id);
    const bound = new Set(ctx.repo.listAgentCredentials(id));
    return !a.all_credentials && (input.all || input.ids.some((x) => !bound.has(x)));
  },
  apply(ctx, id, input, { fromDraft = false } = {}) {
    const a = ctx.repo.getAgent(id);
    ctx.repo.setAgentCredentials(id, { all: input.all, ids: input.ids });
    ctx.repo.audit(ctx.userId, 'agent.keys', id, { keys: input.all ? 'all' : ctx.repo.listAgentCredentials(id), ...(fromDraft ? { via: 'draft' } : {}) });
    return { redirect: '/agents', flash: { type: 'ok', text: t('flash.agent_keys_saved', { name: a.name }) } };
  },
  summary(ctx, id, input) {
    const a = ctx.repo.getAgent(id);
    const cur = { all: !!a.all_credentials, ids: ctx.repo.listAgentCredentials(id) };
    return { title: t('pending.title.agent_keys', { name: a.name }), before: { [t('pending.f.keys')]: bindingText(ctx, cur) }, after: { [t('pending.f.keys')]: bindingText(ctx, input) } };
  },
  back: agentBack,
  notFound: agentNotFound,
};

// ---- уведомления: включение канала и выбор событий (секреты каналов сюда не входят: у них своя форма со свежим кодом)

export const NOTIFY_CHANNELS = Object.freeze(['slack', 'email']);
export const eventLabel = (e) => t(`notify.ev.${e.replace('.', '_')}`);
const eventsText = (events) => (events.length ? events.map(eventLabel).join(', ') : DASH);
const notifyView = (m) => ({ [t('pending.f.enabled')]: yes(m.enabled), [t('pending.f.events')]: eventsText(m.events) });

const notifyChannel = {
  type: 'notify.channel',
  perm: 'notify.channel',
  fields: ['enabled', 'events'],
  targetOf: (params) => String(params.id ?? ''),
  version(ctx, id) {
    if (!NOTIFY_CHANNELS.includes(id)) return null;
    return digest(readChannelMeta(ctx.repo, id));
  },
  parse(ctx, id, body) {
    const enabled = String(body.enabled ?? '') === '1';
    const picked = body.events === undefined ? [] : [].concat(body.events);
    const events = EVENTS.filter((e) => picked.includes(e)); // allowlist событий в каноническом порядке
    const errors = [];
    if (enabled && !readChannelMeta(ctx.repo, id).configured) errors.push(t('flash.notify_no_secret'));
    if (enabled && !events.length) errors.push(t('flash.notify_no_events'));
    return { input: { enabled, events }, errors };
  },
  // включение канала — со свежим кодом; выключение и смена событий применяются сразу
  needsFresh: (ctx, id, input) => input.enabled && !readChannelMeta(ctx.repo, id).enabled,
  apply(ctx, id, input, { fromDraft = false } = {}) {
    const cur = readChannelMeta(ctx.repo, id);
    writeChannelMeta(ctx.repo, id, { enabled: input.enabled, events: input.events, configured: cur.configured });
    ctx.repo.audit(ctx.userId, 'notify.channel', id, { enabled: input.enabled, events: input.events, ...(fromDraft ? { via: 'draft' } : {}) });
    return { redirect: '/settings', flash: { type: 'ok', text: t('flash.notify_saved') } };
  },
  summary(ctx, id, input) {
    return { title: t('pending.title.notify', { name: t(`notify.channel.${id}`) }), ...changed(notifyView(readChannelMeta(ctx.repo, id)), notifyView(input)) };
  },
  back: () => '/settings',
  notFound: () => ({ redirect: '/settings' }),
};

/** Допустимые типы (allowlist): сохранить в черновик что-либо ещё нельзя. Формы с секретом сюда не входят никогда. */
export const ACTIONS = Object.freeze({
  'key.policy': Object.freeze(keyPolicy),
  'key.filter': Object.freeze(keyFilter),
  'agent.create': Object.freeze(agentCreate),
  'agent.keys': Object.freeze(agentKeys),
  'notify.channel': Object.freeze(notifyChannel),
});

/**
 * Единый путь исполнения для прямого вызова и черновика.
 * -> ActionResult ({redirect, flash?} | {html, code?}) | { needFresh:true, back } | { errors:string[], back }
 */
export function runAction(ctx, type, targetId, body, { fromDraft = false } = {}) {
  const def = Object.hasOwn(ACTIONS, type) ? ACTIONS[type] : null;
  if (!def) throw new Error(`unknown action type: ${type}`);
  if (def.version(ctx, targetId) === null) return def.notFound(ctx, targetId);
  const { input, errors } = def.parse(ctx, targetId, body);
  if (errors.length) return { errors, back: def.back(targetId) };
  if (def.needsFresh(ctx, targetId, input) && !ctx.hasRecentTotp) return { needFresh: true, back: def.back(targetId) };
  return def.apply(ctx, targetId, input, { fromDraft });
}
