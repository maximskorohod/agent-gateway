// Экраны ключей: список и заявки (1), выбор сервиса (2), форма ключа (3), страница ключа.
import { html, raw, form, layout, enc, fmtDate, fmtDuration, plural, isoDate, keyName, isDemo, showcaseBanner } from './html.js';
import { t, hasKey, providerHint } from '../../i18n.js';
import { normalizeFilter, protectionOf, defaultFilterFor } from '../../core/filter.js';
import { DEMO_CREDENTIAL_ID } from '../../demo/reset.js';

const MODE_OPTIONS = ['ask', 'always', 'deny'];
const ALWAYS_FOR = [[3600, 'policy.for_3600'], [86400, 'policy.for_86400'], [604800, 'policy.for_604800'], ['forever', 'policy.for_forever']];
const DAYS = [1, 2, 3, 4, 5, 6, 7];
const TTL_OPTIONS = [300, 900, 3600, 7200, 28800, 86400];
const DEFAULTS = { mode: 'ask', max_ttl: 3600, max_calls: 100, max_parallel: 2 };

const providerName = (providers, slug) => providers.find((p) => p.slug === slug)?.name ?? slug;
const sel = (cond) => (cond ? raw(' selected') : '');
const chk = (cond) => (cond ? raw(' checked') : '');

function approvalOptions(telegramConnected, preview = false) {
  // в демо нет кода 2FA: остальные варианты отклонит demoRouteGuard; витрина только показывает полный набор
  if (isDemo() && !preview) return ['web_button'];
  return telegramConnected
    ? ['tg_button', 'tg_code', 'web_button', 'web_code']
    : ['web_button', 'web_code'];
}

/** Подпись режима для списка: «Без вопросов до 03.11.2026 14:00». */
function modeText(c) {
  if (c.mode === 'always' && c.always_until) return t('policy.always_until', { date: fmtDate(c.always_until) });
  const key = `policy.mode.${c.mode}`;
  return hasKey(key) ? t(key) : c.mode;
}

/** Срок «без вопросов»: для включённого режима со сроком первым идёт «оставить как есть». */
function alwaysForSelect(v) {
  const until = v.mode === 'always' && typeof v.always_until === 'number' ? v.always_until : null;
  const cur = String(v.always_for ?? (until ? 'keep' : v.mode === 'always' && v.id ? 'forever' : 86400));
  return html`<select name="always_for" aria-label="${t('policy.for_aria')}">
      ${until ? html`<option value="keep"${sel(cur === 'keep')}>${t('policy.keep', { date: fmtDate(until) })}</option>` : ''}
      ${ALWAYS_FOR.map(([s, k]) => html`<option value="${s}"${sel(cur === String(s))}>${s === 'forever'
        ? t(until ? 'policy.for_more_forever' : 'policy.for_new_forever')
        : t(until ? 'policy.for_more' : 'policy.for_new', { label: t(k) })}</option>`)}
    </select>`;
}

/**
 * Настройки ключа: на виду только режим (спрашивать / без вопросов на время / запретить),
 * остальное — в свёрнутом «Дополнительно». Общий для формы ключа и страницы ключа.
 */
function policyFields(v = {}, { telegramConnected = false, sensitive = false, locked = false, preview = false } = {}) {
  const win = v.window ?? {};
  const days = (win.days ?? v.days ?? []).map(Number);
  const mode = MODE_OPTIONS.includes(v.mode) ? v.mode : DEFAULTS.mode;
  const approvals = approvalOptions(telegramConnected, preview);
  const approval = approvals.includes(v.approval) ? v.approval : approvals[0];
  const maxTtl = Number(v.max_ttl ?? DEFAULTS.max_ttl);
  const expires = typeof v.expires_at === 'number' ? isoDate(v.expires_at) : (v.expires_at ?? '');

  return html`
    <fieldset>
      <legend>${t('policy.how')}</legend>
      ${MODE_OPTIONS.filter((m) => !(locked && m === 'deny')).map((m) => html`<label class="inline"><input type="radio" name="mode" value="${m}"${chk(mode === m)}> ${t(`policy.choice.${m}`)}</label>${m === 'always' ? alwaysForSelect(v) : ''}`)}
      <p class="hint">${t(isDemo() && !preview ? 'demo.always_hint' : 'policy.always_hint')}</p>
      ${locked ? html`<p class="hint">${t('demo.seeded_hint')}</p>` : ''}
      ${sensitive ? html`<div class="sensitive">
        <p class="hint">${t('policy.sensitive_warning')}</p>
        <label class="inline"><input type="checkbox" name="confirm_sensitive" value="1"> ${t('policy.sensitive_confirm')}</label>
      </div>` : ''}
    </fieldset>
    <details class="fold">
      <summary>${t('policy.advanced')}</summary>
      <label>${t('policy.name')}
        <input name="label" value="${v.label ?? ''}" maxlength="80" autocomplete="off" placeholder="${t('policy.name_ph')}">
      </label>
      ${approvals.length > 1 ? html`<label>${t('policy.approval')}
        <select name="approval">
          ${approvals.map((a) => html`<option value="${a}"${sel(a === approval)}>${t(`policy.approval.${a}`)}</option>`)}
        </select>
      </label>` : html`<input type="hidden" name="approval" value="${approval}">`}
      <label>${t('policy.max_ttl')}
        <select name="max_ttl">
          ${TTL_OPTIONS.map((t) => html`<option value="${t}"${sel(t === maxTtl)}>${fmtDuration(t)}</option>`)}
        </select>
      </label>
      <div class="row2">
        <label>${t('policy.max_calls')}
          <input type="number" name="max_calls" min="1" max="100000" step="1" inputmode="numeric" value="${v.max_calls ?? DEFAULTS.max_calls}">
        </label>
        <label>${t('policy.max_parallel')}
          <input type="number" name="max_parallel" min="1" max="20" step="1" inputmode="numeric" value="${v.max_parallel ?? DEFAULTS.max_parallel}">
        </label>
      </div>
      ${locked ? '' : html`<fieldset>
        <legend>${t('policy.days')}</legend>
        ${DAYS.map((d) => html`<label class="inline"><input type="checkbox" name="days" value="${d}"${chk(days.includes(d))}> ${t(`policy.day.${d}`)}</label>`)}
      </fieldset>
      <div class="row2">
        <label>${t('policy.from')} <input type="time" name="from" value="${win.from ?? v.from ?? ''}"></label>
        <label>${t('policy.to')} <input type="time" name="to" value="${win.to ?? v.to ?? ''}"></label>
      </div>
      <p class="hint">${t('policy.window_hint')}</p>
      <label>${t('policy.expires')}
        <input type="date" name="expires_at" value="${expires}">
      </label>
      <p class="hint">${t('policy.expires_hint')}</p>`}
    </details>
  `;
}

// Поле формы: (значения, провайдер, { replace }). При замене ключа автофокуса нет, ключ называется «Новый ключ».
const FIELDS = {
  key: (v, p, o = {}) => html`<label>${o.replace ? t('key.new_key') : t('key.label')}
      <input type="password" name="key" autocomplete="off" autocapitalize="off" spellcheck="false" required${o.replace ? '' : raw(' autofocus')}>
    </label>`,
  // Ссылка вебхука — секрет, поэтому в форму не возвращается.
  webhook_url: () => html`<label>${t('key.webhook_url')}
      <input type="url" name="webhook_url" autocomplete="off" spellcheck="false" required>
    </label>`,
  account: (v, p = {}) => {
    const labelKey = `catalog.label.account.${p.slug}`;
    return html`<label>${hasKey(labelKey) ? t(labelKey) : t('key.account')}
      <input name="account" value="${v.account ?? ''}" autocomplete="off" spellcheck="false"${p.accountPlaceholder ? html` placeholder="${p.accountPlaceholder}"` : ''} required>
    </label>`;
  },
  email: (v) => html`<label>${t('key.email')}
      <input type="email" name="email" value="${v.email ?? ''}" autocomplete="off" spellcheck="false" required>
    </label>`,
  host: (v) => html`<label>${t('key.api_host')}
      <input type="url" name="host" value="${v.host ?? ''}" autocomplete="off" placeholder="https://api.example.com" required>
    </label>`,
  header: (v) => html`<label>${t('key.header_name')}
      <input name="header" value="${v.header ?? ''}" autocomplete="off" spellcheck="false" placeholder="authorization" required>
    </label>`,
};

function errorBox(errors) {
  const list = (errors && typeof errors === 'object' ? Object.values(errors) : [errors]).filter(Boolean);
  if (!list.length) return '';
  return html`<div class="error" role="alert">${list.map((e) => html`<p>${String(e)}</p>`)}</div>`;
}

function iconRow(provider, caption) {
  return html`<div class="head-ico">
      <img class="ico" src="/public/icons/${enc(provider.slug)}.svg" alt="" width="32" height="32">
      <span class="muted">${caption}</span>
    </div>`;
}

// имя ключа в скобках только если оно отличается от имени сервиса: «HubSpot (HubSpot)» не нужно
function requestTarget(r, providers) {
  const svc = providerName(providers, r.provider);
  return r.credential_label && r.credential_label.trim() !== svc ? `${svc} (${r.credential_label})` : svc;
}

const callsText = (n) => `${n} ${plural(n, [t('unit.call.one'), t('unit.call.few'), t('unit.call.many')])}`;

// Строка заявки в списке: решение принимается на отдельном экране, где видно, что получит агент.
function pendingRow(r, providers) {
  return html`
    <li>
      <a class="row wait-row" href="/requests/${enc(r.id)}">
        <span class="grow">
          <span class="title">${r.agent_name}</span>
          <span class="muted small">${requestTarget(r, providers)}, ${fmtDuration(r.ttl)}, ${callsText(r.calls)}</span>
        </span>
        <span class="pill">${t('keys.review')}</span>
      </a>
    </li>`;
}

/** Экран заявки: кто просит, срок и вызовы, что увидит агент, слова агента, решение. Решение только POST с CSRF. */
export function requestPage({ csrf, request: r, providers = [], filterLine: line = null, flash = null } = {}) {
  const id = enc(r.id);
  return layout(t('request.title', { agent: r.agent_name, target: requestTarget(r, providers) }), html`
    <p class="center"><span class="pill">${t('request.waiting')}</span></p>
    <dl class="facts">
      <div><dt>${t('request.for')}</dt><dd>${fmtDuration(r.ttl)}</dd></div>
      <div><dt>${t('request.calls')}</dt><dd>${r.calls}</dd></div>
    </dl>
    ${line ? html`<p class="see">${line}</p>` : ''}
    ${r.reason ? html`<blockquote class="said"><p>${r.reason}</p><footer>${t('request.reason_caption')}</footer></blockquote>` : ''}
    <div class="two">
      ${form(`/requests/${id}/deny`, html`<button class="btn" type="submit">${t('requests.deny')}</button>`, csrf)}
      ${form(`/requests/${id}/approve`, html`<button class="btn primary" type="submit">${t('requests.approve')}</button>`, csrf)}
    </div>
    <p class="center small"><a href="/keys">${t('keys.back')}</a></p>
  `, { nav: false, csrf, flash });
}

function keyRow(c, providers, currentId = null) {
  return html`
    <li>
      <a class="row${c.id === currentId ? ' on' : ''}" href="/keys/${enc(c.id)}"${c.id === currentId ? raw(' aria-current="true"') : ''}>
        <img class="ico" src="/public/icons/${enc(c.provider)}.svg" alt="" width="32" height="32">
        <span class="grow">
          <span class="title">${keyName(c, providers)}</span>
          <span class="muted small"><span class="dot dot-${c.mode}" aria-hidden="true"></span>${modeText(c)} · ${t('keys.grant_up_to', { ttl: fmtDuration(c.max_ttl).replace(/ /g, ' ') })}</span>
        </span>
        <span class="mask">····${c.last4}</span>
      </a>
    </li>`;
}

// Колонка списка: заявки сверху, ниже ключи. Общая для экрана ключей и страницы ключа.
function keysColumn({ credentials = [], pending = [], providers = [], currentId = null }) {
  return html`
    <div class="list-actions"><a class="btn" href="/keys/new">${t('keys.add')}</a></div>
    ${pending.length ? html`<section>
      <h2 class="cap">${t('keys.pending', { n: pending.length })}</h2>
      <ul class="list">${pending.map((r) => pendingRow(r, providers))}</ul>
    </section>` : ''}
    <section>
      <h2 class="cap">${t('keys.my_keys')}</h2>
      ${credentials.length
        ? html`<ul class="list">${credentials.map((c) => keyRow(c, providers, currentId))}</ul>`
        : html`<div class="empty"><p>${t('keys.empty')}</p></div>`}
    </section>`;
}

// Карточка первого ключа справа от списка: только чтение, правка на странице ключа.
function keySummary(c, providers, line) {
  return html`
    <div class="summary">
      <div class="head-ico">
        <img class="ico" src="/public/icons/${enc(c.provider)}.svg" alt="" width="32" height="32">
        <h2>${keyName(c, providers)}</h2>
      </div>
      <dl class="fields">
        <div><dt>${t('summary.key')}</dt><dd class="mono">············ ${c.last4}</dd></div>
        <div><dt>${t('summary.approval')}</dt><dd>${modeText(c)}</dd></div>
        <div><dt>${t('summary.longest')}</dt><dd>${fmtDuration(c.max_ttl)}</dd></div>
        ${line ? html`<div><dt>${t('summary.access')}</dt><dd>${line}</dd></div>` : ''}
      </dl>
      <p class="callout">${t('summary.never_shown')}</p>
      <p><a class="btn" href="/keys/${enc(c.id)}">${t('summary.open')}</a></p>
    </div>`;
}

/** Один шаг сценария демо: номер, заголовок, содержимое только у текущего шага. */
function demoStep(n, current, title, body) {
  const state = n === current ? 'on' : n < current ? 'done' : 'todo';
  return html`<li class="${state}"${n === current ? raw(' aria-current="step"') : ''}>
      <span class="step-num" aria-hidden="true">${n}</span>
      <div class="step-body">
        <span class="title">${title}</span>
        ${n === current ? body : ''}
      </div>
    </li>`;
}

/** Сценарий демо из трёх шагов. scenario — { step: 1 } | { step: 2, requestId } | { step: 3, curl }. */
function demoSteps(scenario, csrf) {
  const { step = 1, requestId = '', curl = '' } = scenario ?? {};
  return html`<section class="card demo-steps">
      <h2>${t('demo.steps_title')}</h2>
      <ol class="steps">
        ${demoStep(1, step, t('demo.step1'), html`
          <p class="muted small">${t('demo.simulate_hint')}</p>
          ${form('/demo/simulate', html`<button class="btn primary" type="submit">${t('demo.simulate')}</button>`, csrf)}`)}
        ${demoStep(2, step, t('demo.step2'), html`
          <p class="muted small">${t('demo.step2_hint')}</p>
          <a class="btn primary" href="/requests/${enc(requestId)}">${t('demo.review')}</a>`)}
        ${demoStep(3, step, t('demo.step3'), html`
          <p class="muted small">${t('demo.step3_hint')}</p>
          <div class="token-box"><code id="demo-curl">${curl}</code></div>
          <p class="actions"><button class="btn primary" type="button" data-copy="#demo-curl" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
          <p class="small"><a href="/stats">${t('demo.activity_link')}</a></p>
          ${form('/demo/simulate', html`<button class="btn" type="submit">${t('demo.simulate_again')}</button>`, csrf)}`)}
      </ol>
    </section>`;
}

/** Экран 1: колонка заявок и ключей, справа карточка первого ключа. keyLine — «Агент увидит…» для этого ключа. */
export function keysPage({ csrf, credentials = [], pending = [], providers = [], keyLine = null, flash = null, onboarding = null, demo = false, scenario = null } = {}) {
  const demoBlock = demo ? demoSteps(scenario, csrf) : '';
  // onboarding — { count } пока онбординг не пропущен и нет ни агента, ни ключа; иначе null
  const onboardingBlock = onboarding
    ? html`<section class="card" role="note"><p class="actions"><a class="btn primary" href="/welcome">${t('welcome.title')}</a> <span class="muted">${t('welcome.progress', { n: onboarding.count })}</span></p></section>`
    : '';
  const list = html`${onboardingBlock}${demoBlock}${keysColumn({ credentials, pending, providers })}`;
  const detail = credentials.length ? keySummary(credentials[0], providers, keyLine) : '';
  return layout(t('keys.title'), detail, { csrf, flash, list, listHome: true, pendingCount: pending.length });
}

function providerTile(p, href, tag = '') {
  return html`<li>
        <a class="tile" href="${href}">
          <img src="/public/icons/${enc(p.slug)}.svg" alt="" width="32" height="32">
          <span>${p.name}</span>
          ${tag ? html`<span class="tag">${tag}</span>` : ''}
        </a>
      </li>`;
}

/**
 * Экран 2: сетка сервисов (включая «Другой»). showcase — только в демо: настоящие сервисы
 * с пометкой «Попробовать», остальные каталога обычной установки ведут на витрину.
 */
export function pickProvider({ providers = [], csrf, showcase = null } = {}) {
  return layout(t('keys.new'), html`
    <p class="muted">${t(showcase ? 'showcase.pick_hint' : 'keys.pick_service')}</p>
    <ul class="grid">
      ${providers.map((p) => providerTile(p, `/keys/new/${enc(p.slug)}`, showcase ? t('showcase.try') : ''))}
      ${(showcase ?? []).map((p) => providerTile(p, `/showcase/services/${enc(p.slug)}`, t('showcase.view')))}
    </ul>
    <p><a href="/keys">${t('keys.back_new')}</a></p>
  `, { csrf });
}

/**
 * Ссылка «Get a key →» и подсказка, где взять ключ. Показываются только если поле есть у провайдера;
 * русский текст подсказки — `catalog.getkey.<slug>`, иначе getKeyHint из providers.yaml.
 */
function getKeyBlock(provider) {
  const url = typeof provider.getKeyUrl === 'string' && /^https:\/\//i.test(provider.getKeyUrl) ? provider.getKeyUrl : '';
  const key = `catalog.getkey.${provider.slug}`;
  const hint = hasKey(key) ? t(key) : (provider.getKeyHint || '');
  if (!url && !hint) return '';
  return html`<p class="hint">${url ? html`<a href="${url}" target="_blank" rel="noopener noreferrer">${t('key.get_key')}</a>` : ''}${url && hint ? ' ' : ''}${hint}</p>`;
}

/** Галочки защиты на форме нового ключа: из отправленной формы, иначе по умолчанию каталога (CRM: только чтение). */
function newKeyProtection(provider, values) {
  if (values.protect_form === '1') return { readOnly: values.read_only === '1', mask: values.mask === '1' };
  return { readOnly: defaultFilterFor(provider)?.readOnly === true, mask: false };
}

/** Пометка «поля не проверены на живом сервисе» (каталог: filter.unverified, п. 7.3). */
function unverifiedNote(provider) {
  return provider?.filter?.unverified === true ? html`<div class="warn" role="note"><p>${t('filter.unverified')}</p></div>` : '';
}

/** Экран 3: поля сервиса, подсказка, настройки (свёрнуты), кнопка «Сохранить». */
export function keyForm({ csrf, provider, values = {}, errors, telegramConnected = false } = {}) {
  const fields = provider.fields ?? ['key'];
  return layout(provider.name, html`
    ${iconRow(provider, t('keys.new'))}
    ${errorBox(errors)}
    ${provider.warning && hasKey(`catalog.warn.${provider.slug}`) ? html`<div class="warn" role="note"><p>${t(`catalog.warn.${provider.slug}`)}</p></div>` : ''}
    ${unverifiedNote(provider)}
    ${form(`/keys/new/${enc(provider.slug)}`, html`
      ${fields.map((f) => (FIELDS[f] ? FIELDS[f](values, provider) : ''))}
      ${providerHint(provider) ? html`<p class="hint">${providerHint(provider)}</p>` : ''}
      ${getKeyBlock(provider)}
      ${policyFields(values, { telegramConnected, sensitive: !!provider.sensitive })}
      ${protectFields(provider, newKeyProtection(provider, values))}
      <button class="btn primary" type="submit">${t('key.save')}</button>
    `, csrf)}
    <p><a href="/keys/new">${t('keys.other_service')}</a></p>
  `, { csrf });
}

/** Один тип данных в блоке «Что видит агент»: галочка типа, галочки полей, свои поля текстом. */
function filterEntity(id, e, fields, flags = []) {
  const open = fields !== undefined;
  // закрытый тип показываем с полями по умолчанию: включил галочку типа — и сразу разумный набор
  const ticked = new Set(open ? fields : e.defaults || []);
  const known = new Set(e.fields.flatMap((x) => x.paths ?? [x.path]));
  const extra = open ? fields.filter((x) => !known.has(x)) : [];
  return html`
    <fieldset class="entity">
      <legend><label class="inline"><input type="checkbox" name="ent_${id}" value="1"${chk(open)}> ${e.name}</label></legend>
      <div class="entity-fields">
        ${e.fields.map((x) => html`<label class="inline"><input type="checkbox" name="f_${id}" value="${x.path}"${chk(ticked.has(x.path))}> ${x.label}</label>`)}
      </div>
      ${Object.entries(e.extras || {}).map(([fl, x]) => html`<div class="flag"><label class="inline"><input type="checkbox" name="fl_${id}" value="${fl}"${chk(flags.includes(fl))}> ${x.label}</label><p class="hint">${t('filter.flag_hint')}</p></div>`)}
      <details class="fold"${extra.length ? raw(' open') : ''}>
        <summary>${t('filter.own_fields')}</summary>
        <label>${t('filter.own_fields_label')}
          <textarea name="x_${id}" rows="2" autocomplete="off" spellcheck="false" placeholder="result.UF_CRM_123">${extra.join('\n')}</textarea>
        </label>
      </details>
    </fieldset>
  `;
}

/**
 * Слой 1 (п. 7.2), доступен у любого сервиса: «Только чтение» (если в каталоге описано чтение) и «Скрывать личные данные».
 * f — { readOnly, mask }; скрытое поле protect_form говорит обработчику, что галочки пришли с формы.
 */
function protectFields(prov, f, { preview = false } = {}) {
  const a = protectionOf(prov);
  if (!a.readOnly && !a.mask) return '';
  return html`
    <fieldset class="protect">
      <legend>${t('protect.title')}</legend>
      <input type="hidden" name="protect_form" value="1">
      ${a.readOnly ? html`<label class="inline"><input type="checkbox" name="read_only" value="1"${chk(f.readOnly)}> ${t('protect.read_only')}</label>
        <p class="hint">${t('protect.read_only_hint')}</p>` : ''}
      ${a.mask ? html`<label class="inline"><input type="checkbox" name="mask" value="1"${chk(f.mask)}> ${t('protect.mask')}</label>
        <p class="hint">${t('protect.mask_hint')}</p>` : ''}
      ${isDemo() && !preview ? '' : html`<p class="hint">${t('protect.weaken_hint')}</p>`}
    </fieldset>`;
}

/**
 * Витрина сервиса в демо: настоящие поля и настройки обычной установки, все отключены.
 * Формы нет, значения не отправляются, сервис в демо недоступен.
 */
export function showcaseService({ provider } = {}) {
  const fields = provider.fields ?? ['key'];
  const ents = provider.filter ? Object.entries(provider.filter.entities) : [];
  return layout(provider.name, html`
    ${showcaseBanner()}
    ${iconRow(provider, t('showcase.service_caption'))}
    ${provider.warning && hasKey(`catalog.warn.${provider.slug}`) ? html`<div class="warn" role="note"><p>${t(`catalog.warn.${provider.slug}`)}</p></div>` : ''}
    ${unverifiedNote(provider)}
    <fieldset disabled>
      ${fields.map((f) => (FIELDS[f] ? FIELDS[f]({}, provider) : ''))}
      ${providerHint(provider) ? html`<p class="hint">${providerHint(provider)}</p>` : ''}
      ${getKeyBlock(provider)}
      ${policyFields({}, { telegramConnected: true, sensitive: !!provider.sensitive, preview: true })}
      ${protectFields(provider, newKeyProtection(provider, {}), { preview: true })}
      ${ents.length ? html`<section class="card">
        <h2>${t('filter.title')}</h2>
        <label class="inline switch"><input type="checkbox" name="enabled" value="1" checked> ${t('filter.enabled')}</label>
        <p class="hint">${t('filter.on_hint')}</p>
        ${ents.map(([id, e]) => filterEntity(id, e, e.defaults ?? []))}
        <p class="hint">${t('filter.deny_hint')}</p>
      </section>` : ''}
    </fieldset>
    <p class="actions"><a class="btn primary" href="/">${t('showcase.try_live')}</a></p>
    <p><a href="/keys/new">${t('keys.other_service')}</a></p>
  `);
}

/** Блок «Что видит агент» (ТЗ v1.3): защита слоя 1, выключатель и галочки по типам данных (сделки, лиды…). */
function filterCard(cred, prov, csrf) {
  const f = normalizeFilter(cred.filter, prov);
  const ents = prov.filter ? Object.entries(prov.filter.entities) : [];
  const other = f.methods.length > 0;
  return html`
    <section class="card">
      <h2>${prov.filter ? t('filter.title') : t('protect.title')}</h2>
      ${unverifiedNote(prov)}
      ${form(`/keys/${enc(cred.id)}/filter`, html`
        ${prov.filter ? html`
        <input type="hidden" name="entities_form" value="1">
        <label class="inline switch"><input type="checkbox" name="enabled" value="1"${chk(f.enabled)}> ${t('filter.enabled')}</label>
        <p class="hint">${f.enabled ? t('filter.on_hint') : t('filter.off_hint')}</p>
        ${ents.map(([id, e]) => filterEntity(id, e, f.entities[id], f.flags?.[id]))}
        <details class="fold"${other ? raw(' open') : ''}>
          <summary>${t('filter.other_methods')}</summary>
          <label>${t('filter.methods_label')}
            <textarea name="methods" rows="3" autocomplete="off" spellcheck="false">${f.methods.join('\n')}</textarea>
          </label>
          <label>${t('filter.fields_label')}
            <textarea name="fields_extra" rows="2" autocomplete="off" spellcheck="false" placeholder="result.ID">${f.fields.join('\n')}</textarea>
          </label>
        </details>
        <p class="hint">${t(isDemo() ? 'demo.filter_deny_hint' : 'filter.deny_hint')}</p>` : ''}
        ${protectFields(prov, f)}
        <button class="btn primary" type="submit">${t('filter.save')}</button>
      `, csrf)}
    </section>
  `;
}

const NAMES_SHOWN = 100;
const nameList = (list) => (list.length
  ? `${list.slice(0, NAMES_SHOWN).join(', ')}${list.length > NAMES_SHOWN ? ` +${list.length - NAMES_SHOWN}` : ''}`
  : t('preview.none'));

/** Итог предпросмотра: только имена полей «было → осталось», значений в результате нет вовсе. */
function previewResult(p) {
  if (!p.ok) {
    const msg = p.error === 'preview_no_route' ? t('preview.err.no_route')
      : p.error === 'upstream_status' ? t('preview.err.status', { status: p.status })
        : t('preview.err.generic', { code: p.error });
    return html`<div class="error" role="alert"><p>${msg}</p></div>`;
  }
  const kept = new Set(p.after);
  const hidden = p.before.filter((x) => !kept.has(x));
  return html`<div role="status">
      <p class="muted small">${t('preview.route', { route: p.route })}</p>
      <p><strong>${t('preview.counts', { before: p.before.length, after: p.after.length })}</strong></p>
      ${p.allowed ? '' : html`<p class="hint">${t('preview.not_allowed')}</p>`}
      <p><strong>${t('preview.agent_sees')}:</strong> ${nameList(p.after)}</p>
      <p><strong>${t('preview.hidden')}:</strong> ${nameList(hidden)}</p>
    </div>`;
}

/** Блок «Проверить на одном вызове»: у сервисов с описанным фильтром (есть типы и маршруты для вызова). */
function previewCard(cred, prov, csrf, preview) {
  if (!prov.filter) return '';
  return html`
    <section class="card">
      <h2>${t('preview.title')}</h2>
      <p class="hint">${t('preview.hint')}</p>
      ${form(`/keys/${enc(cred.id)}/preview`, html`<button class="btn" type="submit">${t('preview.button')}</button>`, csrf)}
      ${preview ? previewResult(preview) : ''}
    </section>`;
}

/**
 * Поля формы замены ключа: те же, что при добавлении. У «Другого» адрес и заголовок берутся
 * из сохранённого ключа и не показываются.
 */
function replaceFields(cred, prov) {
  const fields = prov.fields ?? ['key'];
  return fields.filter((f) => FIELDS[f] && !(prov.builder === 'other' && (f === 'host' || f === 'header')));
}

/** Предзаполнение: только адрес аккаунта для поддоменных сервисов; ключ, вебхук и SID не возвращаются. */
function replaceValues(cred, prov) {
  const bySubdomain = prov.host === 'owner' && typeof prov.hostTemplate === 'string';
  return bySubdomain && cred.host ? { account: cred.host } : {};
}

/** Страница ключа: настройки, замена ключа, удаление. Ключ не показывается, только последние 4 символа. */
export function keyDetail({ csrf, cred, provider, telegramConnected = false, flash = null, preview = null, credentials = null, pending = [], providers = [] } = {}) {
  const id = enc(cred.id);
  const prov = provider ?? { slug: cred.provider, name: cred.provider };
  return layout(keyName(cred, [prov]), html`
    ${iconRow(prov, `${prov.name} · ····${cred.last4}`)}
    <p class="muted small">${t('key.added', { date: fmtDate(cred.created_at) })}</p>
    ${form(`/keys/${id}/policy`, html`
      ${policyFields(cred, { telegramConnected, sensitive: !!prov.sensitive, locked: isDemo() && cred.id === DEMO_CREDENTIAL_ID })}
      <button class="btn primary" type="submit">${t('key.save')}</button>
    `, csrf)}
    ${prov.filter || protectionOf(prov).readOnly || protectionOf(prov).mask ? filterCard(cred, prov, csrf) : ''}
    ${isDemo() ? '' : html`${previewCard(cred, prov, csrf, preview)}
    <section class="card">
      <h2>${t('key.replace_title')}</h2>
      ${form(`/keys/${id}/replace`, html`
        ${replaceFields(cred, prov).map((f) => FIELDS[f](replaceValues(cred, prov), prov, { replace: true }))}
        ${prov.fields && providerHint(prov) ? html`<p class="hint">${providerHint(prov)}</p>` : ''}
        <button class="btn" type="submit">${t('key.replace')}</button>
      `, csrf)}
    </section>
    <section class="card">
      <h2>${t('key.delete_title')}</h2>
      <details class="fold">
        <summary>${t('key.delete_open')}</summary>
        <p class="hint">${t('key.delete_hint')}</p>
        ${form(`/keys/${id}/delete`, html`<button class="btn btn-danger" type="submit">${t('key.delete')}</button>`, csrf)}
      </details>
    </section>`}
    <p><a href="/keys">${t('keys.back')}</a></p>
  `, {
    csrf,
    flash,
    pendingCount: pending.length,
    list: credentials ? keysColumn({ credentials, pending, providers, currentId: cred.id }) : null,
  });
}
