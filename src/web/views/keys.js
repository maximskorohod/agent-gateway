// Экраны ключей: список и заявки (1), выбор сервиса (2), форма ключа (3), страница ключа.
import { html, raw, form, layout, enc, fmtDate, fmtDuration, plural, isoDate, keyName } from './html.js';
import { t, hasKey, providerHint } from '../../i18n.js';
import { normalizeFilter, protectionOf, defaultFilterFor } from '../../core/filter.js';

const MODE_OPTIONS = ['ask', 'always', 'deny'];
const ALWAYS_FOR = [[3600, 'policy.for_3600'], [86400, 'policy.for_86400'], [604800, 'policy.for_604800'], ['forever', 'policy.for_forever']];
const DAYS = [1, 2, 3, 4, 5, 6, 7];
const TTL_OPTIONS = [300, 900, 3600, 7200, 28800, 86400];
const DEFAULTS = { mode: 'ask', max_ttl: 3600, max_calls: 100, max_parallel: 2 };

const providerName = (providers, slug) => providers.find((p) => p.slug === slug)?.name ?? slug;
const sel = (cond) => (cond ? raw(' selected') : '');
const chk = (cond) => (cond ? raw(' checked') : '');

function approvalOptions(telegramConnected) {
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
function policyFields(v = {}, { telegramConnected = false, sensitive = false } = {}) {
  const win = v.window ?? {};
  const days = (win.days ?? v.days ?? []).map(Number);
  const mode = MODE_OPTIONS.includes(v.mode) ? v.mode : DEFAULTS.mode;
  const approvals = approvalOptions(telegramConnected);
  const approval = approvals.includes(v.approval) ? v.approval : approvals[0];
  const maxTtl = Number(v.max_ttl ?? DEFAULTS.max_ttl);
  const expires = typeof v.expires_at === 'number' ? isoDate(v.expires_at) : (v.expires_at ?? '');

  return html`
    <fieldset>
      <legend>${t('policy.how')}</legend>
      ${MODE_OPTIONS.map((m) => html`<label class="inline"><input type="radio" name="mode" value="${m}"${chk(mode === m)}> ${t(`policy.choice.${m}`)}</label>${m === 'always' ? alwaysForSelect(v) : ''}`)}
      <p class="hint">${t('policy.always_hint')}</p>
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
      <label>${t('policy.approval')}
        <select name="approval">
          ${approvals.map((a) => html`<option value="${a}"${sel(a === approval)}>${t(`policy.approval.${a}`)}</option>`)}
        </select>
      </label>
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
      <fieldset>
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
      <p class="hint">${t('policy.expires_hint')}</p>
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

function pendingCard(r, providers, csrf, filterLines = {}) {
  const id = enc(r.id);
  // имя ключа в скобках только если оно отличается от имени сервиса: «HubSpot (HubSpot)» не нужно
  const svc = providerName(providers, r.provider);
  const label = r.credential_label && r.credential_label.trim() !== svc ? html` (${r.credential_label})` : '';
  return html`
    <li class="card">
      <p><strong>${r.agent_name}</strong> → ${providerName(providers, r.provider)}${label}</p>
      <p class="muted small">${fmtDuration(r.ttl)} · ${r.calls} ${plural(r.calls, [t('unit.call.one'), t('unit.call.few'), t('unit.call.many')])}</p>
      ${r.reason ? html`<p class="reason">${t('keys.agent_reason', { reason: r.reason })}</p>` : ''}
      ${Object.hasOwn(filterLines, r.id) ? html`<p class="muted small">${filterLines[r.id]}</p>` : ''}
      <div class="actions">
        ${form(`/requests/${id}/approve`, html`<button class="btn primary" type="submit">${t('requests.approve')}</button>`, csrf)}
        ${form(`/requests/${id}/deny`, html`<button class="btn" type="submit">${t('requests.deny')}</button>`, csrf)}
      </div>
    </li>`;
}

function keyRow(c, providers) {
  return html`
    <li>
      <a class="row" href="/keys/${enc(c.id)}">
        <img class="ico" src="/public/icons/${enc(c.provider)}.svg" alt="" width="32" height="32">
        <span class="grow">
          <span class="title">${keyName(c, providers)}</span>
          <span class="muted small"><span class="dot dot-${c.mode}" aria-hidden="true"></span>${modeText(c)} · ${t('keys.grant_up_to', { ttl: fmtDuration(c.max_ttl).replace(/ /g, ' ') })}</span>
        </span>
        <span class="mask">····${c.last4}</span>
      </a>
    </li>`;
}

/** Экран 1: заявки «Ожидают», список ключей и кнопка «+». */
export function keysPage({ csrf, credentials = [], pending = [], providers = [], filterLines = {}, flash = null, onboarding = null, demo = false } = {}) {
  // демо: кнопка «Simulate agent request» создаёт заявку от демо-агента через настоящий requests.submit
  const demoBlock = demo
    ? html`<section class="card" role="note">
        <p class="muted">${t('demo.simulate_hint')}</p>
        ${form('/demo/simulate', html`<button class="btn primary" type="submit">${t('demo.simulate')}</button>`, csrf)}
      </section>`
    : '';
  // onboarding — { count } пока онбординг не пропущен и нет ни агента, ни ключа; иначе null
  const onboardingBlock = onboarding
    ? html`<section class="card" role="note"><p class="actions"><a class="btn primary" href="/welcome">${t('welcome.title')}</a> <span class="muted">${t('welcome.progress', { n: onboarding.count })}</span></p></section>`
    : '';
  const pendingBlock = pending.length
    ? html`<section class="pending">
        <h2>${t('keys.pending', { n: pending.length })}</h2>
        <ul class="list">${pending.map((r) => pendingCard(r, providers, csrf, filterLines))}</ul>
      </section>`
    : '';
  return layout(t('keys.title'), html`
    ${onboardingBlock}
    ${demoBlock}
    ${pendingBlock}
    <section>
      <div class="head">
        <h2>${t('keys.my_keys')}</h2>
        <a class="btn primary" href="/keys/new">+ ${t('keys.add')}</a>
      </div>
      ${credentials.length
        ? html`<ul class="list">${credentials.map((c) => keyRow(c, providers))}</ul>`
        : html`<div class="empty">
            <p>${t('keys.empty')}</p>
            <a class="btn primary" href="/keys/new">${t('keys.add')}</a>
          </div>`}
    </section>
  `, { csrf, flash });
}

/** Экран 2: сетка сервисов (включая «Другой»). */
export function pickProvider({ providers = [], csrf } = {}) {
  return layout(t('keys.new'), html`
    <p class="muted">${t('keys.pick_service')}</p>
    <ul class="grid">
      ${providers.map((p) => html`<li>
        <a class="tile" href="/keys/new/${enc(p.slug)}">
          <img src="/public/icons/${enc(p.slug)}.svg" alt="" width="32" height="32">
          <span>${p.name}</span>
        </a>
      </li>`)}
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
function protectFields(prov, f) {
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
      <p class="hint">${t('protect.weaken_hint')}</p>
    </fieldset>`;
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
        <p class="hint">${t('filter.deny_hint')}</p>` : ''}
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
export function keyDetail({ csrf, cred, provider, telegramConnected = false, flash = null, preview = null } = {}) {
  const id = enc(cred.id);
  const prov = provider ?? { slug: cred.provider, name: cred.provider };
  return layout(keyName(cred, [prov]), html`
    ${iconRow(prov, `${prov.name} · ····${cred.last4}`)}
    <p class="muted small">${t('key.added', { date: fmtDate(cred.created_at) })}</p>
    ${form(`/keys/${id}/policy`, html`
      ${policyFields(cred, { telegramConnected, sensitive: !!prov.sensitive })}
      <button class="btn primary" type="submit">${t('key.save')}</button>
    `, csrf)}
    ${prov.filter || protectionOf(prov).readOnly || protectionOf(prov).mask ? filterCard(cred, prov, csrf) : ''}
    ${previewCard(cred, prov, csrf, preview)}
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
    </section>
    <p><a href="/keys">${t('keys.back')}</a></p>
  `, { csrf, flash });
}
