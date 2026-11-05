// Экран агентов: список, привязка ключей, создание, токен (показывается один раз).
import { html, raw, form, layout, enc, fmtDate, th, keyName, isDemo } from './html.js';
import { t } from '../../i18n.js';
import { DEMO_AGENT_ID } from '../../demo/reset.js';

const chk = (cond) => (cond ? raw(' checked') : '');

/** Подпись привязки: «все ключи» или названия выбранных. */
function keysText(a, credentials, ids, providers) {
  if (a.all_credentials) return t('agents.keys_all');
  const names = credentials.filter((c) => ids.includes(c.id)).map((c) => keyName(c, providers));
  return names.length ? names.join(', ') : t('agents.keys_none');
}

/**
 * Поля выбора ключей: «все» или только отмеченные. Общие для формы создания и страницы агента.
 * name="keys_all" = 1|0, name="keys" — id отмеченных ключей.
 */
function keyFields(credentials, { all = true, ids = [], providers = [] } = {}) {
  return html`
    <fieldset>
      <legend>${t('agents.keys_legend')}</legend>
      <label class="inline"><input type="radio" name="keys_all" value="1"${chk(all)}> ${t('agents.keys_all_new')}</label>
      <label class="inline"><input type="radio" name="keys_all" value="0"${chk(!all)}> ${t('agents.keys_only')}</label>
      ${credentials.length
        ? html`<ul class="checks">${credentials.map((c) => html`<li><label class="inline"><input type="checkbox" name="keys" value="${c.id}"${chk(ids.includes(c.id))}>
            <img class="ico-sm" src="/public/icons/${enc(c.provider)}.svg" alt="" width="20" height="20"> ${keyName(c, providers)} <span class="mask">····${c.last4}</span></label></li>`)}</ul>`
        : html`<p class="hint">${t('agents.keys_empty')}</p>`}
      <p class="hint">${t('agents.keys_hint')}</p>
    </fieldset>`;
}

function agentRow(a, csrf, credentials, ids, providers) {
  const id = enc(a.id);
  const seen = a.last_seen_at ? t('agents.last_seen', { date: fmtDate(a.last_seen_at) }) : t('agents.never');
  return html`
    <li class="card">
      <div class="agent">
        <div class="grow">
          <strong>${a.name}</strong>
          <span class="muted small">${a.enabled ? t('agents.enabled') : t('agents.disabled')} · ${seen}</span>
          <span class="muted small">${t('agents.keys_label', { keys: keysText(a, credentials, ids, providers) })}</span>
        </div>
        <div class="actions">
          <a class="btn" href="/stats?agent=${id}">${t('nav.activity')}</a>
          ${isDemo() ? '' : html`${a.enabled
            ? form(`/agents/${id}/disable`, html`<button class="btn" type="submit">${t('agents.disable')}</button>`, csrf)
            : form(`/agents/${id}/enable`, html`<button class="btn primary" type="submit">${t('agents.enable')}</button>`, csrf)}
          <details class="fold inline-fold">
            <summary>${t('agents.delete')}</summary>
            ${form(`/agents/${id}/delete`, html`<button class="btn btn-danger" type="submit">${t('agents.delete_agent')}</button>`, csrf)}
          </details>`}
        </div>
      </div>
      ${isDemo() && a.id === DEMO_AGENT_ID ? '' : html`<details class="fold">
        <summary>${t('agents.keys_edit')}</summary>
        ${form(`/agents/${id}/keys`, html`
          ${keyFields(credentials, { all: !!a.all_credentials, ids, providers })}
          <button class="btn primary" type="submit">${t('common.save')}</button>
        `, csrf)}
      </details>`}
    </li>`;
}

/** Список агентов и форма «+ Добавить». bindings — { [agentId]: credentialId[] }. */
export function agentsPage({ csrf, agents = [], credentials = [], bindings = {}, flash = null, providers = [] } = {}) {
  return layout(t('agents.title'), html`
    ${agents.length
      ? html`<ul class="list">${agents.map((a) => agentRow(a, csrf, credentials, bindings[a.id] ?? [], providers))}</ul>`
      : html`<p class="empty">${t('agents.none')}</p>`}
    <p class="hint">${t('agents.hint')}</p>
    <section class="card">
      <h2>${t('agents.new_title')}</h2>
      ${form('/agents', html`
        <label>${t('agents.name')}
          <input name="name" required maxlength="60" autocomplete="off" spellcheck="false" placeholder="${t('agents.name_ph')}">
        </label>
        ${keyFields(credentials, { all: true, providers })}
        <button class="btn primary" type="submit">${t('agents.add')}</button>
      `, csrf)}
    </section>
  `, { csrf, flash });
}

/** Показ токена один раз. Токен в <code id="token">, кнопка копирует его через data-copy. */
export function agentCreated({ csrf, agent = {}, token = '' } = {}) {
  return layout(t('agents.created_title'), html`
    <p>${th('agents.created', { name: html`<strong>${agent.name}</strong>` })}</p>
    <div class="token-box"><code id="token">${token}</code></div>
    <p class="actions"><button class="btn primary" type="button" data-copy="#token" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <p class="warn" role="alert">${t('agents.token_warn')}</p>
    <p><a href="/agents">${t('agents.done')}</a></p>
  `, { csrf });
}
