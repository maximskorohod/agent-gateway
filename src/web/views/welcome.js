// Онбординг «Connect your agent»: карточки агентов, первый ключ, уведомления, экран «It works».
// Без инлайн-скриптов и внешних ресурсов; кнопка Copy работает через data-copy из /public/app.js.
import { html, form, layout, enc, th, waitlistLink } from './html.js';
import { t, hasKey } from '../../i18n.js';
import { KINDS, snippetFor } from '../onboarding.js';

const mark = (done) => (done ? html`<span class="tag">${t('welcome.done')}</span>` : '');

function agentCards(csrf) {
  return html`<ul class="grid">${KINDS.map((k) => html`<li>${form(`/welcome/agent/${enc(k)}`, html`
      <button class="tile" type="submit"><strong>${t(`welcome.card.${k}`)}</strong><span class="muted small">${t(`welcome.card.${k}_hint`)}</span></button>`, csrf)}</li>`)}</ul>`;
}

/** Подпись «Get a key →»: только https-адрес из каталога. */
function getKeyLink(p) {
  const url = typeof p.getKeyUrl === 'string' && /^https:\/\//i.test(p.getKeyUrl) ? p.getKeyUrl : '';
  return url ? html`<a class="small" href="${url}" target="_blank" rel="noopener noreferrer">${t('key.get_key')}</a>` : '';
}

function keyGrid(providers) {
  return html`<ul class="grid">${providers.map((p) => html`<li>
      <a class="tile" href="/keys/new/${enc(p.slug)}"><img src="/public/icons/${enc(p.slug)}.svg" alt="" width="32" height="32"><span>${p.name}</span></a>
      ${getKeyLink(p)}
    </li>`)}</ul>`;
}

/** Экран «It works»: число успешных вызовов, ссылки на «Запросы» и аудит, лист ожидания (если задан). */
function worksBlock(calls) {
  return html`<section class="card" role="status">
    <h2>${t('welcome.works_title')}</h2>
    <p>${th('welcome.works', { n: html`<strong>${calls}</strong>` })}</p>
    <p class="actions"><a class="btn primary" href="/stats">${t('welcome.works_activity')}</a> <a class="btn" href="/audit">${t('welcome.works_audit')}</a></p>
    <p class="small">${waitlistLink()}</p>
  </section>`;
}

/** Главная страница онбординга. state — из onboardingState. */
export function welcomePage({ csrf, state, providers = [], flash = null } = {}) {
  return layout(t('welcome.title'), html`
    <p class="muted">${t('welcome.intro')} <strong>${t('welcome.progress', { n: state.count })}</strong></p>
    ${state.calls > 0 ? worksBlock(state.calls) : ''}
    <section class="card">
      <h2>${t('welcome.s1_title')} ${mark(state.agent)}</h2>
      <p class="hint">${t('welcome.s1_hint')}</p>
      ${agentCards(csrf)}
    </section>
    <section class="card">
      <h2>${t('welcome.s2_title')} ${mark(state.key)}</h2>
      <p class="hint">${t('welcome.s2_hint')}</p>
      ${keyGrid(providers)}
      <p><a class="btn" href="/keys/new">${t('welcome.s2_open')}</a></p>
    </section>
    <section class="card">
      <h2>${t('welcome.s3_title')} ${mark(state.notify)}</h2>
      <p class="hint">${t('welcome.s3_hint')}</p>
      <div class="actions">
        <a class="btn" href="/settings">${t('welcome.s3_open')}</a>
        ${state.notify ? '' : form('/welcome/skip-notify', html`<button class="btn" type="submit">${t('welcome.s3_skip')}</button>`, csrf)}
      </div>
    </section>
    <div class="actions">
      ${form('/welcome/skip', html`<button class="btn" type="submit">${t('welcome.skip_all')}</button>`, csrf)}
      <a href="/keys/new">${t('keys.add')}</a>
    </div>
  `, { csrf, flash });
}

/**
 * Страница после нажатия карточки: токен и текст настройки. Показывается один раз (no-store ставит onSend),
 * в адреса токен не попадает.
 */
export function welcomeAgentCreated({ csrf, agent = {}, token = '', kind = 'script', publicUrl = '' } = {}) {
  const text = snippetFor(kind, { publicUrl, token });
  const how = hasKey(`welcome.how.${kind}`) ? t(`welcome.how.${kind}`) : '';
  return layout(t('welcome.created_title', { name: agent.name }), html`
    <p class="hint">${how}</p>
    <h2>${t('welcome.snippet')}</h2>
    <pre class="codes" id="snippet">${text}</pre>
    <p class="actions"><button class="btn primary" type="button" data-copy="#snippet" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <h2>${t('welcome.token_label')}</h2>
    <div class="token-box"><code id="token">${token}</code></div>
    <p class="actions"><button class="btn" type="button" data-copy="#token" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <p class="warn" role="alert">${t('welcome.token_warn')}</p>
    <p><a href="/welcome">${t('welcome.back')}</a></p>
  `, { csrf });
}
