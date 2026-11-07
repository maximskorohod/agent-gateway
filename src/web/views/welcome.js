// Онбординг «Connect your agent»: карточки агентов, первый ключ, уведомления, экран «It works».
// Без инлайн-скриптов и внешних ресурсов; кнопка Copy работает через data-copy из /public/app.js.
import { html, form, layout, layoutIcon, enc, th, waitlistLink, fmtDate, showcaseBanner } from './html.js';
import { t, hasKey } from '../../i18n.js';
import { KINDS, snippetFor } from '../onboarding.js';
import { notifyChoice, telegramLinkStep } from './notify-setup.js';

// Заглушки витрины: посетитель не должен принять адрес демо за адрес своего шлюза
const SHOWCASE_URL = 'https://gateway.example.com';
const SHOWCASE_TOKEN = 'YOUR_AGENT_TOKEN';
const CHECKED_LIVE_URL = 'https://github.com/maximskorohod/agentkeygate#connect-an-agent';

// Типы, где сниппет читает AGENTKEYGATE_TOKEN: без этого блока переменная осталась бы пустой и агент получил бы 401.
const tokenEnvBlock = (text) => (text.includes('AGENTKEYGATE_TOKEN')
  ? html`<p class="hint">${t('welcome.token_env')}</p><pre class="codes">${t('welcome.token_env_cmd')}</pre>`
  : '');

const copyButton = (target, primary = false) => html`<p class="actions"><button class="btn${primary ? ' primary' : ''}" type="button" data-copy="${target}" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>`;

const mark = (done) => (done ? html`<span class="tag">${t('welcome.done')}</span>` : '');
const agentLogo = (kind) => layoutIcon(`agent-${kind}`);
const agentHead = (kind, caption) => html`<div class="head-ico">${agentLogo(kind)}<span class="muted">${caption}</span></div>`;

function agentCards(csrf) {
  return html`<ul class="grid">${KINDS.map((k) => html`<li>${form(`/welcome/agent/${enc(k)}`, html`
      <button class="tile" type="submit">${agentLogo(k)}<strong>${t(`welcome.card.${k}`)}</strong><span class="muted small">${t(`welcome.card.${k}_hint`)}</span></button>`, csrf)}</li>`)}</ul>`;
}

/** Шаг уведомлений: готово — ссылка на настройки; ждём Start у бота — кнопка на бота; иначе выбор канала. */
function notifyStep(csrf, state, tgCode, botUsername) {
  const open = html`<p><a class="btn" href="/settings">${t('welcome.s3_open')}</a></p>`;
  if (state.notify && !tgCode) return open;
  const post = (mode, inner) => form(`/welcome/notify/${enc(mode)}`, inner, csrf);
  return html`
    ${tgCode ? telegramLinkStep({ post, code: tgCode, botUsername }) : notifyChoice({ post })}
    <div class="actions">
      ${form('/welcome/skip-notify', html`<button class="btn" type="submit">${t('welcome.s3_skip')}</button>`, csrf)}
      <a class="btn" href="/settings">${t('notify_setup.other')}</a>
    </div>`;
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
export function welcomePage({ csrf, state, providers = [], flash = null, tgCode = null, botUsername = null } = {}) {
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
      ${notifyStep(csrf, state, tgCode, botUsername)}
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
  const envBlock = tokenEnvBlock(text);
  return layout(t('welcome.created_title', { name: agent.name }), html`
    ${agentHead(kind, t(`welcome.card.${kind}`))}
    <p class="hint">${how}</p>
    <h2>${t('welcome.snippet')}</h2>
    <pre class="codes" id="snippet">${text}</pre>
    <p class="actions"><button class="btn primary" type="button" data-copy="#snippet" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <h2>${t('welcome.token_label')}</h2>
    <div class="token-box"><code id="token">${token}</code></div>
    <p class="actions"><button class="btn" type="button" data-copy="#token" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <p class="warn" role="alert">${t('welcome.token_warn')}</p>
    ${envBlock}
    <h2>${t('welcome.say_title')}</h2>
    <pre class="codes" id="say">${t('welcome.say_to_agent')}</pre>
    <p class="actions"><button class="btn" type="button" data-copy="#say" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
    <p class="actions"><a class="btn" href="/welcome/check/${enc(agent.id)}" target="_blank" rel="noopener noreferrer">${t('welcome.check_open')}</a></p>
    <p><a href="/welcome">${t('welcome.back')}</a></p>
  `, { csrf });
}

/** Витрина: карточки агентов ведут на просмотр настройки, агент не создаётся. */
export function showcaseConnect() {
  return layout(t('welcome.title'), html`
    ${showcaseBanner()}
    <p class="muted">${t('showcase.connect_hint')}</p>
    <ul class="grid">${KINDS.map((k) => html`<li><a class="tile" href="/showcase/connect/${enc(k)}">${agentLogo(k)}<strong>${t(`welcome.card.${k}`)}</strong><span class="muted small">${t(`welcome.card.${k}_hint`)}</span></a></li>`)}</ul>
  `);
}

/** Витрина: настройка одного агента с заглушками адреса и токена. Статус живой проверки только в README, чтобы текст не устаревал. */
export function showcaseAgent({ kind = 'script' } = {}) {
  const text = snippetFor(kind, { publicUrl: SHOWCASE_URL, token: SHOWCASE_TOKEN });
  return layout(t(`welcome.card.${kind}`), html`
    ${showcaseBanner()}
    ${agentHead(kind, t('showcase.agent_caption'))}
    <p class="hint">${hasKey(`welcome.how.${kind}`) ? t(`welcome.how.${kind}`) : ''}</p>
    <h2>${t('welcome.snippet')}</h2>
    <pre class="codes" id="snippet">${text}</pre>
    ${copyButton('#snippet', true)}
    <p class="hint">${t('showcase.token_note')}</p>
    ${tokenEnvBlock(text)}
    <h2>${t('welcome.say_title')}</h2>
    <pre class="codes" id="say">${t('welcome.say_to_agent')}</pre>
    ${copyButton('#say')}
    <p><a href="${CHECKED_LIVE_URL}" target="_blank" rel="noopener noreferrer">${t('showcase.checked_live')}</a></p>
    <p><a href="/showcase/connect">${t('showcase.back_connect')}</a></p>
  `);
}

/**
 * Проверка подключения (ТЗ 1.0.2): без JS и опроса. Показывает «ещё нет» или дату последней
 * авторизации агента (agents.last_seen_at), обновляется переходом по ссылке «Обновить».
 * В демо маршрут закрыт allowlist-ом (в таблицу demoRouteGuard не добавлен).
 */
export function welcomeCheck({ agent = {} } = {}) {
  const when = agent.last_seen_at ? fmtDate(agent.last_seen_at) : t('welcome.check_none');
  return layout(t('welcome.check_title', { name: agent.name }), html`
    <section class="card" role="status">
      <p class="hint">${t('welcome.check_hint')}</p>
      <p><strong>${when}</strong></p>
      <p class="actions"><a class="btn" href="/welcome/check/${enc(agent.id)}">${t('welcome.check_refresh')}</a></p>
    </section>
    <p><a href="/welcome">${t('welcome.back')}</a></p>
  `);
}
