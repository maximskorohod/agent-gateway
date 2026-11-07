// Подключение канала заявок за несколько нажатий: общий блок мастера и онбординга.
// post(mode, поля) собирает форму своего экрана: у мастера скрытые step и mode, у онбординга свой адрес.
// Создать бота за человека нельзя: кнопки ведут в Telegram и Slack, сюда вставляется только результат.
import { html, layoutIcon, th } from './html.js';
import { t } from '../../i18n.js';
import { BOTFATHER_URL, slackCreateUrl, telegramStartUrl } from '../onboarding.js';

const outLink = (href, text, primary = false) => html`<a class="btn${primary ? ' primary' : ''}" href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
const head = (slug, title, hint) => html`<div class="head-ico">${layoutIcon(slug)}<h3>${title}</h3></div><p class="hint">${hint}</p>`;
// Канал свёрнут: на экране сначала выбор из двух вариантов, шаги видны только у выбранного. Работает без JS
const pick = (slug, title, hint) => html`<summary><span class="head-ico">${layoutIcon(slug)}<span><strong>${title}</strong><span class="muted small channel-why">${hint}</span></span></span></summary>`;

/** Выбор канала: Telegram или Slack, у каждого кнопка наружу и поле для результата. */
export function notifyChoice({ post }) {
  return html`
    <details class="channel">
      ${pick('telegram', t('notify.channel.telegram'), t('notify_setup.why_tg'))}
      <ol class="setup-steps">
        <li>${t('notify_setup.tg_step1')}<p>${outLink(BOTFATHER_URL, t('notify_setup.tg_open_father'), true)}</p></li>
        <li>${t('notify_setup.tg_step2')}
          <div class="token-box"><code id="tg-newbot">/newbot</code></div>
          <p class="actions"><button class="btn" type="button" data-copy="#tg-newbot" data-copied="${t('agents.copied')}" data-selected="${t('agents.selected')}">${t('agents.copy')}</button></p>
        </li>
        <li>${t('notify_setup.tg_step3')}
          ${post('telegram', html`
            <label>${t('setup.bot_token')}
              <input type="password" name="token" autocomplete="off" autocapitalize="off" spellcheck="false" required>
            </label>
            <button class="btn primary" type="submit">${t('setup.tg_connect')}</button>`)}
        </li>
      </ol>
    </details>
    <details class="channel">
      ${pick('slack', t('notify.channel.slack'), t('notify_setup.why_slack'))}
      <ol class="setup-steps">
        <li>${t('notify_setup.slack_step1')}<p>${outLink(slackCreateUrl(), t('notify_setup.slack_open'), true)}</p></li>
        <li>${t('notify_setup.slack_step2')}</li>
        <li>${t('notify_setup.slack_step3')}
          ${post('slack', html`
            <label>${t('settings.slack_webhook')}
              <input type="password" name="webhook" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://hooks.slack.com/services/…" required>
            </label>
            <button class="btn primary" type="submit">${t('notify_setup.slack_connect')}</button>`)}
        </li>
      </ol>
    </details>`;
}

/** Токен принят: остаётся нажать Start у своего бота. Код короткоживущий, поэтому текст запасного пути рядом. */
export function telegramLinkStep({ post, code, botUsername }) {
  const url = telegramStartUrl(botUsername, code);
  return html`
    <div class="channel">
      ${head('telegram', t('notify.channel.telegram'), t('notify_setup.tg_start_hint'))}
      ${url ? html`<p>${outLink(url, t('notify_setup.tg_open_bot'), true)}</p>` : ''}
      <p class="hint">${th(botUsername ? 'setup.tg_write' : 'settings.tg_write_nobot', { bot: html`<strong>@${botUsername}</strong>`, command: html`<code>/start ${code}</code>` })}</p>
      ${post('check', html`<button class="btn${url ? '' : ' primary'}" type="submit">${t('setup.check')}</button>`)}
    </div>`;
}
