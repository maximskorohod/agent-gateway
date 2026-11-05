// Экраны входа, второго фактора и мастера первичной настройки.
import { html, raw, form, layout, th } from './html.js';
import { t } from '../../i18n.js';

/** Вход: пароль. */
export function login({ csrf, error, locked } = {}) {
  return layout(t('login.title'), html`
    ${locked ? html`<p class="warn" role="alert">${t('login.locked')}</p>` : ''}
    ${error ? html`<p class="error" role="alert">${error}</p>` : ''}
    ${form('/login', html`
      <label>${t('login.password')}
        <input type="password" name="password" autocomplete="current-password" required autofocus>
      </label>
      <button class="btn primary" type="submit"${locked ? raw(' disabled') : ''}>${t('login.submit')}</button>
    `, csrf)}
  `, { nav: false, csrf });
}

/** Код второго фактора. action — текст, зачем нужен код. Форма постит на /2fa. */
/** formAction — куда отправить код: по умолчанию вход/свежий код, для заявки — /requests/:id/approve-code. */
/** title — заголовок (по умолчанию «Код подтверждения»); details — [[подпись, значение]] контекста заявки. */
export function totp({ csrf, action, error, next = '/', formAction = '/totp', title, details = [] } = {}) {
  return layout(title || t('totp.title'), html`
    <p class="muted">${action || t('totp.default_action')}</p>
    ${details.length ? html`<dl class="ctx">${details.map(([k, v]) => html`<div><dt>${k}</dt><dd>${v}</dd></div>`)}</dl>` : ''}
    ${error ? html`<p class="error" role="alert">${error}</p>` : ''}
    ${form(formAction, html`
      <input type="hidden" name="next" value="${next}">
      <label>${t('totp.code')}
        <input name="code" inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required autofocus>
      </label>
      <button class="btn primary" type="submit">${t('totp.submit')}</button>
    `, csrf)}
    <p class="small"><a href="#backup">${t('totp.use_backup')}</a></p>
    <p id="backup" class="hint">${t('totp.backup_hint')}</p>
  `, { nav: false, csrf });
}

function stepOne(csrf) {
  return form('', html`
    <input type="hidden" name="step" value="1">
    <p class="muted">${t('setup.password_hint')}</p>
    <label>${t('setup.password')}
      <input type="password" name="password" minlength="12" autocomplete="new-password" required autofocus>
    </label>
    <label>${t('setup.password_repeat')}
      <input type="password" name="password_repeat" minlength="12" autocomplete="new-password" required>
    </label>
    <button class="btn primary" type="submit">${t('setup.next')}</button>
  `, csrf);
}

function stepTwo(csrf, d) {
  if (Array.isArray(d.backupCodes) && d.backupCodes.length) {
    return html`
      <div class="codes-box">
        <pre class="codes" id="backup-codes">${d.backupCodes.join('\n')}</pre>
        <p class="actions">
          <a class="btn primary" href="${d.downloadHref || '#'}" download data-saves-codes>${t('setup.download')}</a>
          <button class="btn" type="button" data-copy="#backup-codes" data-saves-codes data-copied="${t('agents.copied')}" data-selected="${t('agents.copied')}">${t('agents.copy')}</button>
        </p>
      </div>
      <p class="callout">${t('setup.codes_note')}</p>
      ${form('', html`<input type="hidden" name="step" value="3"><button class="btn wide" type="submit" data-after-save>${t('setup.saved_next')}</button>`, csrf)}
    `;
  }
  return html`
    <p>${t('setup.scan')}</p>
    <div class="qr">${raw(d.qrSvg)}</div>
    <p>${t('setup.manual_key')} <code>${d.secret}</code></p>
    ${form('', html`
      <input type="hidden" name="step" value="2">
      <label>${t('setup.app_code')}
        <input name="code" inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" required autofocus>
      </label>
      <button class="btn primary" type="submit">${t('setup.verify')}</button>
    `, csrf)}
  `;
}

function stepThree(csrf, d) {
  if (d.tgCode) {
    return html`
      <p class="notice">${th('setup.tg_write', { bot: html`<strong>@${d.botUsername}</strong>`, command: html`<code>/start ${d.tgCode}</code>` })}</p>
      ${form('', html`
        <input type="hidden" name="step" value="3">
        <input type="hidden" name="mode" value="check">
        <button class="btn primary" type="submit">${t('setup.check')}</button>
      `, csrf)}
    `;
  }
  return html`
    <p class="muted">${t('setup.tg_intro')}</p>
    ${form('', html`
      <input type="hidden" name="step" value="3">
      <input type="hidden" name="mode" value="telegram">
      <label>${t('setup.bot_token')}
        <input type="password" name="token" autocomplete="off" autocapitalize="off" spellcheck="false" required>
      </label>
      <button class="btn primary" type="submit">${t('setup.tg_connect')}</button>
    `, csrf)}
    ${form('', html`
      <input type="hidden" name="step" value="3">
      <input type="hidden" name="mode" value="skip">
      <button class="btn" type="submit">${t('setup.tg_skip')}</button>
    `, csrf)}
  `;
}

/** Мастер настройки: step 1 — пароль, 2 — 2FA (QR или резервные коды), 3 — Telegram. */
export function setup({ csrf, step = 1, data, error, flash = null } = {}) {
  const d = data || {};
  const n = Number(step) || 1;
  const content = n === 1 ? stepOne(csrf) : n === 2 ? stepTwo(csrf, d) : stepThree(csrf, d);
  const codesStep = n === 2 && Array.isArray(d.backupCodes) && d.backupCodes.length > 0;
  return layout(codesStep ? t('setup.codes_title') : t('setup.title'), html`
    <p class="muted center">${t('setup.step', { n })}</p>
    ${error ? html`<p class="error" role="alert">${error}</p>` : ''}
    ${content}
  `, { nav: false, csrf, flash, dim: codesStep });
}
