// Экран «Настройки», страница привязки Telegram и журнал аудита.
import { html, form, layout, fmtDate, raw, th } from './html.js';
import { t, hasKey } from '../../i18n.js';

function sessionRow(s) {
  return html`<li class="item">
      <span class="grow">
        <span>${s.ua || t('settings.unknown_device')}${s.current ? html` <span class="tag">${t('settings.this_device')}</span>` : ''}</span>
        <span class="muted small">${t('settings.signed_in', { date: fmtDate(s.created_at) })}</span>
      </span>
    </li>`;
}

function telegramBlock(csrf, telegramConnected, botUsername) {
  if (telegramConnected) {
    return html`
      <p>${botUsername ? th('settings.tg_connected', { bot: html`<strong>@${botUsername}</strong>` }) : t('settings.tg_connected_nobot')}</p>
      ${form('/settings/telegram/disconnect', html`<button class="btn" type="submit">${t('settings.tg_disconnect')}</button>`, csrf)}
    `;
  }
  return html`
    <p class="muted">${t('settings.tg_none')}</p>
    ${form('/settings/telegram/connect', html`
      <label>${t('settings.bot_token')}
        <input type="password" name="token" autocomplete="off" autocapitalize="off" spellcheck="false" required>
      </label>
      <button class="btn primary" type="submit">${t('settings.tg_connect')}</button>
    `, csrf)}
  `;
}

const NOTIFY_EVENTS = ['request.created', 'request.decided', 'grant.auto', 'key.expired', 'security', 'info'];
const evKey = (e) => 'notify.ev.' + e.replace('.', '_');

// Секреты (адрес вебхука Slack, пароль SMTP) в разметку не попадают никогда: поля пустые, показывается только «сохранено».
function notifyChannel(csrf, id, st) {
  const on = (cond) => (cond ? raw(' checked') : '');
  const toggle = form(`/settings/notify/${id}`, html`
    <label class="check"><input type="checkbox" name="enabled" value="1"${on(st.enabled)}> ${t('settings.notify_enabled')}</label>
    <fieldset class="events"><legend class="muted small">${t('settings.notify_events')}</legend>
      ${NOTIFY_EVENTS.map((e) => html`<label class="check"><input type="checkbox" name="events" value="${e}"${on(st.events.includes(e))}> ${t(evKey(e))}</label>`)}
    </fieldset>
    <button class="btn" type="submit">${t('settings.notify_save')}</button>
  `, csrf);
  const secret = id === 'slack'
    ? form('/settings/notify/slack/secret', html`
        <label>${t('settings.slack_webhook')}
          <input type="password" name="webhook" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://hooks.slack.com/services/…" required>
        </label>
        <button class="btn primary" type="submit">${t('settings.notify_secret_save')}</button>`, csrf)
    : form('/settings/notify/email/secret', html`
        <label>${t('settings.smtp_host')}<input name="host" autocomplete="off" placeholder="smtp.example.com" required></label>
        <label>${t('settings.smtp_port')}
          <select name="port"><option value="587">587 STARTTLS</option><option value="465">465 TLS</option></select>
        </label>
        <label>${t('settings.smtp_user')}<input name="user" autocomplete="off"></label>
        <label>${t('settings.smtp_pass')}<input type="password" name="pass" autocomplete="new-password"></label>
        <label>${t('settings.smtp_from')}<input name="from" autocomplete="off" placeholder="gateway@example.com" required></label>
        <label>${t('settings.smtp_to')}<input name="to" autocomplete="off" placeholder="you@example.com" required></label>
        <button class="btn primary" type="submit">${t('settings.notify_secret_save')}</button>`, csrf);
  return html`<div class="notify-ch">
    <h3>${t(`notify.channel.${id}`)}</h3>
    <p class="muted">${st.configured ? t('settings.notify_secret_set') : t('settings.notify_secret_unset')}</p>
    ${toggle}
    <details><summary>${t('settings.notify_secret_change')}</summary>${secret}</details>
    ${st.configured ? html`<div class="actions">
      ${form(`/settings/notify/${id}/test`, html`<button class="btn" type="submit">${t('settings.notify_test')}</button>`, csrf)}
      ${form(`/settings/notify/${id}/clear`, html`<button class="btn" type="submit">${t('settings.notify_clear')}</button>`, csrf)}
    </div>` : ''}
  </div>`;
}

/** Настройки: пароль, 2FA, Telegram, уведомления, сессии, аварийный выход, ссылка на журнал. */
export function settingsPage({ csrf, owner = {}, sessions = [], telegramConnected = false, botUsername = '', flash = null, tgCode = null, backupCodes = null, reissueSecret = null, reissueQr = null, manageCredentials = true, notify = null } = {}) {
  // Блоки пароля и 2FA показываются, только если провайдер входа отдаёт их шлюзу (auth.capabilities.manageCredentials)
  return layout(t('settings.title'), html`
    ${manageCredentials ? html`<section class="card">
      <h2>${t('settings.pw_title')}</h2>
      ${form('/settings/password', html`
        <label>${t('settings.pw_current')}
          <input type="password" name="password_old" autocomplete="current-password" required>
        </label>
        <label>${t('settings.pw_new')}
          <input type="password" name="password_new" minlength="12" autocomplete="new-password" required>
        </label>
        <label>${t('settings.pw_repeat')}
          <input type="password" name="password_repeat" minlength="12" autocomplete="new-password" required>
        </label>
        <button class="btn primary" type="submit">${t('settings.pw_change')}</button>
      `, csrf)}
      <p class="hint">${t('settings.pw_hint')}</p>
    </section>

    <section class="card">
      <h2>${t('settings.2fa_title')}</h2>
      <p>${t('settings.2fa_status')} <strong>${owner.totp_enabled ? t('settings.2fa_on') : t('settings.2fa_off')}</strong></p>
      <div class="actions">
        ${form('/settings/2fa/reissue', html`<button class="btn" type="submit">${t('settings.2fa_reissue')}</button>`, csrf)}
        ${form('/settings/2fa/backup-codes', html`<button class="btn" type="submit">${t('settings.2fa_backup')}</button>`, csrf)}
      </div>
      <p class="hint">${t('settings.2fa_hint')}</p>
      ${reissueSecret ? html`
        <div class="qr">${raw(reissueQr || '')}</div>
        <p>${t('setup.manual_key')} <code>${reissueSecret}</code></p>
        ${form('/settings/2fa/confirm', html`
          <label>${t('settings.2fa_new_code')}
            <input name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>
          </label>
          <button class="btn primary" type="submit">${t('settings.2fa_confirm')}</button>
        `, csrf)}` : ''}
      ${Array.isArray(backupCodes) && backupCodes.length ? html`
        <p>${t('settings.backup_shown')}</p>
        <pre class="codes">${backupCodes.join('\n')}</pre>` : ''}
    </section>` : ''}

    <section class="card">
      <h2>Telegram</h2>
      ${telegramBlock(csrf, telegramConnected, botUsername)}
      ${!telegramConnected && tgCode ? html`
        <p class="notice">${th(botUsername ? 'settings.tg_write' : 'settings.tg_write_nobot', { bot: html`<strong>@${botUsername}</strong>`, command: html`<code>/start ${tgCode}</code>` })}</p>
        ${form('/settings/telegram/check', html`<button class="btn primary" type="submit">${t('settings.check')}</button>`, csrf)}` : ''}
    </section>

    ${notify ? html`<section class="card">
      <h2>${t('settings.notify_title')}</h2>
      <p class="hint">${t('settings.notify_hint')}</p>
      ${notifyChannel(csrf, 'slack', notify.slack)}
      ${notifyChannel(csrf, 'email', notify.email)}
    </section>` : ''}

    <section class="card">
      <h2>${t('settings.sessions_title')}</h2>
      ${sessions.length
        ? html`<ul class="list">${sessions.map(sessionRow)}</ul>`
        : html`<p class="muted">${t('settings.no_sessions')}</p>`}
      ${form('/settings/sessions/revoke', html`<button class="btn" type="submit">${t('settings.sign_out_all')}</button>`, csrf)}
    </section>

    <section class="card">
      <h2>${t('settings.panic_title')}</h2>
      <p class="muted">${t('settings.panic_hint')}</p>
      <details class="fold">
        <summary>${t('settings.panic_open')}</summary>
        ${form('/settings/revoke-all', html`<button class="btn btn-danger" type="submit">${t('settings.panic')}</button>`, csrf)}
      </details>
    </section>

    <p><a href="/audit">${t('settings.audit_link')}</a></p>
  `, { csrf, flash });
}

/** Страница привязки Telegram: «Напишите боту /start {code}». Кнопка «Проверить» перезагружает страницу. */
export function tgLink({ code, botUsername } = {}) {
  return layout(t('settings.tg_link_title'), html`
    <p>${th('settings.tg_link_intro', { bot: html`<strong>@${botUsername}</strong>` })}</p>
    <p class="code-line"><code>/start ${code}</code></p>
    <p class="actions"><a class="btn primary" href="">${t('settings.tg_link_check')}</a></p>
  `, { nav: false });
}

// Имена полей meta, значения которых в журнале не показываются (на случай секрета в записи)
// tokens (счётчик токенов MCP) не секрет: совпадает только token и *_token
const SECRET_FIELD = /^(key|pass|code|authorization|cookie|bearer|url|credential)$|secret|(^|_)token$|password|webhook|api_?key/i;
const META_MAX = 200;
// Секретные поля скрываются и во вложенных объектах
const maskSecrets = (k, x) => (k && SECRET_FIELD.test(k) ? '***' : x);

/** Название события из словаря; неизвестный код показывается как есть. */
function eventName(code) {
  const key = `audit.ev.${String(code).replace(/\./g, '_')}`;
  return hasKey(key) ? t(key) : String(code ?? '');
}

/** meta_json (строка JSON или объект) → короткий текст «поле: значение · …»; секретные поля скрыты, пустое и null не выводятся. */
function metaText(m) {
  if (m == null) return '';
  let v = m;
  if (typeof m === 'string') {
    try { v = JSON.parse(m); } catch { return m.slice(0, META_MAX); }
  }
  if (v == null) return '';
  if (typeof v !== 'object') return String(v).slice(0, META_MAX);
  const part = (x) => (x !== null && typeof x === 'object' ? JSON.stringify(x, maskSecrets) : String(x));
  const text = Object.entries(v)
    .filter(([, x]) => x !== null && x !== undefined && x !== '')
    .map(([k, x]) => `${k}: ${SECRET_FIELD.test(k) ? '***' : part(x)}`)
    .join(' · ');
  return text.length > META_MAX ? `${text.slice(0, META_MAX)}…` : text;
}

function auditRow(r) {
  return html`<tr>
      <td>${fmtDate(r.at)}</td>
      <td class="who">${r.actor}</td>
      <td class="ev" title="${r.action}">${eventName(r.action)}</td>
      <td>${r.target ? html`<code>${r.target}</code>` : ''}</td>
      <td class="meta">${metaText(r.meta)}</td>
    </tr>`;
}

/** Журнал аудита: таблица at, actor, action, target, meta. */
export function auditPage({ rows = [], csrf } = {}) {
  return layout(t('audit.title'), html`
    ${rows.length
      ? html`<div class="table-wrap">
          <table>
            <thead><tr><th>${t('audit.when')}</th><th>${t('audit.who')}</th><th>${t('audit.action')}</th><th>${t('audit.target')}</th><th>${t('audit.details')}</th></tr></thead>
            <tbody>${rows.map(auditRow)}</tbody>
          </table>
        </div>`
      : html`<p class="empty">${t('audit.empty')}</p>`}
    <p><a href="/settings">${t('audit.back')}</a></p>
  `, { csrf });
}
