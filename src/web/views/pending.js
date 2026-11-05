// Страница «Применить сохранённые изменения?»: сводка «было → стало» и две кнопки-формы (применить, отменить).
import { html, form, layout, enc } from './html.js';
import { t } from '../../i18n.js';

/**
 * summary — { title, before?: {подпись: значение}, after?: {подпись: значение} } из ACTIONS[type].summary.
 * Без before (создание) показываются только новые значения.
 */
export function pendingPage({ csrf, id, summary, flash = null } = {}) {
  const rows = Object.entries(summary.after || {});
  const before = summary.before || null;
  const table = rows.length
    ? html`<div class="table-wrap"><table class="stats diff">
        <thead><tr><th>${t('pending.col_field')}</th>${before ? html`<th>${t('pending.col_before')}</th>` : ''}<th>${t('pending.col_after')}</th></tr></thead>
        <tbody>${rows.map(([k, v]) => html`<tr><td>${k}</td>${before ? html`<td data-label="${t('pending.col_before')}">${before[k]}</td>` : ''}<td data-label="${t('pending.col_after')}"><strong>${v}</strong></td></tr>`)}</tbody>
      </table></div>`
    : html`<p class="empty">${t('pending.no_changes')}</p>`;
  return layout(t('pending.heading'), html`
    <section class="card">
      <h2>${summary.title}</h2>
      <p class="hint">${t('pending.intro')}</p>
      ${table}
      <div class="actions">
        ${form(`/pending/${enc(id)}/apply`, html`<button class="btn primary" type="submit">${t('pending.apply')}</button>`, csrf)}
        ${form(`/pending/${enc(id)}/cancel`, html`<button class="btn" type="submit">${t('pending.cancel')}</button>`, csrf)}
      </div>
    </section>
  `, { csrf, flash });
}
