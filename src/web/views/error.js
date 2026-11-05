// Страница ошибки: короткий текст без технических подробностей.
import { html, layout } from './html.js';
import { t } from '../../i18n.js';

/** opts.nav — показать меню (для вошедшего владельца), opts.csrf нужен форме «Выйти» в меню. */
export function errorPage(code, text, { nav = false, csrf = '' } = {}) {
  return layout(t('error.title', { code }), html`
    <p>${text}</p>
    <p><a href="/">${t('error.home')}</a></p>
  `, { nav, csrf });
}
