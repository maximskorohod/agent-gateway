// Общие хелперы серверных шаблонов. Шаблоны — чистые функции (data) => string.
// Любое значение из данных экранируется esc(). Готовая разметка приходит из html`…`
// (он возвращает Raw) или помечается raw() (например, QR-код SVG) и вставляется как есть.

import { t, lang, locale } from '../../i18n.js';

// Часовой пояс отображения дат: из конфигурации (GW_TZ), по умолчанию UTC. Задаётся при старте через setTimezone.
let TZ = 'UTC';

/** Задаёт пояс для fmtDate/isoDate. Неверное имя пояса игнорируется (остаётся прежний). */
export function setTimezone(tz) {
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
  } catch {
    return false;
  }
  TZ = tz;
  return true;
}

// Ссылка «Cloud: join the waitlist» в подвале (GW_WAITLIST_URL, уже проверена в buildApp); пусто — не показывается
let WAITLIST = '';

/** Задаёт адрес листа ожидания для подвала layout(). */
export function setWaitlistUrl(url) {
  WAITLIST = typeof url === 'string' ? url : '';
}

// Демо-режим (GW_DEMO=1): баннер на каждой странице, без ссылки на настройки и без «Выйти» (маршруты закрыты allowlist-ом)
let DEMO = false;

/** Включает баннер демо в layout(); вызывает buildApp. */
export function setDemoMode(on) {
  DEMO = Boolean(on);
}

/** Демо-режим включён: экраны скрывают кнопки маршрутов, закрытых allowlist-ом. */
export const isDemo = () => DEMO;

/** Ссылка на лист ожидания или пустая строка; без скриптов и параметров. */
export function waitlistLink() {
  return WAITLIST ? html`<a class="waitlist" href="${WAITLIST}" rel="noopener noreferrer" target="_blank">${t('cloud.waitlist')}</a>` : '';
}

/** Разметка, которой можно доверять: уже экранирована или создана в коде. */
export class Raw {
  constructor(value) {
    this.value = value;
  }
}

/** Помечает строку как готовую HTML-разметку без экранирования. */
export const raw = (s) => new Raw(s == null ? '' : String(s));

/** Экранирование для текста и атрибутов: & < > " ' */
export function esc(s) {
  if (s == null || s === false) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Значение атрибута (кавычки экранируются тем же esc). */
export const attr = esc;

/** Кодирование сегмента пути (id, slug) для href и action. */
export const enc = (s) => encodeURIComponent(String(s ?? ''));

function piece(v) {
  if (v instanceof Raw) return v.value;
  if (Array.isArray(v)) return v.map(piece).join('');
  return esc(v);
}

/**
 * Тегированный шаблон: все подстановки экранируются, кроме Raw и массивов из них.
 * null, undefined и false дают пустую строку, поэтому `${cond && html`…`}` работает.
 */
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += piece(values[i]) + strings[i + 1];
  return new Raw(out);
}

/** POST-форма с скрытым CSRF-полем. action пустой — постим на текущий адрес. */
export function form(action, inner, csrf) {
  return html`<form method="post" action="${action}"><input type="hidden" name="_csrf" value="${csrf}">${inner}</form>`;
}

const fmtCache = new Map();

function partsOf(unix) {
  const ck = `${locale}|${TZ}`;
  let f = fmtCache.get(ck);
  if (!f) {
    f = new Intl.DateTimeFormat(locale, {
      timeZone: TZ,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    });
    fmtCache.set(ck, f);
  }
  const p = {};
  const d = new Date(Number(unix) * 1000);
  for (const x of f.formatToParts(d)) p[x.type] = x.value;
  // название месяца словом: «4 Nov 2026» читается однозначно, в отличие от «04/11/2026»
  const mk = `m|${ck}`;
  let mf = fmtCache.get(mk);
  if (!mf) {
    // с числом: иначе в ru месяц в именительном падеже («4 май» вместо «4 мая»)
    mf = new Intl.DateTimeFormat(locale, { timeZone: TZ, day: 'numeric', month: 'short' });
    fmtCache.set(mk, mf);
  }
  p.monthName = mf.formatToParts(d).find((x) => x.type === 'month')?.value ?? p.month;
  p.dayNum = String(Number(p.day));
  return p;
}

/** Дата и время в поясе владельца (по умолчанию UTC): en «4 Nov 2026, 17:29», ru «4 нояб. 2026, 17:29». */
export function fmtDate(unix) {
  if (unix == null) return '—';
  const p = partsOf(unix);
  return t('fmt.datetime', { day: p.day, month: p.month, year: p.year, hour: p.hour, minute: p.minute, dayNum: p.dayNum, monthName: p.monthName });
}

/** Имя ключа для вывода: у ключей, созданных раньше, label может быть пустым — тогда имя сервиса (из providers) или slug. */
export function keyName(cred, providers = []) {
  const label = String(cred?.label ?? '').trim();
  if (label) return label;
  const slug = cred?.provider ?? '';
  return providers.find((p) => p.slug === slug)?.name || slug;
}

/** Дата для поля type=date: «гггг-мм-дд» в поясе владельца. */
export function isoDate(unix) {
  const p = partsOf(unix);
  return `${p.year}-${p.month}-${p.day}`;
}

/** Длительность в секундах: «5 мин», «2 ч», «1 ч 30 мин». */
export function fmtDuration(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const H = t('unit.h');
  const M = t('unit.min');
  if (h === 0) return `${m} ${M}`;
  if (m === 0) return `${h} ${H}`;
  return `${h} ${H} ${m} ${M}`;
}

/** Русское склонение: plural(2, ['вызов', 'вызова', 'вызовов']) → «вызова». */
export function plural(n, [one, few, many]) {
  if (lang === 'en') return n === 1 ? one : many;
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

// Знак в шапке: проём ворот со стрелкой, рисуется цветом акцента (SVG без скриптов).
const BRAND_MARK = raw('<svg class="mark" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">'
  + '<rect class="mark-bg" x="2" y="2" width="20" height="20" rx="6"/>'
  + '<path class="mark-fg" d="M7 17V9a5 5 0 0 1 10 0v8M12 11v5m-2-2 2 2 2-2"/></svg>');

/**
 * Перевод с разметкой в подстановках: текст словаря экранируется, значения Raw (strong, code) вставляются как есть.
 * th('agents.created', { name: html`<strong>${n}</strong>` })
 */
export function th(key, params = {}) {
  const parts = t(key).split(/\{(\w+)\}/);
  return new Raw(parts.map((p, i) => (i % 2 === 0 ? esc(p) : (Object.hasOwn(params, p) ? piece(params[p]) : esc(`{${p}}`)))).join(''));
}

/**
 * Каркас страницы. body — Raw (из html`…`); обычная строка экранируется.
 * flash — { type: 'ok'|'error', text }. nav=false убирает ссылки разделов.
 * list — колонка со списком ключей слева от содержимого; listHome — экран самого списка: заголовок в колонке,
 * а на телефоне видна только она. pendingCount — счётчик заявок у раздела «Ключи». dim — затемнённый фон окна.
 */
export function layout(title, body, { flash = null, nav = true, csrf = '', list = null, listHome = false, pendingCount = 0, dim = false } = {}) {
  const flashBox = flash
    ? html`<div class="flash ${flash.type === 'ok' ? 'ok' : 'error'}" role="${flash.type === 'ok' ? 'status' : 'alert'}">${flash.text}</div>`
    : '';
  const badge = pendingCount > 0
    ? html`<span class="count" aria-label="${t('keys.pending', { n: pendingCount })}">${pendingCount}</span>`
    : '';
  // Компьютер: боковое меню. Телефон: то же меню полосой внизу экрана. Работает без JS.
  const navBox = nav
    ? html`<nav class="nav" aria-label="${t('nav.sections')}">
        <a href="/keys">${t('nav.keys')}${badge}</a>
        <a href="/agents">${t('nav.agents')}</a>
        <a href="/stats">${t('nav.activity')}</a>
        ${DEMO ? '' : html`<a href="/settings">${t('nav.settings')}</a>
        ${form('/logout', html`<button class="link" type="submit">${t('nav.sign_out')}</button>`, csrf)}`}
      </nav>`
    : '';
  // Ссылка на лист ожидания в баннере показывается, только если адрес задан (waitlistLink() пуст без него)
  const demoBanner = DEMO ? html`<div class="demo-banner" role="note">${t('demo.banner')}${waitlistLink()}</div>` : '';
  const bodyClass = [nav ? '' : 'bare', dim ? 'dim' : ''].filter(Boolean).join(' ');
  const main = list
    ? html`<main class="wrap has-list ${listHome ? 'list-home' : 'list-detail'}">
${flashBox}
<aside class="list-col">${listHome ? html`<h1>${title}</h1>` : ''}${list}</aside>
<div class="detail-col">${listHome ? '' : html`<h1>${title}</h1>`}${body}</div>
</main>`
    : html`<main class="wrap">
<h1>${title}</h1>
${flashBox}
${body}
</main>`;
  return html`<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>${title} · ${t('app.name')}</title>
<link rel="icon" href="/public/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/public/style.css">
<script src="/public/app.js" defer></script>
</head>
<body${bodyClass ? html` class="${bodyClass}"` : ''}>
${demoBanner}
<header class="top"><div class="top-in"><a class="brand" href="/">${BRAND_MARK}${t('app.name')}</a>${navBox}</div></header>
${main}
<footer class="foot">${waitlistLink()}</footer>
</body>
</html>`.value;
}
