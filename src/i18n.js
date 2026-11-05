// Интернационализация: t(key, params), словари en/ru, глобальный t для модулей
import en from './i18n/en.js';
import ru from './i18n/ru.js';

export const LANGS = ['en', 'ru'];
const DICTS = { en, ru };
const LOCALES = { en: 'en-GB', ru: 'ru-RU' };
const warned = new Set();

export function createI18n(lang) {
  const code = LANGS.includes(lang) ? lang : 'en';
  const dict = DICTS[code];
  function t(key, params) {
    const s = dict[key];
    if (typeof s !== 'string') {
      if (!warned.has(key)) { warned.add(key); console.warn(`i18n: missing key "${key}"`); }
      return key;
    }
    if (!params) return s;
    return s.replace(/\{(\w+)\}/g, (m, name) => (Object.hasOwn(params, name) ? String(params[name]) : m));
  }
  return { t, lang: code, locale: LOCALES[code], has: (key) => typeof dict[key] === 'string' };
}

let current = createI18n('en');

/** Глобальный t: живая привязка, меняется после initI18n */
export let t = current.t;
/** Текущий язык ('en' | 'ru') и локаль для Intl */
export let lang = current.lang;
export let locale = current.locale;

export function initI18n(code) {
  current = createI18n(code);
  t = current.t; lang = current.lang; locale = current.locale;
}

/** Есть ли ключ в текущем словаре (без предупреждения в консоль) */
export function hasKey(key) { return current.has(key); }

/** Подсказка к ключу сервиса: словарь `catalog.hint.<slug>`, запасной вариант — keyHint из providers.yaml */
export function providerHint(provider) {
  const key = `catalog.hint.${provider.slug}`;
  return hasKey(key) ? t(key) : (provider.keyHint || '');
}
