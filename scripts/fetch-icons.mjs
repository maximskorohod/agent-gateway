// Загрузка иконок провайдеров в assets/icons/<slug>.svg (ТЗ §4).
// Порядок: Simple Icons с jsDelivr (версия зафиксирована, цвет бренда из data/simple-icons.json)
// → cdn.simpleicons.org → favicon.svg сайта сервиса → SVG-заглушка.
// cdn.simpleicons.org с адресов AWS отвечает 403 (проверка Cloudflare), поэтому он не первый.
// Запуск: node scripts/fetch-icons.mjs
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalog } from '../src/catalog.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const iconsDir = path.join(root, 'assets', 'icons');
const MAX_BYTES = 50 * 1024;        // итоговый размер после очистки
const MAX_RAW_BYTES = 1024 * 1024;  // защита памяти при скачивании
const TIMEOUT_MS = 10_000;

// Дополнительные имена в Simple Icons, которые не совпадают со slug и name.
const SIMPLE_ICON_ALIASES = {
  mistral: ['mistralai'],
  gemini: ['googlegemini'],
  // Имена в Simple Icons совпадают со slug; перечислены явно, чтобы не полагаться на нормализацию имени.
  openai: ['openai'],
  anthropic: ['anthropic'],
  slack: ['slack'],
  notion: ['notion'],
  linear: ['linear'],
  stripe: ['stripe'],
  hubspot: ['hubspot'],
  resend: ['resend'],
  sendgrid: ['sendgrid'],
  twilio: ['twilio'],
};
// Сайт с favicon.svg, если у сервиса нет иконки в Simple Icons, а API-хост своей не отдаёт.
const FAVICON_HOSTS = { groq: 'groq.com', bitrix24: 'www.bitrix24.ru' };
const SIMPLE_ICONS = 'https://cdn.jsdelivr.net/npm/simple-icons@16.36.0';

let brandHex = null; // slug Simple Icons → цвет бренда
async function loadBrandHex() {
  if (brandHex) return brandHex;
  brandHex = new Map();
  try {
    const data = JSON.parse((await fetchText(`${SIMPLE_ICONS}/data/simple-icons.json`)) ?? '[]');
    for (const i of data) if (i.slug && /^[0-9A-Fa-f]{6}$/.test(i.hex)) brandHex.set(i.slug, i.hex);
  } catch { /* без цвета — иконка будет чёрной */ }
  return brandHex;
}

async function fetchText(url) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctl.signal });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_RAW_BYTES) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Очистка SVG: скрипты, on*-атрибуты, внешние href, foreignObject.
 * @returns {string|null} очищенный SVG или null, если это не SVG или он не проходит проверки
 */
export function sanitizeSvg(raw) {
  // Убираем XML-декларацию и комментарии в начале.
  let s = raw.replace(/^﻿/, '').trim();
  s = s.replace(/^(?:<\?xml[^>]*\?>\s*|<!--[\s\S]*?-->\s*)+/i, '');
  if (!s.startsWith('<svg')) return null;
  // DOCTYPE и ENTITY не нужны иконке и открывают XXE.
  if (/<!DOCTYPE|<!ENTITY/i.test(s)) return null;

  s = s.replace(/<script\b[\s\S]*?<\/script\s*>/gi, '');
  s = s.replace(/<foreignObject\b[\s\S]*?<\/foreignObject\s*>/gi, '');
  s = s.replace(/<foreignObject\b[^>]*\/>/gi, '');
  s = s.replace(/\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  s = s.replace(/\s+(?:xlink:)?href\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, (match, dq, sq) => {
    const v = (dq ?? sq ?? '').trim().toLowerCase();
    return /^(https?:|javascript:|\/\/)/.test(v) ? '' : match;
  });

  if (/<script|javascript:|<foreignObject/i.test(s)) return null;
  if (Buffer.byteLength(s, 'utf8') > MAX_BYTES) return null;
  return s;
}

const escapeXml = (t) => t.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** SVG-заглушка: серый круг с буквой или знаком «+». */
function stubSvg(name, { plus = false } = {}) {
  const body = plus
    ? '<path d="M32 18v28M18 32h28" stroke="#ffffff" stroke-width="6" stroke-linecap="round"/>'
    : `<text x="32" y="32" dy=".35em" font-family="Arial, sans-serif" font-size="32" font-weight="600" text-anchor="middle" fill="#ffffff">${escapeXml([...name][0].toUpperCase())}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#6b7280"/>${body}</svg>\n`;
}

/** Ищет иконку провайдера: сначала Simple Icons, затем favicon хоста. */
async function findIcon(p) {
  const normName = p.name.toLowerCase().replace(/[^a-z0-9]/g, '');
  const candidates = [...new Set([p.slug, normName, ...(SIMPLE_ICON_ALIASES[p.slug] || [])])];
  const hex = await loadBrandHex();
  for (const c of candidates) {
    let svg = sanitizeSvg((await fetchText(`${SIMPLE_ICONS}/icons/${c}.svg`)) ?? '');
    if (svg) {
      if (hex.has(c)) svg = svg.replace(/^<svg\b/, `<svg fill="#${hex.get(c)}"`);
      return { svg, source: `Simple Icons jsDelivr (${c})` };
    }
    svg = sanitizeSvg((await fetchText(`https://cdn.simpleicons.org/${c}`)) ?? '');
    if (svg) return { svg, source: `Simple Icons (${c})` };
  }
  // favicon.ico намеренно не берём: это не SVG.
  const hosts = [...new Set([FAVICON_HOSTS[p.slug], p.host !== 'owner' ? p.host : null].filter(Boolean))];
  for (const h of hosts) {
    const svg = sanitizeSvg((await fetchText(`https://${h}/favicon.svg`)) ?? '');
    if (svg) return { svg, source: `favicon ${h}` };
  }
  return { svg: null, source: null };
}

/**
 * Что делать с иконкой провайдера (без сети, тестируется отдельно).
 * Найдена в источнике — пишем; не найдена и файл уже есть — оставляем как есть; нет ни того, ни другого — заглушка.
 * @returns {'write'|'keep'|'stub'}
 */
export function decideIconAction({ found, exists }) {
  if (found) return 'write';
  return exists ? 'keep' : 'stub';
}

/** Атомарная запись: временный файл рядом, затем rename; при ошибке временный файл удаляется. */
export async function writeFileAtomic(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tmp, data);
    await fs.rename(tmp, file);
  } catch (e) {
    await fs.rm(tmp, { force: true });
    throw e;
  }
}

/** Применяет решение к файлу иконки. @returns {Promise<'write'|'keep'|'stub'>} */
export async function saveIcon(dir, slug, { svg, stub }) {
  const file = path.join(dir, `${slug}.svg`);
  const exists = await fs.access(file).then(() => true, () => false);
  const action = decideIconAction({ found: !!svg, exists });
  if (action === 'keep') return action;
  const body = action === 'write' ? svg : stub;
  await writeFileAtomic(file, body.endsWith('\n') ? body : `${body}\n`);
  return action;
}

// Необязательные аргументы — slug'и: `node scripts/fetch-icons.mjs pipedrive zendesk` обновляет только их
async function main(only = []) {
  const catalog = loadCatalog(path.join(root, 'providers.yaml'));
  await fs.mkdir(iconsDir, { recursive: true });
  for (const p of catalog.list()) {
    if (only.length && !only.includes(p.slug)) continue;
    let svg = null;
    let source = null;
    let stub = stubSvg(p.name);
    if (p.slug === 'other') {
      svg = stubSvg(p.name, { plus: true });
      source = 'заглушка (+)';
    } else {
      ({ svg, source } = await findIcon(p));
    }
    const action = await saveIcon(iconsDir, p.slug, { svg, stub });
    console.log(`${p.slug}\t${action === 'write' ? source : action === 'keep' ? 'источники недоступны, файл оставлен как есть' : 'заглушка (буква)'}`);
  }
}

// Запуск только как скрипт, не при импорте в тестах.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
