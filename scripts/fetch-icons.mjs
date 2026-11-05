// Downloads provider icons to assets/icons/<slug>.svg (spec section 4).
// Order: Simple Icons from jsDelivr (pinned version, brand color from data/simple-icons.json)
// -> cdn.simpleicons.org -> the service's favicon.svg -> SVG placeholder.
// cdn.simpleicons.org answers 403 to AWS addresses (Cloudflare check), so it is not first.
// Run: node scripts/fetch-icons.mjs
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalog } from '../src/catalog.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const iconsDir = path.join(root, 'assets', 'icons');
const MAX_BYTES = 50 * 1024;        // final size after sanitizing
const MAX_RAW_BYTES = 1024 * 1024;  // memory guard while downloading
const TIMEOUT_MS = 10_000;

// Extra Simple Icons names that match neither the slug nor the name.
const SIMPLE_ICON_ALIASES = {
  mistral: ['mistralai'],
  gemini: ['googlegemini'],
  // Simple Icons names match the slug; listed explicitly so as not to rely on name normalization.
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
// Site with a favicon.svg, if the service has no icon in Simple Icons and its API host serves none.
const FAVICON_HOSTS = { groq: 'groq.com', bitrix24: 'www.bitrix24.ru' };
const SIMPLE_ICONS = 'https://cdn.jsdelivr.net/npm/simple-icons@16.36.0';

let brandHex = null; // Simple Icons slug -> brand color
async function loadBrandHex() {
  if (brandHex) return brandHex;
  brandHex = new Map();
  try {
    const data = JSON.parse((await fetchText(`${SIMPLE_ICONS}/data/simple-icons.json`)) ?? '[]');
    for (const i of data) if (i.slug && /^[0-9A-Fa-f]{6}$/.test(i.hex)) brandHex.set(i.slug, i.hex);
  } catch { /* no color: the icon will be black */ }
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
 * SVG sanitizing: scripts, on* attributes, external href, foreignObject.
 * @returns {string|null} sanitized SVG, or null if it is not an SVG or fails the checks
 */
export function sanitizeSvg(raw) {
  // Strip the XML declaration and leading comments.
  let s = raw.replace(/^﻿/, '').trim();
  s = s.replace(/^(?:<\?xml[^>]*\?>\s*|<!--[\s\S]*?-->\s*)+/i, '');
  if (!s.startsWith('<svg')) return null;
  // An icon needs no DOCTYPE or ENTITY, and they open the door to XXE.
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

/** SVG placeholder: a grey circle with a letter or a "+" sign. */
function stubSvg(name, { plus = false } = {}) {
  const body = plus
    ? '<path d="M32 18v28M18 32h28" stroke="#ffffff" stroke-width="6" stroke-linecap="round"/>'
    : `<text x="32" y="32" dy=".35em" font-family="Arial, sans-serif" font-size="32" font-weight="600" text-anchor="middle" fill="#ffffff">${escapeXml([...name][0].toUpperCase())}</text>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#6b7280"/>${body}</svg>\n`;
}

/** Looks for the provider icon: Simple Icons first, then the host favicon. */
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
  // favicon.ico is skipped on purpose: it is not an SVG.
  const hosts = [...new Set([FAVICON_HOSTS[p.slug], p.host !== 'owner' ? p.host : null].filter(Boolean))];
  for (const h of hosts) {
    const svg = sanitizeSvg((await fetchText(`https://${h}/favicon.svg`)) ?? '');
    if (svg) return { svg, source: `favicon ${h}` };
  }
  return { svg: null, source: null };
}

/**
 * What to do with the provider icon (no network, tested separately).
 * Found in a source: write it; not found and the file already exists: keep it as is; neither: placeholder.
 * @returns {'write'|'keep'|'stub'}
 */
export function decideIconAction({ found, exists }) {
  if (found) return 'write';
  return exists ? 'keep' : 'stub';
}

/** Atomic write: a temporary file next to the target, then rename; on error the temporary file is removed. */
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

/** Applies the decision to the icon file. @returns {Promise<'write'|'keep'|'stub'>} */
export async function saveIcon(dir, slug, { svg, stub }) {
  const file = path.join(dir, `${slug}.svg`);
  const exists = await fs.access(file).then(() => true, () => false);
  const action = decideIconAction({ found: !!svg, exists });
  if (action === 'keep') return action;
  const body = action === 'write' ? svg : stub;
  await writeFileAtomic(file, body.endsWith('\n') ? body : `${body}\n`);
  return action;
}

// Optional arguments are slugs: `node scripts/fetch-icons.mjs pipedrive zendesk` updates only those
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
      source = 'placeholder (+)';
    } else {
      ({ svg, source } = await findIcon(p));
    }
    const action = await saveIcon(iconsDir, p.slug, { svg, stub });
    console.log(`${p.slug}\t${action === 'write' ? source : action === 'keep' ? 'sources unavailable, file kept as is' : 'placeholder (letter)'}`);
  }
}

// Runs only as a script, not when imported in tests.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
