// Тесты i18n: одинаковые ключи в словарях, подстановка параметров, неизвестный ключ.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createI18n, initI18n, t, LANGS } from '../src/i18n.js';
import en from '../src/i18n/en.js';
import ru from '../src/i18n/ru.js';
import * as V from '../src/web/views/index.js';

test('LANGS: en и ru', () => {
  assert.deepEqual(LANGS, ['en', 'ru']);
});

test('словари en и ru содержат одинаковый набор ключей', () => {
  const a = Object.keys(en).sort();
  const b = Object.keys(ru).sort();
  assert.deepEqual(a.filter((k) => !b.includes(k)), [], 'есть в en, нет в ru');
  assert.deepEqual(b.filter((k) => !a.includes(k)), [], 'есть в ru, нет в en');
});

test('в словарях нет пустых значений, а {параметры} совпадают в en и ru', () => {
  const names = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  for (const k of Object.keys(en)) {
    assert.ok(en[k].length > 0 && ru[k].length > 0, `${k}: пустое значение`);
    assert.equal(names(en[k]), names(ru[k]), `${k}: разные параметры`);
  }
});

test('t подставляет params', () => {
  const i = createI18n('en');
  assert.equal(i.t('keys.pending', { n: 3 }), 'Pending (3)');
  assert.equal(createI18n('ru').t('keys.pending', { n: 3 }), 'Ожидают (3)');
  assert.equal(i.t('setup.step', { n: 2 }), 'Step 2 of 3');
});

test('t: неизвестный ключ возвращает ключ и предупреждает один раз', () => {
  const calls = [];
  const orig = console.warn;
  console.warn = (...a) => calls.push(a.join(' '));
  try {
    const i = createI18n('en');
    assert.equal(i.t('no.such.key'), 'no.such.key');
    assert.equal(i.t('no.such.key'), 'no.such.key');
    assert.equal(createI18n('ru').t('no.such.key'), 'no.such.key');
  } finally {
    console.warn = orig;
  }
  assert.equal(calls.length, 1);
});

test('неизвестный язык — английский', () => {
  assert.equal(createI18n('de').lang, 'en');
  assert.equal(createI18n().lang, 'en');
});

test('initI18n переключает глобальный t и форматы дат/длительностей', () => {
  initI18n('en');
  assert.equal(t('nav.keys'), 'Keys');
  assert.equal(V.fmtDuration(5400), '1 h 30 min');
  assert.equal(V.fmtDate(0), '1 Jan 1970, 00:00');
  assert.equal(V.plural(1, ['call', 'calls', 'calls']), 'call');
  assert.equal(V.plural(2, ['call', 'calls', 'calls']), 'calls');
  assert.equal(V.plural(21, ['call', 'calls', 'calls']), 'calls');
  assert.match(V.login({}), /<html lang="en">/);
  initI18n('ru');
  assert.equal(t('nav.keys'), 'Ключи');
  assert.equal(V.fmtDuration(5400), '1 ч 30 мин');
  assert.equal(V.fmtDate(0), '1 янв. 1970, 00:00');
  assert.match(V.login({}), /<html lang="ru">/);
  initI18n('en');
});

test('все ключи, которые использует код, есть в словаре', async () => {
  const { readFileSync, readdirSync } = await import('node:fs');
  const { join } = await import('node:path');
  const files = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) { if (!/mcp|i18n$/.test(p)) walk(p); } else if (p.endsWith('.js')) files.push(p); } };
  const { fileURLToPath } = await import('node:url');
  walk(fileURLToPath(new URL('../src', import.meta.url)));
  files.push(fileURLToPath(new URL('../bin/gateway.js', import.meta.url)));
  const missing = [];
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/\bth?\('([a-z0-9_.]+)'/g)) if (!(m[1] in en)) missing.push(`${f}: ${m[1]}`);
  }
  assert.deepEqual(missing, []);
});
