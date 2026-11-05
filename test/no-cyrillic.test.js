// Регрессия 4.9: в src/ (кроме src/i18n/) и bin/ нет кириллицы внутри строковых литералов.
// Логи и внутренние ошибки английские; текст для владельца идёт только через t().
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CYR = /[а-яёА-ЯЁ]/;
// Исключений нет: html.js берёт формы множественного числа из словарей.
const ALLOW = new Set();

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (p === path.join(root, 'src', 'i18n')) continue;
      walk(p, out);
    } else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

// Находит строковые литералы с кириллицей. Комментарии пропускаются, регэкспы обходятся эвристикой,
// выражения внутри ${...} шаблонов сканируются рекурсивно как обычный код.
function findCyrillicStrings(src) {
  const found = [];
  const n = src.length;
  let line = 1;

  // сканирует код с позиции i; если inExpr, останавливается на парной закрывающей скобке
  function scanCode(i, inExpr) {
    let depth = 0;
    let prev = '';
    while (i < n) {
      const c = src[i];
      if (c === '\n') { line++; i++; continue; }
      if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
      if (c === '/' && src[i + 1] === '*') {
        i += 2;
        while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') line++; i++; }
        i += 2;
        continue;
      }
      if (c === '"' || c === "'") {
        const start = line;
        let j = i + 1;
        let body = '';
        while (j < n && src[j] !== c && src[j] !== '\n') {
          if (src[j] === '\\') { body += src[j + 1] ?? ''; j += 2; continue; }
          body += src[j];
          j++;
        }
        if (CYR.test(body)) found.push({ line: start, text: body.slice(0, 80) });
        i = j + 1;
        prev = c;
        continue;
      }
      if (c === '`') {
        i = scanTemplate(i + 1);
        prev = '`';
        continue;
      }
      if (inExpr) {
        if (c === '{') depth++;
        else if (c === '}') {
          if (depth === 0) return i + 1;
          depth--;
        }
      }
      if (c === '/' && (prev === '' || '(,=:[!&|?{};+-*%<>~^'.includes(prev))) {
        let j = i + 1;
        let cls = false;
        while (j < n && src[j] !== '\n') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '[') cls = true;
          else if (src[j] === ']') cls = false;
          else if (src[j] === '/' && !cls) break;
          j++;
        }
        i = j + 1;
        prev = '/';
        continue;
      }
      if (!/\s/.test(c)) prev = c;
      i++;
    }
    return i;
  }

  function scanTemplate(i) {
    const start = line;
    let body = '';
    while (i < n && src[i] !== '`') {
      if (src[i] === '\\') { body += src[i + 1] ?? ''; i += 2; continue; }
      if (src[i] === '$' && src[i + 1] === '{') { i = scanCode(i + 2, true); continue; }
      if (src[i] === '\n') line++;
      body += src[i];
      i++;
    }
    if (CYR.test(body)) found.push({ line: start, text: body.slice(0, 80) });
    return i + 1;
  }

  scanCode(0, false);
  return found;
}

test('кириллица в строковых литералах src/ и bin/ запрещена (вне src/i18n)', () => {
  const files = [...walk(path.join(root, 'src')), ...walk(path.join(root, 'bin'))];
  const bad = [];
  for (const f of files) {
    const rel = path.relative(root, f).replace(/\\/g, '/');
    if (ALLOW.has(rel)) continue;
    for (const h of findCyrillicStrings(fs.readFileSync(f, 'utf8'))) bad.push(`${rel}:${h.line} ${h.text}`);
  }
  assert.deepEqual(bad, []);
});

test('сканер видит литерал, пропускает комментарии и регэкспы', () => {
  const src = "// привет\n/* мир */\nconst a = 'ok'; const r = /[а-я'\"]/; const b = \"да\"; const t = `x ${f('ok')} y`;\n";
  const f = findCyrillicStrings(src);
  assert.equal(f.length, 1);
  assert.equal(f[0].line, 3);
});
