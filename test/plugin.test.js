// ТЗ 1.0.2, пакеты 5-7: таблица агентов в README, навык agentkeygate, плагин Claude Code и server.json.
// Статические проверки без сети и без публикаций.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const json = (rel) => JSON.parse(read(rel));

// ---- Пакет 5: README и навык ----

test('README: таблица агентов с колонкой Checked live', () => {
  const readme = read('README.md');
  for (const a of ['Claude Code', 'Codex', 'Cursor', 'VS Code', 'Gemini', 'Hermes', 'OpenClaw', 'Claude Desktop', 'ChatGPT']) {
    assert.ok(readme.includes(a), a);
  }
  assert.match(readme, /Checked live/, 'есть колонка Checked live');
  // у всех агентов значение no
  const rows = readme.split('\n').filter((l) => /^\| [A-Z]/.test(l) && /\|\s*no\s*\|/.test(l));
  assert.ok(rows.length >= 9, `строк таблицы с no: ${rows.length}`);
});

test('README: ограничения Claude Desktop (mcp-remote) и ChatGPT (OAuth)', () => {
  const readme = read('README.md');
  assert.match(readme, /mcp-remote/, 'Claude Desktop через mcp-remote');
  assert.match(readme, /ChatGPT[^\n]*OAuth|OAuth[^\n]*ChatGPT/, 'ChatGPT: MCP требует OAuth');
});

test('SKILL.md: имя совпадает с папкой, описание не длиннее 1024 символов', () => {
  const skill = read('skills/agentkeygate/SKILL.md');
  assert.match(skill, /^name: agentkeygate$/m);
  const desc = skill.match(/^description:\s*(.+)$/m)?.[1] ?? '';
  assert.ok(desc.length > 0 && desc.length <= 1024, `описание ${desc.length} символов`);
  assert.ok(fs.existsSync(path.join(root, 'skills/agentkeygate/scripts/gw.sh')), 'хелпер gw.sh на месте');
});

test('skills/agentkeygate/README.md: пути установки навыка и переменные окружения', () => {
  const sr = read('skills/agentkeygate/README.md');
  for (const p of ['~/.claude/skills', '~/.agents/skills', '~/.cursor/skills', '~/.copilot/skills', '~/.gemini/skills', '~/.hermes/skills']) {
    assert.ok(sr.includes(p), p);
  }
  assert.ok(sr.includes('AGENTKEYGATE_URL') && sr.includes('AGENTKEYGATE_TOKEN'), 'переменные окружения');
});
