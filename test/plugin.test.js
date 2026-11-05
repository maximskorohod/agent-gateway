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

// ---- Пакет 6: плагин Claude Code ----

test('marketplace.json: name, owner и запись плагина с source', () => {
  const mp = json('.claude-plugin/marketplace.json');
  assert.equal(mp.name, 'agentkeygate');
  assert.ok(mp.owner && typeof mp.owner === 'object' && mp.owner.name, 'owner задан');
  assert.equal(mp.plugins[0].name, 'agentkeygate');
  assert.equal(mp.plugins[0].source, './plugins/agentkeygate');
});

test('plugin.json: name, версия из package.json, license, repository, userConfig', () => {
  const pl = json('plugins/agentkeygate/.claude-plugin/plugin.json');
  const version = json('package.json').version;
  assert.equal(pl.name, 'agentkeygate');
  assert.equal(pl.version, version, 'версия плагина равна версии package.json');
  assert.equal(pl.license, 'Apache-2.0');
  assert.match(pl.repository, /github\.com\/maximskorohod\/agentkeygate/);
  assert.ok(pl.userConfig.mcp_url.description.includes('https://your-domain/mcp'), 'описание mcp_url: полный адрес');
  assert.equal(pl.userConfig.agent_token.sensitive, true, 'agent_token sensitive');
});

test('.mcp.json плагина: http-сервер с user_config, без настоящих значений', () => {
  const mcpj = json('plugins/agentkeygate/.mcp.json');
  const srv = mcpj.mcpServers.agentkeygate;
  assert.equal(srv.type, 'http');
  assert.equal(srv.url, '${user_config.mcp_url}');
  assert.equal(srv.headers.Authorization, 'Bearer ${user_config.agent_token}');
  const text = read('plugins/agentkeygate/.mcp.json');
  assert.ok(!/gwa_[A-Za-z0-9_-]{10,}|https:\/\/[a-z0-9.-]+\/mcp/.test(text), 'нет настоящих адресов и токенов');
});

test('README плагина: не короче 40 слов, команды установки', () => {
  const readme = read('plugins/agentkeygate/README.md');
  assert.ok(readme.split(/\s+/).length >= 40, `слов: ${readme.split(/\s+/).length}`);
  assert.ok(readme.includes('claude plugin marketplace add maximskorohod/agentkeygate'));
  assert.ok(readme.includes('claude plugin install agentkeygate@agentkeygate'));
});

test('копия навыка в плагине совпадает побайтно с skills/agentkeygate', () => {
  const same = (a, b) => fs.readFileSync(path.join(root, a)).equals(fs.readFileSync(path.join(root, b)));
  assert.ok(same('skills/agentkeygate/SKILL.md', 'plugins/agentkeygate/skills/agentkeygate/SKILL.md'), 'SKILL.md');
  assert.ok(same('skills/agentkeygate/scripts/gw.sh', 'plugins/agentkeygate/skills/agentkeygate/scripts/gw.sh'), 'gw.sh');
});

// ---- Пакет 7: server.json для реестра MCP (публикацию выполняет заказчик) ----

test('server.json: имя, версия из package.json, описание до 100 символов, repository, актуальная $schema', () => {
  const sj = json('server.json');
  const version = json('package.json').version;
  assert.equal(sj.name, 'io.github.maximskorohod/agentkeygate');
  assert.equal(sj.version, version);
  assert.ok(sj.description.length > 0 && sj.description.length <= 100, `описание ${sj.description.length} символов`);
  assert.match(sj.repository.url, /github\.com\/maximskorohod\/agentkeygate/);
  assert.equal(sj.repository.source, 'github');
  assert.match(sj.$schema, /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/\d{4}-\d{2}-\d{2}\/server\.schema\.json$/);
});

test('server.json: один remote streamable-http с переменной host и секретным заголовком Authorization', () => {
  const sj = json('server.json');
  assert.equal(sj.remotes.length, 1);
  const rem = sj.remotes[0];
  assert.equal(rem.type, 'streamable-http');
  assert.equal(rem.url, 'https://{host}/mcp');
  assert.equal(rem.variables.host.isRequired, true);
  assert.ok(rem.variables.host.description, 'описание переменной host');
  const hdr = rem.headers.find((h) => h.name === 'Authorization');
  assert.ok(hdr, 'заголовок Authorization');
  assert.equal(hdr.isRequired, true);
  assert.equal(hdr.isSecret, true);
  assert.ok(!('value' in hdr) || hdr.value === undefined, 'значения заголовка в файле нет');
});
