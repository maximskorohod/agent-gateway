// Статические проверки серверных файлов (Н-9, Н-10, Н-11): без сети, без сервера.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

const hasBash = spawnSync('bash', ['--version']).status === 0;

for (const script of ['scripts/setup.sh', 'scripts/backup.sh']) {
  test(`bash -n ${script}`, { skip: !hasBash && 'bash не найден' }, () => {
    const r = spawnSync('bash', ['-n', path.join(root, script)], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  });
}

test('gateway.service: харденинг systemd (Н-9)', () => {
  const unit = read('deploy/gateway.service');
  // Строки без комментариев: закомментированная директива не считается.
  const active = unit.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  for (const needle of ['CapabilityBoundingSet=\n', 'ProtectProc=invisible', 'MemoryMax=', 'MemorySwapMax=0', 'TasksMax=', 'NoNewPrivileges=yes']) {
    assert.ok(active.includes(needle), `нет директивы ${needle.trim()}`);
  }
  assert.match(active, /MemoryDenyWriteExecute=no/);
});

test('setup.sh: unattended-upgrades обновляет Caddy (Cloudsmith) и Node (NodeSource), отдельным файлом (I-04)', () => {
  const setup = read('scripts/setup.sh');
  assert.ok(setup.includes('site=dl.cloudsmith.io'), 'источник Caddy');
  assert.ok(setup.includes('site=deb.nodesource.com'), 'источник Node');
  assert.match(setup, /Unattended-Upgrade::Origins-Pattern \{\n\s*"site=dl\.cloudsmith\.io";\n\s*"site=deb\.nodesource\.com";\n\};/);
  // отдельный файл в /etc/apt/apt.conf.d/, а не внутри 20auto-upgrades
  assert.ok(setup.includes("cat > /etc/apt/apt.conf.d/51agentkeygate-origins <<'APT'"), 'отдельный heredoc-файл');
  const auto = setup.indexOf('20auto-upgrades');
  const origins = setup.indexOf('51agentkeygate-origins');
  assert.ok(auto >= 0 && origins > auto, 'файл origins пишется после 20auto-upgrades');
});

test('setup.sh: npm без скриптов и без глобального safe.directory (Н-10)', () => {
  const setup = read('scripts/setup.sh');
  assert.ok(setup.includes('--ignore-scripts'));
  assert.ok(setup.includes('npm rebuild argon2 better-sqlite3'));
  assert.ok(!setup.includes('git config --global --add safe.directory'));
});

test('nftables.conf: IMDS 169.254.169.254 открыт только с --vault ssm (у других облаков, например OpenStack, на этом адресе свои метаданные)', () => {
  const lines = read('deploy/nftables.conf').split('\n').filter((l) => l.includes('169.254.169.254') && /accept/.test(l));
  assert.ok(lines.length === 1 && /#ssm\s*$/.test(lines[0]), 'единственное правило IMDS помечено #ssm');
  const setup = read('scripts/setup.sh');
  assert.match(setup, /sed -e '\/#ssm\$\/d'/, 'без ssm строка удаляется');
  assert.match(setup, /if \[\[ "\$VAULT" == "ssm" \]\]; then\n\s*render_cf "\$APP_DIR\/deploy\/nftables.conf"/);
});

test('setup.sh: перед pull возвращает backup.sh к версии из git (свой chmod не блокирует обновление, staging)', () => {
  const lines = read('scripts/setup.sh').split('\n');
  const fetch = lines.findIndex((l) => /fetch --quiet --tags origin "\$BRANCH"/.test(l));
  const co = lines.findIndex((l) => /checkout --quiet -- scripts\/backup\.sh/.test(l));
  const pull = lines.findIndex((l) => /pull --quiet --ff-only/.test(l));
  assert.ok(fetch >= 0 && co > fetch && co < pull, 'checkout -- scripts/backup.sh между fetch и pull');
});

test('установка с тега: версия, тег в setup.sh и sha256 в документах совпадают (I-01)', () => {
  const version = JSON.parse(read('package.json')).version;
  const setup = read('scripts/setup.sh');
  assert.match(setup, new RegExp(`^BRANCH="v${version.replaceAll('.', '\\.')}"$`, 'm'), 'тег по умолчанию');
  const sha = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'scripts/setup.sh'))).digest('hex');
  for (const doc of ['README.md', 'docs/DEPLOY.md', 'docs/ru/DEPLOY.md']) {
    const text = read(doc);
    assert.ok(text.includes(`agentkeygate/v${version}/scripts/setup.sh`), `${doc}: ссылка на тег`);
    assert.ok(text.includes(sha), `${doc}: sha256 скрипта`);
    assert.ok(!text.includes('agentkeygate/main/scripts/setup.sh'), `${doc}: установка с main`);
  }
});

test('setup.sh: логин и токен в --repo отклоняются, тег ставится без pull (I-06, I-01)', () => {
  const setup = read('scripts/setup.sh');
  assert.ok(setup.includes('^https://[^/]*@'), 'проверка логина в адресе');
  const lines = setup.split('\n');
  const tag = lines.findIndex((l) => l.includes('show-ref --verify --quiet "refs/tags/'));
  const pull = lines.findIndex((l) => /\bpull --quiet --ff-only\b/.test(l));
  assert.ok(tag >= 0 && pull > tag, 'проверка тега до pull');
});

test('backup.sh: симлинки в каталоге данных не читаются от root (I-10)', () => {
  const backup = read('scripts/backup.sh');
  assert.ok(backup.includes('symbolic link in the data directory'));
  assert.ok(backup.includes('symbolic link instead of the vault file'));
  assert.ok(backup.includes('cp -P "${DATA_DIR}/vault.json"'));
  assert.ok(backup.includes('chown --reference="$DB"'));
});

test('setup.sh: каталог сборки открыт пользователю gateway на вход (staging: mktemp -d даёт 0700)', () => {
  const lines = read('scripts/setup.sh').split('\n');
  const mk = lines.findIndex((l) => /build_dir="\$\(mktemp -d /.test(l));
  const ch = lines.findIndex((l) => /^\s*chmod 0755 "\$build_dir"\s*$/.test(l));
  const build = lines.findIndex((l) => /as_builder npm (ci|install)/.test(l));
  assert.ok(mk >= 0 && ch > mk && ch < build, 'chmod 0755 "$build_dir" сразу после mktemp и до npm');
});

test('Caddyfile: Authenticated Origin Pulls только в строках #cf (Н-11)', () => {
  const lines = read('deploy/Caddyfile').split('\n');
  const aop = lines.filter((l) => /client_auth|trust_pool|require_and_verify/.test(l) && !l.trim().startsWith('# '));
  assert.ok(aop.length >= 3, 'нет настроек client_auth');
  for (const l of aop) assert.match(l, /^\s*#cf /, `строка AOP без метки #cf: ${l}`);
});

test('setup.sh: отпечаток CA Cloudflare Origin Pull вписан, не заглушка (staging 04.11)', () => {
  const m = read('scripts/setup.sh').match(/^CF_CA_SHA256="([^"]*)"$/m);
  assert.ok(m, 'нет константы CF_CA_SHA256');
  assert.equal(m[1], 'c14fed0ce5210db0719fea11d1f10b33750dc17d609aeaf47c75e9eff0d7b843');
});

test('Caddyfile и Caddyfile.docker: пути /l/<токен> и /setup/<код> не попадают в access-log (ревью 9.1)', () => {
  for (const f of ['deploy/Caddyfile', 'Caddyfile.docker']) {
    const active = read(f).split('\n').filter((l) => !l.trim().startsWith('#'));
    const matcher = active.find((l) => /^\s*@\w+\s+path\b/.test(l) && l.includes('/l/*') && l.includes('/setup/*'));
    assert.ok(matcher, `${f}: нет матчера путей /l/* и /setup/*`);
    const name = matcher.trim().split(/\s+/)[0];
    assert.ok(active.some((l) => l.trim() === `log_skip ${name}`), `${f}: нет log_skip для ${name}`);
  }
});

test('docker-compose.yml: GW_TRUST_PROXY с подсетью Docker; config и Fastify принимают CIDR (ревью M3)', async () => {
  const compose = read('docker-compose.yml').split('\n').filter((l) => !l.trim().startsWith('#'));
  const line = compose.find((l) => /^\s*GW_TRUST_PROXY:\s*/.test(l));
  assert.ok(line, 'в environment сервиса gateway нет GW_TRUST_PROXY');
  const cidr = line.split(':').slice(1).join(':').trim();
  assert.equal(cidr, '172.16.0.0/12');
  // config.js разбирает значение в список
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./src/config.js').then((m) => console.log(JSON.stringify(m.config.trustProxy)))"], { cwd: root, encoding: 'utf8', env: { ...process.env, GW_TRUST_PROXY: cidr } });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout.trim()), [cidr]);
  // Fastify доверяет X-Forwarded-For от адреса из подсети и не доверяет чужому
  const { default: Fastify } = await import('fastify');
  const f = Fastify({ trustProxy: [cidr] });
  f.get('/ip', async (req) => req.ip);
  const viaCaddy = await f.inject({ url: '/ip', remoteAddress: '172.18.0.2', headers: { 'x-forwarded-for': '203.0.113.9' } });
  assert.equal(viaCaddy.body, '203.0.113.9');
  const direct = await f.inject({ url: '/ip', remoteAddress: '198.51.100.5', headers: { 'x-forwarded-for': '203.0.113.9' } });
  assert.equal(direct.body, '198.51.100.5');
  await f.close();
});

test('nftables.conf: исходящие SMTP 587 и 465 разрешены пользователю gateway до финального drop (ревью 9.1)', () => {
  const lines = read('deploy/nftables.conf').split('\n').filter((l) => !l.trim().startsWith('#'));
  const smtp = lines.findIndex((l) => /meta skuid gateway tcp dport \{ *465, *587 *\} accept/.test(l) || /meta skuid gateway tcp dport \{ *587, *465 *\} accept/.test(l));
  const drop = lines.findIndex((l) => /^\s*meta skuid gateway drop\s*$/.test(l));
  assert.ok(smtp >= 0, 'нет правила для 587/465');
  assert.ok(drop > smtp, 'правило SMTP должно стоять до финального drop');
  assert.ok(!lines.some((l) => /tcp dport \{?[^}]*\b25\b/.test(l) && /accept/.test(l)), 'порт 25 не открывается');
});
