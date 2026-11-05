// Пакет 1 ТЗ 1.0.2: setup.sh --demo, --prod-hosts, --print-env и файлы демо-защиты (deploy/*-demo.conf).
// Только локальные запуски bash без root: любые изменения на сервере не выполняются (--print-env выходит раньше).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const hasBash = spawnSync('bash', ['--version']).status === 0;
const cleanup = [];
const tmpFile = (name, content = '') => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gw-setup-')), name);
  cleanup.push(() => { try { fs.rmSync(path.dirname(p), { recursive: true, force: true }); } catch { /* занято */ } });
  if (content) fs.writeFileSync(p, content);
  return p;
};

/** Запуск setup.sh с подменой пути к старому env (GW_SETUP_ENV_FILE); envFile undefined - переменная не ставится. */
const setup = (args, envFile = undefined) => spawnSync('bash', ['scripts/setup.sh', ...args], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, ...(envFile !== undefined ? { GW_SETUP_ENV_FILE: envFile } : {}) },
});

const DEMO_ARGS = ['--domain', 'demo.example.com', '--demo', '--prod-hosts', 'gw.example.com', '--print-env'];

test('bash -n setup.sh', { skip: !hasBash && 'bash не найден' }, () => {
  const r = spawnSync('bash', ['-n', path.join(root, 'scripts/setup.sh')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

test('--print-env демо: код 0 без root, полный env демо, без SSM-строк', { skip: !hasBash && 'bash не найден' }, () => {
  const missing = path.join(os.tmpdir(), 'gw-setup-missing-' + process.pid + '.env');
  const r = setup(DEMO_ARGS, missing);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.split('\n');
  for (const line of [
    'GW_DEMO=1', 'GW_DATA_DIR=/var/lib/agentkeygate-demo', 'GW_VAULT=file', 'GW_PORT=8080',
    'GW_HOST=127.0.0.1', 'GW_PUBLIC_URL=https://demo.example.com', 'GW_PROD_HOSTS=gw.example.com', 'GW_LOG_LEVEL=info',
  ]) assert.ok(lines.includes(line), `нет строки ${line}`);
  assert.ok(!/GW_VAULT_PREFIX|GW_SSM_REGION/.test(r.stdout), 'в демо нет SSM-строк');
  // несколько боевых хостов переносятся как заданы
  const two = setup(['--domain', 'demo.example.com', '--demo', '--prod-hosts', 'a.example.com,b.example.com', '--print-env'], missing);
  assert.equal(two.status, 0);
  assert.ok(two.stdout.split('\n').includes('GW_PROD_HOSTS=a.example.com,b.example.com'));
});

test('отказы до любых изменений: --demo --vault ssm, --demo --init, неверный --prod-hosts, демо без списка хостов', { skip: !hasBash && 'bash не найден' }, () => {
  for (const args of [
    ['--domain', 'demo.example.com', '--demo', '--vault', 'ssm', '--print-env'],
    ['--domain', 'demo.example.com', '--demo', '--init', '--print-env'],
    ['--domain', 'demo.example.com', '--demo', '--prod-hosts', 'bad host;x', '--print-env'],
    ['--domain', 'demo.example.com', '--demo', '--prod-hosts', 'gw.example.com,', '--print-env'],
    ['--domain', 'demo.example.com', '--demo', '--print-env'],
  ]) {
    const r = setup(args);
    assert.notEqual(r.status, 0, args.join(' '));
    assert.equal(r.stdout, '', args.join(' '));
  }
});

test('повторный запуск без флага: демо сохраняется, GW_PROD_HOSTS и чужие GW_* переносятся (I-03)', { skip: !hasBash && 'bash не найден' }, () => {
  const old = tmpFile('demo.env', 'GW_DEMO=1\nGW_PROD_HOSTS=gw.example.com\nGW_LANG=ru\nGW_DATA_DIR=/x\nGW_TZ=Europe/Berlin\nGW_WAITLIST_URL=https://example.org/w\n');
  const r = setup(['--domain', 'demo.example.com', '--print-env'], old);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.split('\n');
  for (const line of [
    'GW_DEMO=1', 'GW_DATA_DIR=/var/lib/agentkeygate-demo', 'GW_PROD_HOSTS=gw.example.com',
    'GW_LANG=ru', 'GW_TZ=Europe/Berlin', 'GW_WAITLIST_URL=https://example.org/w',
  ]) assert.ok(lines.includes(line), `нет строки ${line}`);
  // GW_DATA_DIR скриптом управляется: старое значение не переносится
  assert.ok(!lines.includes('GW_DATA_DIR=/x'));
});

test('обычная установка: без строк демо, управляемые поля новые, чужие GW_* переносятся', { skip: !hasBash && 'bash не найден' }, () => {
  const old = tmpFile('plain.env', 'GW_TZ=Asia/Tbilisi\nGW_VAULT=ssm\nGW_PUBLIC_URL=https://old.example.com\n');
  const r = setup(['--domain', 'gw.example.com', '--vault', 'file', '--print-env'], old);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.split('\n');
  assert.ok(!lines.some((l) => l.startsWith('GW_DEMO')), 'без демо нет GW_DEMO');
  for (const line of [
    'GW_TZ=Asia/Tbilisi', 'GW_VAULT=file', 'GW_PUBLIC_URL=https://gw.example.com',
    'GW_VAULT_PREFIX=/gateway', 'GW_SSM_REGION=eu-central-1', 'GW_DATA_DIR=/var/lib/agentkeygate',
  ]) assert.ok(lines.includes(line), `нет строки ${line}`);
  assert.ok(!lines.includes('GW_DATA_DIR=/var/lib/agentkeygate-demo'));
});

test('--repo с логином по-прежнему отклоняется, --print-env не обходит проверку', { skip: !hasBash && 'bash не найден' }, () => {
  const r = setup(['--domain', 'gw.example.com', '--repo', 'https://u:v@example.com/x.git', '--print-env']);
  assert.notEqual(r.status, 0);
  assert.equal(r.stdout, '');
});

test('deploy/gateway-demo.conf: drop-in с изоляцией сети и каталога записи', () => {
  const dropIn = fs.readFileSync(path.join(root, 'deploy/gateway-demo.conf'), 'utf8');
  assert.match(dropIn, /^\[Service\]$/m);
  assert.match(dropIn, /^IPAddressDeny=any$/m);
  assert.match(dropIn, /^IPAddressAllow=localhost$/m);
  assert.match(dropIn, /^ReadWritePaths=\/var\/lib\/agentkeygate-demo$/m);
});

test('deploy/nftables-demo.conf: таблица agw_demo без flush ruleset', () => {
  const nft = fs.readFileSync(path.join(root, 'deploy/nftables-demo.conf'), 'utf8');
  assert.match(nft, /table inet agw_demo \{/);
  assert.match(nft, /meta skuid gateway oif "lo" accept/);
  assert.match(nft, /meta skuid gateway ct state established,related accept/);
  assert.match(nft, /meta skuid gateway limit rate 6\/minute log prefix "agw-demo-out: "/);
  assert.match(nft, /meta skuid gateway drop/);
  assert.ok(!nft.includes('flush ruleset'), 'файл подключается include-ом: flush в нём стирал бы главный ruleset');
});

test('setup.sh: ставит демо-файлы и include, снимает demo.conf и cron вне демо, не запускает мастер', () => {
  const setupText = fs.readFileSync(path.join(root, 'scripts/setup.sh'), 'utf8');
  assert.ok(setupText.includes('gateway.service.d'), 'каталог drop-in');
  assert.ok(setupText.includes('deploy/gateway-demo.conf'), 'установка drop-in');
  assert.ok(setupText.includes('rm -f /etc/systemd/system/gateway.service.d/demo.conf'), 'вне демо drop-in снимается');
  assert.ok(setupText.includes('nftables-demo.conf'), 'установка таблицы');
  assert.ok(setupText.includes('include "/etc/nftables-demo.conf"'), 'include в главный конфиг');
  assert.ok(setupText.includes('nft -c'), 'проверка nft -c');
  assert.ok(setupText.includes('rm -f /etc/cron.d/agentkeygate'), 'в демо cron бэкапа удаляется');
  assert.match(setupText, /Backups: none in demo mode/, 'в демо cron бэкапа не ставится');
  assert.match(setupText, /Demo mode: gateway init is not run/, 'мастер в демо не запускается');
});
