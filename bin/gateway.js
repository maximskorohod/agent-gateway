#!/usr/bin/env node
// CLI: start | init | restore <file> | audit rotate [--days N] [--out <dir>] | key list
// Логика команд в src/cli.js; здесь только разбор аргументов и сборка зависимостей.
import fs from 'node:fs';
import { config } from '../src/config.js';
import { openDb } from '../src/db/index.js';
import { createRepo } from '../src/db/repo.js';
import { createVault } from '../src/vault/index.js';
import { runInit, runRestore, runAuditRotate } from '../src/cli.js';
import { initI18n, t } from '../src/i18n.js';

initI18n(config.lang);

const [cmd, ...args] = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

async function main() {
  if (cmd === 'start') {
    // Демо (GW_DEMO=1): вторая линия защиты от исходящих соединений ставится до всего остального; отказ изоляции в buildApp = выход с кодом 1 до listen
    if (config.demo) (await import('../src/demo/guard.js')).installNetworkGuard();
    const { buildApp } = await import('../src/app.js');
    const app = await buildApp();
    await app.start();
    const stop = () => app.stop().then(() => process.exit(0), () => process.exit(1));
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
    return;
  }
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  if (cmd === 'restore') {
    await runRestore({ config, vault: createVault(config), file: args[0], log: console.log });
    return;
  }
  if (cmd === 'init' || cmd === 'audit' || (cmd === 'key' && args[0] === 'list')) {
    const db = openDb(config.dbPath);
    const repo = createRepo(db);
    try {
      if (cmd === 'init') runInit({ repo, config, log: console.log });
      else if (cmd === 'audit' && args[0] === 'rotate') {
        const d = opt('--days');
        runAuditRotate({ repo, config, days: d === undefined ? 90 : Number(d), outDir: opt('--out'), log: console.log, warn: console.error });
      } else if (cmd === 'key') {
        for (const c of repo.listCredentials()) console.log(`${c.id}  ${c.provider.padEnd(10)} ${c.label.padEnd(24)} ${c.mode.padEnd(6)} ····${c.last4}`);
      } else { console.log(t('cli.usage')); process.exitCode = 2; }
    } finally { db.close(); }
    return;
  }
  console.log(t('cli.usage'));
  process.exit(2);
}
main().catch((e) => { console.error(e.message); process.exit(e.exitCode || 1); });
