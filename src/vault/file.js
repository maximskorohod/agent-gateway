// Файловый сейф для dev и тестов: JSON, зашифрованный AES-256-GCM мастер-ключом из dataDir/master.key (0600).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function createFileVault(config) {
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  let master;
  if (fs.existsSync(config.masterKeyFile)) {
    master = Buffer.from(fs.readFileSync(config.masterKeyFile, 'utf8').trim(), 'hex');
  } else {
    master = crypto.randomBytes(32);
    fs.writeFileSync(config.masterKeyFile, master.toString('hex') + '\n', { mode: 0o600 });
  }
  if (master.length !== 32) throw new Error('master.key is corrupted');

  const load = () => {
    if (!fs.existsSync(config.vaultFile)) return {};
    const { iv, tag, data } = JSON.parse(fs.readFileSync(config.vaultFile, 'utf8'));
    const d = crypto.createDecipheriv('aes-256-gcm', master, Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8'));
  };
  const save = (obj) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', master, iv);
    const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
    const tmp = config.vaultFile + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') }), { mode: 0o600 });
    fs.renameSync(tmp, config.vaultFile);
  };

  return {
    async get(name) { return load()[name] ?? null; },
    async put(name, value) { const o = load(); o[name] = value; save(o); },
    async del(name) { const o = load(); delete o[name]; save(o); },
    // Только имена, без значений: проверка изоляции демо (contracts/rest-demo-notify.md)
    async names() { return Object.keys(load()); },
  };
}
