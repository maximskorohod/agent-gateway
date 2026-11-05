// Демо-режим: сид и сброс раз в час (контракт rest-demo-notify.md, «Данные и сброс раз в час»).
import crypto from 'node:crypto';
import { DEMO_HOST, DEMO_KEY_HEADER } from './mock.js';

export const DEMO_CREDENTIAL_ID = 'demo';
export const DEMO_AGENT_ID = 'demo-agent';
/** Публичный демо-ключ: общий для всех посетителей, ничего не открывает (мок в процессе). Формат — keyPattern провайдера demo. */
export const DEMO_KEY = 'demo-public01';
/** Формат ключа посетителя: совпадает с keyPattern провайдера demo в providers.yaml. */
export const DEMO_KEY_PATTERN = /^demo-[a-z0-9]{8,32}$/;
export const DEMO_CHECK_SEC = 30;

/**
 * @param {{ repo:object, vault:object, cfg:{demoResetSec:number}, logger:object, onReset?:()=>Promise<void>|void }} deps
 *   onReset вызывается в начале сброса при поднятом флаге resetting (buildApp закрывает им MCP-сессии)
 * @returns {{ runOnce:(opts?:{hold?:Promise<unknown>})=>Promise<void>, loop:()=>NodeJS.Timeout, readonly resetting:boolean }}
 *   hold — только тесты: сброс ждёт этот промис при поднятом флаге (проверка 503 во время сброса)
 */
export function createDemoReset({ repo, vault, cfg, logger, onReset }) {
  let resetting = false;
  let generation = 0;
  let running = null;

  /** Владелец без пароля, ключ cred/demo, агент demo-agent. Синхронно, без await (после demoWipe). */
  function seedDb() {
    repo.setSetupDone();
    repo.createCredential({
      id: DEMO_CREDENTIAL_ID, provider: 'demo', label: 'Demo CRM', kind: 'static', host: DEMO_HOST,
      injection: { type: 'header', name: DEMO_KEY_HEADER }, vault_param: `cred/${DEMO_CREDENTIAL_ID}`,
      mode: 'ask', approval: 'web_button', max_ttl: 3600, max_calls: 100, max_parallel: 2, last4: DEMO_KEY.slice(-4),
    });
    // токен демо-агента нигде не хранится: им пользуется только «Simulate agent request»
    const tokenHash = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');
    repo.createAgent({ id: DEMO_AGENT_ID, name: DEMO_AGENT_ID, token_hash: tokenHash, enabled: 1, all_credentials: 1 });
  }

  async function reset(hold) {
    resetting = true;
    try {
      await onReset?.();
      repo.revokeAllGrants();
      if (hold) await hold;
      // сейф: все cred/* заменяются одним демо-ключом, sys/* (подпись, ключ 2FA) остаются
      const names = typeof vault.names === 'function' ? await vault.names() : [];
      for (const n of names) if (n.startsWith('cred/')) await vault.del(n);
      await vault.put(`cred/${DEMO_CREDENTIAL_ID}`, DEMO_KEY);
      repo.demoWipe();
      seedDb();
      repo.demoMarkReset();
      generation += 1;
      logger.info({}, 'demo reset');
    } finally {
      resetting = false;
    }
  }

  function runOnce({ hold } = {}) {
    if (!running) running = reset(hold).finally(() => { running = null; });
    return running;
  }

  return {
    runOnce,
    /** Проверка каждые 30 с: сброс, когда с прошлого прошло demoResetSec (время считает SQLite). Начальный сброс — на старте buildApp. */
    loop() {
      const timer = setInterval(() => {
        (async () => {
          const age = repo.demoResetAge();
          if (age === null || age >= cfg.demoResetSec) await runOnce();
        })().catch((e) => logger.error({ err: e?.message }, 'demo reset failed'));
      }, DEMO_CHECK_SEC * 1000);
      timer.unref();
      return timer;
    },
    get resetting() { return resetting; },
    /** Номер сброса: растёт после каждого завершённого сброса (guard по нему обнуляет счётчики создания по IP). */
    get generation() { return generation; },
  };
}
