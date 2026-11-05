// Управляет экземпляром бота: запуск при старте, перезапуск при смене токена, остановка
import { createBot } from './bot.js';

export function createTgManager({ repo, vault, logger, deps }) {
  let bot = null;
  async function startWith(token) {
    if (bot) { try { await bot.stop(); } catch {} bot = null; }
    const b = createBot({ token, repo, logger, ...deps() });
    await b.getUsername(); // проверка токена
    b.start();
    bot = b;
    return b;
  }
  return {
    current: () => bot,
    // Проверка токена (getMe) без остановки работающего бота и без записи в сейф; бросает при неверном токене
    async check(token) { await createBot({ token, repo, logger, ...deps() }).getUsername(); },
    async init() {
      const token = await vault.get('sys/tg_bot').catch(() => null);
      if (!token) return null;
      try { return await startWith(token); } catch (e) { logger.error({ err: e.message }, 'telegram start'); return null; }
    },
    restart: (token) => startWith(token),
    async stop() { if (bot) { try { await bot.stop(); } catch {} bot = null; } },
  };
}
