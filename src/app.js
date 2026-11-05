// Сборка приложения (ТЗ §2): один процесс, один писатель в базу
import crypto from 'node:crypto';
import fs from 'node:fs';
import Fastify from 'fastify';
import { config, parseWaitlistUrl } from './config.js';
import { createLogger, maskUrl } from './logger.js';
import { openDb } from './db/index.js';
import { createRepo } from './db/repo.js';
import { loadCatalog } from './catalog.js';
import { migrateCatalog } from './db/migrate-catalog.js';
import { createVault } from './vault/index.js';
import { createGrantService, loadOrCreateSigningKey } from './core/grants.js';
import { createRequestService } from './core/requests.js';
import { createProxy } from './core/proxy.js';
import { filterLine } from './core/filter.js';
import { createAccess } from './core/access.js';
import { createLimiter } from './core/ratelimit.js';
import { createNotifier } from './notify.js';
import { createTgManager } from './tg/manager.js';
import { makeLink } from './auth/links.js';
import { createAuthProvider } from './auth/provider.js';
import { agentApi } from './api/agents.js';
import { mcpPlugin } from './mcp/server.js';
import { registerWeb } from './web/server.js';
import { initI18n, t } from './i18n.js';
import { setTimezone, setWaitlistUrl, setDemoMode } from './web/views/html.js';
import { assertDemoIsolation, assertDemoDataDirFresh, demoRouteGuard, createDemoTransport, createDemoReset } from './demo/guard.js';

export async function buildApp(overrides = {}) {
  const cfg = { ...config, ...overrides };
  initI18n(cfg.lang);
  setTimezone(cfg.tz);
  setDemoMode(cfg.demo);
  // Демо (П-20): тело MCP не больше 64 KiB; каталог данных чистый или помечен .demo-data — проверка до того, как шлюз что-либо создаст
  if (cfg.demo) { cfg.mcpBodyLimit = Math.min(cfg.mcpBodyLimit, 64 * 1024); assertDemoDataDirFresh(cfg.dataDir); }
  fs.mkdirSync(cfg.dataDir, { recursive: true, mode: 0o700 });
  const catalog = loadCatalog(cfg.catalogPath, { demo: cfg.demo });
  const logger = createLogger(cfg.logLevel, catalog.redactHeaders(), cfg.logStream);
  // Лист ожидания: неверный адрес (не https:, длиннее 300) отбрасывается с предупреждением, значение в лог не попадает
  const waitlistUrl = parseWaitlistUrl(cfg.waitlistUrl);
  if (cfg.waitlistUrl && !waitlistUrl) logger.warn('GW_WAITLIST_URL ignored: https URL up to 300 characters is required');
  setWaitlistUrl(waitlistUrl);
  const db = openDb(cfg.dbPath);
  const repo = createRepo(db, { demo: cfg.demo });
  if (!repo.hasGrantsRequestIndex()) logger.error({}, 'grants_request index missing: duplicate grants for one request in the database');
  // Миграция каталога (П-24): bitrix24 с чужим хостом → bitrix24-box; секреты не трогаются. В демо данных владельца нет
  const migrated = cfg.demo ? [] : migrateCatalog(repo, catalog);
  if (migrated.length) logger.info({ n: migrated.length }, 'catalog.migrated: bitrix24 → bitrix24-box');
  // Демо: сейф только file (клиент SSM не создаётся); изоляция проверяется до таймеров и listen
  if (cfg.demo && cfg.vault !== 'file') { db.close(); throw new Error('demo_isolation: vault_not_file'); }
  const vault = createVault(cfg);
  if (cfg.demo) {
    // cfg.env — только тесты (buildApp(overrides)); из окружения процесса не читается, по умолчанию process.env
    try { await assertDemoIsolation({ cfg, db, vault, repo, env: cfg.env }); } catch (e) { db.close(); throw e; }
  }

  const signingKey = await loadOrCreateSigningKey(vault);
  let totpHex = await vault.get('sys/totp');
  if (!totpHex) { totpHex = crypto.randomBytes(32).toString('hex'); await vault.put('sys/totp', totpHex); }
  const keys = { totp: Buffer.from(totpHex, 'hex'), signing: signingKey };

  // Модуль входа; overrides.auth — готовый провайдер (только тесты, например поддельный внешний)
  let auth = overrides.auth;
  if (!auth) {
    try { auth = createAuthProvider({ config: cfg, repo, keys, logger }); } catch (e) { db.close(); throw e; } // неизвестный провайдер — ошибка старта
  }
  const ctx = { repo, vault, catalog, config: cfg, logger, keys, auth, verifyTotp: null };
  const grants = createGrantService({ repo, signingKey, logger });
  // overrides.notifyChannels / notifyTimeoutMs / notifyTest (mock Slack и SMTP на localhost) — только тесты, из env не читаются
  // Демо: каналы уведомлений не создаются (пустой список), Telegram-менеджера нет
  const notify = createNotifier({ repo, getBot: () => tg.current(), vault, logger, catalog, publicUrl: cfg.publicUrl, channels: cfg.demo ? [] : overrides.notifyChannels, timeoutMs: overrides.notifyTimeoutMs, test: overrides.notifyTest || null });
  const requests = createRequestService({ repo, grants, notify, tz: cfg.tz, logger, verifyTotp: (code) => ctx.verifyTotp?.(code) });
  const tg = cfg.demo
    ? { current: () => null, init: async () => null, check: async () => { throw new Error('demo_network_disabled'); }, restart: async () => { throw new Error('demo_network_disabled'); }, stop: async () => {} }
    : createTgManager({
      repo, vault, logger,
      // overrides.tgApiRoot — только тесты (поддельный Telegram API на localhost)
      deps: () => ({ apiRoot: overrides.tgApiRoot, requests, links: { makeLink: (r, purpose, ttl) => makeLink(r, purpose, ttl, cfg.publicUrl) }, signingKey, publicUrl: cfg.publicUrl, auth, filterLine: (cred) => filterLine(cred.filter, catalog.get(cred.provider)), onLinked: () => notify.security(t('notify.sec.tg_linked')) }),
    });
  // Лимиты частоты (контракт access-mcp): создаются здесь и общие для REST и MCP
  const limits = {
    requests: createLimiter({ limit: 30, windowSec: 60 }),
    poll: createLimiter({ limit: 12, windowSec: 60 }),
    proxy: createLimiter({ limit: cfg.proxyRatePerMin, windowSec: 60 }),
    mcp: createLimiter({ limit: 120, windowSec: 60 }), // запросов к /mcp на агента (все методы)
  };
  const access = createAccess({ repo, catalog, grants, requests });
  // Демо: транспорт прокси — мок в процессе, сокеты не открываются
  const proxy = createProxy({ repo, catalog, vault, grants, access, limits, logger, now: overrides.now, testUpstream: cfg.demo ? null : (overrides.testUpstream || null), transport: cfg.demo ? createDemoTransport() : undefined });
  Object.assign(ctx, { grants, notify, requests, tg, proxy, access });

  const mcp = {}; // управление сессиями: sweep(), closeAll(reason), count() (заполняет плагин; нужно тестам и остановке)
  const demoReset = cfg.demo ? createDemoReset({ repo, vault, cfg, logger, onReset: () => mcp.closeAll?.('demo_reset') }) : null;
  const fastify = Fastify({ logger: false, trustProxy: cfg.trustProxy, bodyLimit: cfg.demo ? 64 * 1024 : cfg.bodyLimit });
  // Демо: allowlist и лимиты по IP — самые первые хуки, до mcp, registerWeb и agentApi
  if (cfg.demo) demoRouteGuard(fastify, { repo, vault, reset: demoReset, logger });
  fastify.addHook('onResponse', async (req, reply) => {
    logger.info({ m: req.method, u: maskUrl(req.url), s: reply.statusCode, ms: Math.round(reply.elapsedTime) }, 'req');
  });
  await fastify.register(agentApi, { repo, catalog, requests, grants, proxy, access, limits, logger });
  // MCP до сайта: у /mcp свои проверки Origin/Host, хуки сайта (cookie, CSRF) на него не действуют
  if (cfg.mcpEnabled) {
    await fastify.register(mcpPlugin, { repo, catalog, requests, grants, access, proxy, limits, config: cfg, logger, now: overrides.mcpNow, control: mcp });
  }
  await registerWeb(fastify, ctx);
  // Демо: на старте всегда сброс (сид: владелец без пароля, ключ cred/demo, агент demo-agent)
  if (demoReset) await demoReset.runOnce();

  const timers = [];
  return {
    fastify, ctx, repo, db, mcp, demoReset,
    async start() {
      await tg.init();
      timers.push(grants.reapLoop(), requests.expireLoop());
      if (demoReset) timers.push(demoReset.loop());
      // старые шаги TOTP (старше 10 минут) больше не нужны для защиты от повтора (П-32)
      const totpPurge = setInterval(() => {
        try { repo.purgeTotpSteps(); } catch (e) { logger.error({ err: e.message }, 'purgeTotpSteps'); }
        try { repo.purgePending(); } catch (e) { logger.error({ err: e.message }, 'purgePending'); } // просроченные черновики 2FA (П-19)
      }, 60_000);
      totpPurge.unref();
      timers.push(totpPurge);
      await fastify.listen({ port: cfg.port, host: cfg.host });
      logger.info({ port: cfg.port, host: cfg.host, publicUrl: cfg.publicUrl, vault: cfg.vault }, 'gateway started');
    },
    async stop() { timers.forEach(clearInterval); await mcp.closeAll?.('shutdown'); await tg.stop(); await fastify.close(); db.close(); },
  };
}
