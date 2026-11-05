// Конфигурация из переменных окружения (ARCHITECTURE.md → config.js)
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const env = process.env;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = env.GW_DATA_DIR || path.join(root, 'data');
const posInt = (v, def) => (Number(v) > 0 ? Math.floor(Number(v)) : def);

/** Адрес листа ожидания: только https:, до 300 символов, без учётных данных; иначе пусто (в config хранится как есть, проверяет buildApp). */
export function parseWaitlistUrl(v) {
  const s = String(v ?? '').trim();
  if (!s || s.length > 300) return '';
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:' || u.username || u.password) return '';
    return u.href;
  } catch { return ''; }
}

export const config = Object.freeze({
  root,
  dataDir,
  dbPath: path.join(dataDir, 'gw.db'),
  port: Number(env.GW_PORT || 8080),
  host: env.GW_HOST || '127.0.0.1',
  publicUrl: (env.GW_PUBLIC_URL || 'http://127.0.0.1:8080').replace(/\/+$/, ''),
  vault: env.GW_VAULT || 'file',
  vaultPrefix: env.GW_VAULT_PREFIX || '/gateway',
  vaultFile: path.join(dataDir, 'vault.json'),
  masterKeyFile: path.join(dataDir, 'master.key'),
  ssmRegion: env.GW_SSM_REGION || env.AWS_REGION || 'eu-central-1',
  logLevel: env.GW_LOG_LEVEL || 'info',
  // лимит вызовов прокси на агента в минуту (П-34); общий для REST и MCP
  proxyRatePerMin: Number(env.GW_PROXY_RATE_PER_MIN) > 0 ? Number(env.GW_PROXY_RATE_PER_MIN) : 300,
  // MCP-сервер (контракт access-mcp.md): Streamable HTTP на /mcp
  mcpEnabled: !['0', 'false', 'off'].includes(String(env.GW_MCP_ENABLED || '').toLowerCase()),
  mcpOrigins: (env.GW_MCP_ORIGINS || '').split(',').map((s) => s.trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean),
  mcpMaxSessionsPerAgent: posInt(env.GW_MCP_MAX_SESSIONS_PER_AGENT, 5),
  mcpMaxSessions: posInt(env.GW_MCP_MAX_SESSIONS, 200),
  mcpIdleSec: posInt(env.GW_MCP_IDLE_SEC, 900),
  mcpMaxLifetimeSec: posInt(env.GW_MCP_MAX_LIFETIME_SEC, 86400),
  mcpMaxResponse: posInt(env.GW_MCP_MAX_RESPONSE, 65536), // байт ответа сервиса, отдаваемых модели
  mcpBodyLimit: posInt(env.GW_MCP_BODY_LIMIT, 262144), // тело JSON-RPC запроса
  mcpCallParallel: posInt(env.GW_MCP_CALL_PARALLEL, 4), // одновременных call на сессию
  mcpSweepSec: 30, // период проверки простоя сессий (не из env: меняется только в тестах)
  bodyLimit: 2 * 1024 * 1024,
  // Доверенный прокси: по умолчанию только Caddy на loopback; в Docker Caddy в другом контейнере — задать GW_TRUST_PROXY=<подсеть>, например 172.16.0.0/12
  trustProxy: env.GW_TRUST_PROXY ? env.GW_TRUST_PROXY.split(',').map((s) => s.trim()).filter(Boolean) : 'loopback',
  catalogPath: path.join(root, 'providers.yaml'),
  iconsDir: path.join(root, 'assets', 'icons'),
  // модуль входа (GW_AUTH_PROVIDER); пусто = значение по умолчанию из src/auth/provider.js, неизвестное имя — ошибка старта
  authProvider: String(env.GW_AUTH_PROVIDER || '').trim(),
  waitlistUrl: String(env.GW_WAITLIST_URL || '').trim(), // «Cloud: join the waitlist»; проверка — parseWaitlistUrl в buildApp
  // Демо-режим (П-20): общий публичный экземпляр без реальных данных и без исходящих соединений
  demo: ['1', 'true', 'on'].includes(String(env.GW_DEMO || '').toLowerCase()),
  demoResetSec: posInt(env.GW_DEMO_RESET_SEC, 3600),
  dataDirExplicit: Boolean(env.GW_DATA_DIR), // в демо каталог данных задаётся явно (assertDemoIsolation)
  prodHosts: (env.GW_PROD_HOSTS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean), // страховка: хосты боевого шлюза
  lang: ['en', 'ru'].includes(env.GW_LANG) ? env.GW_LANG : 'en',
  tz: env.GW_TZ || 'UTC',
});
