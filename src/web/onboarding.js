// Онбординг «Connect your agent» (ТЗ §5): состояние шагов из базы и тексты для настройки агентов.
// Чистые функции без обращений к сети; токен сюда приходит только для показа на странице один раз.
import { readChannelMeta } from '../notify.js';
import { t } from '../i18n.js';

export const KINDS = Object.freeze(['chatgpt', 'claude-code', 'cursor', 'claude-desktop', 'script']);
export const isKind = (k) => KINDS.includes(k);

/** Имя нового агента для карточки (словарь agent_name.*). */
export const agentNameOf = (kind) => t(`welcome.agent_name.${kind}`);

/**
 * Состояние онбординга. Шаги выводятся из базы: агент есть, ключ есть, канал уведомлений включён
 * (Telegram подключён или Slack/e-mail включён) либо шаг пропущен явно.
 * -> { agent, key, notify, count, skipped, pending, calls }
 */
export function onboardingState(repo, { telegramConnected = false } = {}) {
  const agent = repo.listAgents().length > 0;
  const key = repo.listCredentials().length > 0;
  const notify = telegramConnected || readChannelMeta(repo, 'slack').enabled || readChannelMeta(repo, 'email').enabled
    || repo.getMeta('onboarding_notify_skipped') === '1';
  return {
    agent, key, notify,
    count: Number(agent) + Number(key) + Number(notify),
    skipped: repo.getMeta('onboarding_skipped') === '1',
    pending: repo.getMeta('onboarding_pending') === '1',
    calls: repo.countOkCalls(),
  };
}

/** Нужно ли с корня уводить на /welcome: свежая установка, где онбординг не пропущен, нет ни агента, ни ключа. */
export const needsWelcome = (s) => s.pending && !s.skipped && !s.agent && !s.key;

/** Короткое имя сервера для команд (из названия продукта). */
const serverName = () => (t('app.name').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'gateway');

/**
 * Текст настройки для карточки. Содержит токен: показывать только на странице с no-store, один раз.
 * -> { how: ключ словаря, text }
 */
export function snippetFor(kind, { publicUrl, token }) {
  const name = serverName();
  const mcp = `${publicUrl}/mcp`;
  if (kind === 'claude-code') {
    return `claude mcp add --transport http ${name} ${mcp} --header "Authorization: Bearer ${token}"`;
  }
  if (kind === 'cursor') {
    return JSON.stringify({ mcpServers: { [name]: { url: mcp, headers: { Authorization: `Bearer ${token}` } } } }, null, 2);
  }
  if (kind === 'claude-desktop') {
    return JSON.stringify({ mcpServers: { [name]: { command: 'npx', args: ['-y', 'mcp-remote', mcp, '--header', 'Authorization:${AUTH_HEADER}'], env: { AUTH_HEADER: `Bearer ${token}` } } } }, null, 2);
  }
  if (kind === 'script') {
    return [
      `curl -s -X POST ${publicUrl}/v1/grants -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d '{"provider":"<service>","reason":"<why>"}'`,
      `curl -s ${publicUrl}/v1/grants/<request_id> -H "Authorization: Bearer ${token}"`,
      `curl -s ${publicUrl}/v1/proxy/<service>/<path> -H "Authorization: Bearer <pass token>"`,
    ].join('\n');
  }
  // chatgpt: схема Actions (запрос пропуска); вызовы через шлюз идут с токеном пропуска
  return [
    'openapi: 3.1.0',
    'info: { title: Gateway, version: "1" }',
    `servers: [ { url: ${publicUrl} } ]`,
    'paths:',
    '  /v1/grants:',
    '    post:',
    '      operationId: requestPass',
    '      requestBody:',
    '        content:',
    '          application/json:',
    '            schema:',
    '              type: object',
    '              required: [provider]',
    '              properties: { provider: { type: string }, reason: { type: string }, ttl: { type: integer }, calls: { type: integer } }',
    '      responses: { "200": { description: ok }, "202": { description: pending } }',
    '  /v1/grants/{id}:',
    '    get:',
    '      operationId: pollPass',
    '      parameters: [ { name: id, in: path, required: true, schema: { type: string } } ]',
    '      responses: { "200": { description: ok }, "202": { description: pending } }',
  ].join('\n');
}
