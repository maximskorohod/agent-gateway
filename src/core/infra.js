import { maskUrl } from '../logger.js';

// Ошибки инфраструктуры (П-30): сейф и база. Единая классификация: такие ошибки всегда 503, а не 500/502.
// Ошибки сети до сервиса (upstream) сюда не относятся: они остаются 502 upstream_unreachable.

const AWS_INFRA_NAMES = new Set([
  'CredentialsProviderError', 'ThrottlingException', 'TooManyUpdates', 'ServiceUnavailable', 'ServiceUnavailableException',
  'InternalServerError', 'InternalFailure', 'RequestTimeout', 'RequestTimeoutException', 'TimeoutError',
  'AccessDeniedException', 'UnrecognizedClientException', 'ExpiredTokenException', 'InvalidSignatureException',
]);

/** Помечает ошибку как инфраструктурную (source: 'vault' | 'db'); возвращает ту же ошибку. */
export function markInfra(err, source) {
  const e = err instanceof Error ? err : new Error(String(err));
  try { e.infra = source; } catch { /* замороженный объект: оставляем как есть */ }
  return e;
}

/** true: сбой сейфа или базы, шлюз временно недоступен (агенту 503, владельцу страница 503). */
export function isInfraError(err) {
  if (!err || typeof err !== 'object') return false;
  if (err.infra) return true;
  if (err.name === 'SqliteError' || (typeof err.code === 'string' && err.code.startsWith('SQLITE_'))) return true;
  // SDK AWS: у всех ошибок есть $metadata; ParameterNotFound — не сбой, а «нет значения»
  if (err.$metadata && err.name !== 'ParameterNotFound') return AWS_INFRA_NAMES.has(err.name) || !!err.$metadata.httpStatusCode && err.$metadata.httpStatusCode >= 500;
  return false;
}

/** Секунды для заголовка Retry-After при 503. */
export const RETRY_AFTER_SEC = 5;

/**
 * Ответ на ошибку для JSON-API (/v1/*): инфраструктурная -> 503 service_unavailable + Retry-After,
 * 400 -> bad_request, прочее -> internal. Лог без query (в ней могут быть токены) и без секретов.
 * Единственная точка: ею пользуются обработчик плагина /v1 и корневой обработчик (П-30).
 */
export function sendApiError(err, req, reply, logger) {
  const url = maskUrl(req.url);
  if (isInfraError(err)) {
    logger.error({ err: err.message, url, code: err.code, src: err.infra }, 'infra error');
    return reply.header('retry-after', String(RETRY_AFTER_SEC)).code(503).send({ error: 'service_unavailable' });
  }
  const status = err.statusCode || 500;
  if (status === 413) return reply.code(413).send({ error: 'body_too_large' }); // ошибка клиента, не сбой: в журнал не пишем
  // 4xx: ошибка запроса, а не сбой, в журнал ошибок не идёт: иначе любой посетитель его засоряет
  if (status >= 500) logger.error({ err: err.message, url, code: err.code }, 'unhandled');
  else logger.info({ err: err.message, url, code: err.code }, 'request error');
  return reply.code(status).send({ error: status === 400 ? 'bad_request' : 'internal' });
}

/** Обёртка сейфа: любой сбой get/put/del помечается как инфраструктурный. */
export function wrapVault(vault) {
  const w = {};
  // names — необязательный метод file-сейфа (проверка изоляции демо)
  for (const m of ['get', 'put', 'del', 'names']) {
    if (typeof vault[m] !== 'function') continue;
    w[m] = async (...a) => { try { return await vault[m](...a); } catch (e) { throw markInfra(e, 'vault'); } };
  }
  return w;
}
