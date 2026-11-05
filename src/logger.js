// Логи: pino с redact по заголовкам из каталога; тела не логируются; path-секреты маскируются (ТЗ §9.2)
import pino from 'pino';

export function createLogger(level, redactHeaders = [], destination = undefined) {
  const paths = [];
  for (const h of new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', ...redactHeaders.map((s) => s.toLowerCase())])) {
    paths.push(`req.headers["${h}"]`, `headers["${h}"]`, `res.headers["${h}"]`);
  }
  paths.push('password', 'key', 'secret', 'token', 'code', '*.password', '*.key', '*.secret', '*.token');
  return pino({ level, redact: { paths, censor: '****' }, base: null, timestamp: pino.stdTimeFunctions.isoTime }, destination);
}

/**
 * URL для логов (П-33): без query и фрагмента, токен одноразовых ссылок (/l/<токен>, /setup/<код>) заменён на ****.
 * Единственное место маскирования URL: access-log, обработчики ошибок, sendApiError.
 */
export function maskUrl(url) {
  const p = String(url ?? '').split(/[?#]/)[0];
  return p.replace(/^\/(l|setup)\/(?!backup-codes\.txt$)[^/]+/i, '/$1/****');
}

export function maskPath(path, credential) {
  if (!credential || credential.kind !== 'path') return path;
  const t = credential.injection?.template || '';
  const prefix = t.split('{secret}')[0];
  if (!prefix || !path.startsWith(prefix)) return path;
  const rest = path.slice(prefix.length);
  const segs = (credential.injection.secretSegments || 1);
  const parts = rest.split('/');
  for (let i = 0; i < segs && i < parts.length; i++) parts[i] = '****';
  return prefix + parts.join('/');
}
