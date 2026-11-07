// Прокси к сервису без привязки к транспорту: call(input) -> CallResult (ТЗ §8, §9; контракт access-mcp.md)
import { Agent, request as undiciRequest } from 'undici';
import dns from 'node:dns';
import { Transform, PassThrough, Readable, pipeline, finished } from 'node:stream';
import { isPrivateIp, validateAgentPath } from './ssrf.js';
import { makeRedactor, redactText } from './redact.js';
import { maskPath } from '../logger.js';
import { compileFilter, checkJsonDepth, previewRoute, fieldNames } from './filter.js';
import { isInfraError, markInfra, RETRY_AFTER_SEC } from './infra.js';

/** Читает поток целиком, но не больше max байт; иначе ошибка с code. */
async function readAll(stream, max, code) {
  const chunks = [];
  let n = 0;
  for await (const c of stream) {
    n += c.length;
    if (n > max) { stream.destroy?.(); throw Object.assign(new Error('body too large'), { code }); }
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length', 'authorization', 'cookie', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip', 'expect',
  // служебные заголовки Cloudflare и прокси: сервису не нужен IP и маршрут агента
  'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cdn-loop', 'true-client-ip', 'forwarded', 'via', 'x-forwarded-port',
  // подмена метода: фильтр проверил один метод, а сервис выполнил бы другой (9.1b)
  'x-http-method-override', 'x-method-override', 'x-http-method']);
const RESP_DROP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'content-encoding', 'set-cookie', 'strict-transport-security', 'alt-svc']);
// Заголовки маршрута и прокси удаляются по префиксу: сервису не нужны IP и путь агента (П-36)
const DROP_PREFIXES = ['x-forwarded-', 'cf-', 'x-real-', 'x-envoy-', 'x-amzn-'];

/** Имена заголовков из значения Connection (строка или массив): нижний регистр, без пробелов. */
export function connectionTokens(value) {
  return new Set([].concat(value ?? []).flatMap((v) => String(v).split(',')).map((s) => s.trim().toLowerCase()).filter(Boolean));
}

/** Заголовки запроса агента к сервису: без hop-by-hop, маршрутных (по префиксу) и названных в Connection (П-36). */
export function filterRequestHeaders(headers, extraDrop = []) {
  const extra = new Set(extraDrop);
  const named = connectionTokens(headers.connection);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (HOP.has(lk) || lk.startsWith(':') || lk === 'accept-encoding' || named.has(lk) || extra.has(lk)) continue;
    if (DROP_PREFIXES.some((p) => lk.startsWith(p))) continue;
    out[lk] = v;
  }
  return out;
}

/** Заголовки ответа сервиса: без RESP_DROP и названных в его Connection (П-36). */
export function filterResponseHeaders(headers) {
  const named = connectionTokens(headers.connection);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (!RESP_DROP.has(lk) && !named.has(lk)) out[lk] = v;
  }
  return out;
}

/** lookup для undici: резолвим сами и отклоняем приватные адреса (защита от DNS rebinding) */
function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
    if (err) return cb(err);
    const list = Array.isArray(addrs) ? addrs : [addrs];
    if (!list.length) return cb(new Error('DNS: no address found'));
    if (list.some((a) => isPrivateIp(a.address))) return cb(Object.assign(new Error('Service address points to a private network'), { code: 'EPRIVATE' }));
    const pick = list.find((a) => a.family === 4) || list[0];
    if (options?.all) return cb(null, [pick]);
    cb(null, pick.address, pick.family);
  });
}

const MAX_QUERY = 4096;
// Предел буфера ответа при фильтре полей или mask (contracts/rest-demo-notify.md): больше — 502 filtered_too_large
const BUFFER_MAX = 8 * 1024 * 1024;
const NO_BODY = new Set(['GET', 'HEAD']);

/**
 * transport(url, opts) -> { statusCode, headers, body } — как undici.request. В демо-режиме это
 * createDemoTransport() из src/demo/guard.js (мок в процессе, без сокетов).
 */
export function createProxy({ repo, catalog, vault, grants, access, limits, logger, now = Date.now, testUpstream = null, transport = undiciRequest }) {
  // Агрегация повторных записей audit (П-34): не чаще раза в минуту на ключ, остальное считается в памяти
  // и пишется как count в мету следующей записи
  const agg = new Map(); // ключ -> { last, skipped }
  function auditAggregated(key, actor, action, target, meta) {
    const t = now();
    const s = agg.get(key) || { last: -Infinity, skipped: 0 };
    if (t - s.last < 60_000) { s.skipped += 1; agg.set(key, s); return; }
    repo.audit(actor, action, target, { ...meta, ...(s.skipped > 0 && { count: s.skipped }) });
    agg.set(key, { last: t, skipped: 0 });
    if (agg.size > 10000) for (const [k, v] of agg) if (t - v.last >= 60_000 && !v.skipped) agg.delete(k);
  }
  // testUpstream: { host: 'http://127.0.0.1:port' } — только из тестов через buildApp(overrides), из env не читается
  const agent = new Agent({ connect: { lookup: safeLookup, timeout: 10_000 }, maxRedirections: 0 });

  function countingLimiter(maxBody, onExceed) {
    let n = 0;
    return new Transform({ transform(chunk, _e, cb) { n += chunk.length; if (n > maxBody) return cb(onExceed()); cb(null, chunk); } });
  }

  const fail = (status, error, extra) => ({ ok: false, status, error, ...(extra && { extra }) });

  /**
   * Вызов сервиса от имени пропуска (контракт access-mcp.md, «core/proxy.js»).
   * Возвращает CallResult. Владелец lease — это ядро: при ok:true lease снимается по концу/destroy() потока body,
   * при ok:false после резерва — до возврата. Потребитель обязан дочитать body или вызвать body.destroy().
   * Инфраструктурный сбой (сейф, база) -> { ok:false, status:503, error:'service_unavailable', retryAfter } (адаптер ставит Retry-After).
   */
  async function run(input) {
    const method = String(input.method || 'GET').toUpperCase();
    const upstreamPath = input.path;
    const via = input.via || 'rest';
    const providerSlug = input.provider;
    // Вызов владельца (предпросмотр фильтра, п. 7.3): только из preview(), токена и пропуска нет, квоты агентов не тратятся
    const owner = input.ownerCredentialId != null;

    // Шаг 1: авторизация (П-15). Между ней и grants.reserve нет await: отзыв не успевает проскочить
    let auth;
    if (owner) {
      const c = repo.getCredential(input.ownerCredentialId);
      const p = c && catalog.get(c.provider);
      auth = c && p ? { ok: true, grant: null, credential: c, provider: p } : { ok: false, code: 'not_found' };
    } else auth = access.authorizeCall({ token: input.token, provider: providerSlug, agentId: input.expectAgentId, credentialId: input.expectCredentialId });
    if (!auth.ok) { logger.debug?.({ reason: auth.reason }, 'proxy.unauthorized'); return fail(owner ? 404 : 401, auth.code); }
    const { grant, credential, provider } = auth;
    const agentId = owner ? 'owner' : grant.agent_id;
    if (!owner) repo.touchAgent(agentId); // успешная авторизация пропуска: last_seen_at (repo сам держит раз в минуту)
    const auditBase = owner
      ? { credential: credential.id, provider: provider.slug, via }
      : { grant: grant.id, agent: agentId, credential: credential.id, provider: provider.slug, via, ...(input.sessionTag && { session: input.sessionTag }) };

    // Шаг 2: лимит частоты на агента (П-34): до фильтра, audit и сейфа; сервис и квота не затрагиваются
    if (!owner && limits?.proxy && !limits.proxy.take(agentId)) {
      auditAggregated(`rl:${agentId}`, `agent:${agentId}`, 'proxy.rate_limited', `${provider.slug}`, auditBase);
      return fail(429, 'rate_limited');
    }

    // Шаг 3: путь и query
    let decodedPath = upstreamPath;
    try { decodedPath = decodeURIComponent(upstreamPath); } catch { return fail(400, 'bad_path'); }
    if (!validateAgentPath(upstreamPath) || !validateAgentPath(decodedPath)) return fail(400, 'bad_path');
    // двойное кодирование (%2562atch): сервис может раскодировать путь ещё раз (П-1)
    if (decodedPath.includes('%')) return fail(400, 'bad_path');
    let q = typeof input.query === 'string' ? input.query : '';
    // eslint-disable-next-line no-control-regex
    if (q.length > MAX_QUERY || /[\u0000-\u001f\u007f#]/.test(q)) return fail(400, 'bad_query');

    // Шаг 4: фильтр данных (ТЗ v1.3): закрытый метод отклоняем до квоты и до сервиса
    // Вызов владельца идёт без фильтра: предпросмотр сам сравнивает «было» и «осталось» (значения наружу не выходят)
    const flt = owner ? null : compileFilter(credential.filter, provider);
    // Метод и путь (П-17): deny → запись/правила → 403 method_not_allowed | write_not_allowed; затем query → 400 query_not_allowed
    if (flt) {
      let reason = null;
      let status = 403;
      if (!flt.allowMethod(method, decodedPath)) reason = flt.denyReason(method, decodedPath) || 'method_not_allowed';
      else {
        const qr = flt.checkQuery(method, decodedPath, q);
        if (qr) { reason = qr; status = qr === 'query_not_allowed' ? 400 : 403; }
      }
      if (reason) {
        auditAggregated(`den:${agentId}:${credential.id}`, `agent:${agentId}`, 'proxy.denied', `${method} ${provider.slug}${maskPath(upstreamPath, credential)}`, { ...auditBase, denied_reason: reason, status });
        return fail(status, reason, status === 403 ? { allowed: flt.methods } : undefined);
      }
    }

    // Шаг 5: длина тела проверяется до чтения и до резерва
    const isBuf = Buffer.isBuffer(input.body);
    const cl = input.contentLength ?? (isBuf ? input.body.length : null);
    if (cl !== null && (!Number.isFinite(cl) || cl > provider.maxBody)) return fail(413, 'body_too_large');

    // Шаг 6: резерв квоты; дальше любой выход освобождает lease
    const leaseId = owner ? null : grants.reserve(grant.id);
    if (!owner && !leaseId) return fail(429, 'quota_exceeded');

    // Шаг 7: таймеры. Общий срок вызова и отмена от транспорта: медленный поток не держит слот бесконечно (П-11)
    const extendTimer = setInterval(() => { if (!leaseId) return; try { grants.extend(leaseId); } catch (e) { logger.error({ err: e?.message, code: e?.code }, 'lease extend failed'); } }, 30_000); extendTimer.unref();
    const ac = new AbortController();
    let resBody = null;
    const deadline = setTimeout(() => { ac.abort(); resBody?.destroy(); }, provider.timeout * 1000); deadline.unref();
    const signal = input.signal ? AbortSignal.any([ac.signal, input.signal]) : ac.signal;
    // done: ровно один раз; сбой базы при release не должен ронять процесс (вызывается из события), lease добьёт reapLeases
    let released = false;
    const done = () => {
      if (released) return;
      released = true;
      clearInterval(extendTimer); clearTimeout(deadline);
      if (!leaseId) return;
      try { grants.release(leaseId); } catch (e) { logger.error({ err: e?.message, code: e?.code }, 'lease release failed'); }
    };

    const started = Date.now();
    const target = `${method} ${provider.slug}${maskPath(upstreamPath, credential)}`;
    let audited = false;
    let removed = null;
    let masked = null;
    const auditCall = (status) => {
      if (audited) return;
      audited = true;
      try { repo.audit(owner ? 'owner' : `agent:${agentId}`, owner ? 'proxy.preview' : 'proxy.call', target, { ...auditBase, status, ms: Date.now() - started, ...(removed !== null && { fields_removed: removed }), ...(masked !== null && { masked }) }); }
      catch (e) { logger.error({ err: e?.message, code: e?.code }, 'proxy audit failed'); }
    };
    // ошибка после резерва: audit, снять lease и таймеры, вернуть ok:false
    const failAfter = (status, error, extra) => { auditCall(status); done(); return fail(status, error, extra); };

    try {
      // Шаг 8: сбой сейфа — инфраструктурная ошибка (503), до сервиса дело не доходит (П-30)
      let secret;
      try { secret = await vault.get(`cred/${credential.id}`); } catch (e) { throw markInfra(e, 'vault'); }
      if (!secret) {
        repo.audit(owner ? 'owner' : `agent:${agentId}`, 'proxy.no_secret', credential.id, auditBase);
        return failAfter(401, 'invalid_grant');
      }
      // все формы секрета (сырая, URL, base64, для Basic ещё ключ): сервис может вернуть любую из них (Н-7)
      const forms = catalog.secretForms(provider, secret);

      // Шаг 9: заголовки к сервису
      const headers = filterRequestHeaders(input.headers || {}, catalog.redactHeaders());
      headers['accept-encoding'] = 'identity'; // ответ нужен несжатым, чтобы вычистить секрет
      if (provider.extraHeaders) for (const [k, v] of Object.entries(provider.extraHeaders)) headers[k.toLowerCase()] = v;
      let path = upstreamPath.startsWith('/') ? upstreamPath : '/' + upstreamPath;
      if (credential.injection.type === 'header') {
        delete headers[credential.injection.name.toLowerCase()];
        // encode: base64 — HTTP Basic: в сейфе `логин:ключ`, в заголовок идёт prefix + base64(секрет)
        const value = credential.injection.encode === 'base64' ? Buffer.from(secret, 'utf8').toString('base64') : secret;
        headers[credential.injection.name.toLowerCase()] = (credential.injection.prefix || '') + value;
      } else {
        path = credential.injection.template.replace('{secret}', secret) + path;
      }
      const hasBody = !NO_BODY.has(method) && input.body != null;
      if (cl !== null && !NO_BODY.has(method)) headers['content-length'] = String(cl);
      // без Content-Length тело уходит потоком: undici сам выбирает chunked (свой transfer-encoding он отвергает)

      // Шаг 10: тело — потоком с лимитом
      let body;
      if (flt?.enabled) {
        // при фильтре полей тело читаем целиком: select агента заменяется списком разрешённых полей
        let buf = null;
        if (hasBody) {
          if (isBuf) { if (input.body.length > provider.maxBody) throw Object.assign(new Error('body too large'), { code: 'EBODY' }); buf = input.body; }
          else buf = await readAll(input.body, provider.maxBody, 'EBODY');
        }
        const sel = flt.rewriteSelect(decodedPath, q, buf, (input.headers || {})['content-type'], method);
        if (sel.error) return failAfter(400, sel.error);
        q = sel.query;
        if (sel.body) { body = sel.body; headers['content-length'] = String(sel.body.length); delete headers['transfer-encoding']; }
        else if (buf) { headers['content-length'] = '0'; delete headers['transfer-encoding']; }
      } else if (hasBody) {
        if (isBuf) body = input.body;
        else {
          const lim = countingLimiter(provider.maxBody, () => Object.assign(new Error('body too large'), { code: 'EBODY' }));
          // pipe, а не pipeline: при превышении лимита нельзя разрушать источник (иначе 413 клиенту не отправить)
          input.body.on('error', (e) => lim.destroy(e));
          body = input.body.pipe(lim);
        }
      }

      // Шаг 11: запрос к сервису
      const override = testUpstream?.[credential.host];
      const res = await transport(`${override || 'https://' + credential.host}${path}${q}`, {
        method, headers, body, dispatcher: override ? undefined : agent, signal,
        headersTimeout: provider.timeout * 1000, bodyTimeout: provider.timeout * 1000,
      });
      // Шаг 12: сервис проигнорировал identity и сжал ответ: маскирование секрета по сжатым байтам не работает,
      // тело не отдаём ни потоком, ни через фильтр (П-4)
      const enc = String(res.headers['content-encoding'] || 'identity').trim().toLowerCase();
      if (enc !== 'identity') {
        // destroy() у тела undici испускает RequestAbortedError — без слушателя это необработанное исключение
        res.body.on('error', () => {});
        res.body.destroy();
        return failAfter(502, 'upstream_encoded');
      }
      resBody = res.body;
      const status = res.statusCode;
      const outHeaders = {};
      for (const [k, v] of Object.entries(filterResponseHeaders(res.headers))) outHeaders[k] = Array.isArray(v) ? v.map((x) => redactText(x, forms)) : redactText(String(v), forms);

      // ответ без тела (HEAD, 204, 304) разбирать нечего: идёт потоком
      const emptyBody = method === 'HEAD' || status === 204 || status === 304;
      if (flt?.needsBuffer && !emptyBody) {
        // ответ целиком: отдаём только разрешённые поля JSON (и маскируем), всё прочее — ошибка без тела сервиса
        const ctype = String(res.headers['content-type'] || '');
        if (/text\/event-stream/i.test(ctype)) { res.body.on('error', () => {}); res.body.destroy(); return failAfter(502, 'filtered_stream'); }
        let raw;
        const bufferMax = Math.min(provider.maxBody, provider.bufferMax ?? BUFFER_MAX);
        try { raw = await readAll(res.body, bufferMax, 'ERESP'); } catch (e) { if (e?.code === 'ERESP') return failAfter(502, 'filtered_too_large'); throw e; }
        if (!/application\/json/i.test(ctype)) return failAfter(502, 'filtered_non_json');
        // глубину считаем по байтам до JSON.parse: слишком вложенный ответ не разбираем (П-28)
        if (!checkJsonDepth(raw)) return failAfter(502, 'filtered_too_deep');
        let json;
        try { json = JSON.parse(raw.toString('utf8')); } catch { return failAfter(502, 'filtered_non_json'); }
        // №12: строковые значения вычищаем от секрета ДО filterBody. Обрезка длинного поля
        // (maxFieldLen) и маска режут строку и могут разрезать секрет посередине, тогда после
        // фильтра он целиком уже не найдётся и его часть ушла бы агенту.
        const scrub = (v) => {
          if (typeof v === 'string') return redactText(v, forms);
          if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) v[i] = scrub(v[i]); return v; }
          if (v && typeof v === 'object') { for (const k of Object.keys(v)) v[k] = scrub(v[k]); return v; }
          return v;
        };
        scrub(json);
        const f = flt.filterBody(json, decodedPath, method);
        if (flt.enabled) removed = f.removed;
        if (flt.mask) masked = f.masked;
        const payload = Buffer.from(redactText(JSON.stringify(f.json), forms), 'utf8');
        outHeaders['content-type'] = 'application/json; charset=utf-8';
        outHeaders['content-length'] = String(payload.length);
        const out = Readable.from([payload]);
        resBody = out;
        finished(out, { writable: false }, done);
        auditCall(status);
        return { ok: true, status, headers: outHeaders, body: out };
      }

      // секрет вычищаем из любого ответа: сервис может вернуть ключ в тексте ошибки
      const r = makeRedactor(forms);
      const t = new Transform({ transform(c, _e, cb) { cb(null, r.push(c)); }, flush(cb) { cb(null, r.flush()); } });
      const pass = new PassThrough();
      // pipeline: destroy() потребителя или ошибка/отмена любого звена разрушает остальные (в т.ч. запрос к сервису)
      pipeline(res.body, t, pass, () => {});
      resBody = pass;
      finished(pass, { writable: false }, done);
      auditCall(status);
      return { ok: true, status, headers: outHeaders, body: pass };
    } catch (e) {
      // лимит тела превышен на лету: обрываем запрос к сервису (он не должен принять усечённое тело как полное)
      if (e?.code === 'EBODY') { ac.abort(); return failAfter(413, 'body_too_large'); }
      if (isInfraError(e)) { logger.error({ err: e?.message, code: e?.code, src: e?.infra }, 'infra error'); return { ...failAfter(503, 'service_unavailable'), retryAfter: RETRY_AFTER_SEC }; }
      if (e?.code === 'EPRIVATE') { logger.warn({ host: credential.host }, 'ssrf blocked'); return failAfter(502, 'upstream_unreachable'); }
      logger.warn({ err: e?.message, code: e?.code, host: credential.host }, 'upstream error');
      return failAfter(502, 'upstream_unreachable');
    }
  }

  /**
   * «Проверить на одном вызове» (ТЗ §9.3): один читающий вызов от имени владельца с limit=1 тем же путём, что и агентский
   * (сейф, SSRF-защита, фиксированный хост, редактор секретов), но без пропуска, квот и фильтра; в audit — proxy.preview.
   * Из ответа берутся только имена полей: значения не возвращаются, не сохраняются и не логируются.
   * @returns {Promise<{ok:true, route:string, before:string[], after:string[], allowed:boolean}|{ok:false, error:string, status?:number}>}
   */
  async function preview(credentialId) {
    const cred = repo.getCredential(credentialId);
    const provider = cred && catalog.get(cred.provider);
    if (!provider) return { ok: false, error: 'not_found', status: 404 };
    const route = previewRoute(cred.filter, provider);
    if (!route) return { ok: false, error: 'preview_no_route' };
    const r = await run({ ownerCredentialId: cred.id, provider: provider.slug, method: route.method, path: route.path, query: route.query, via: 'owner' });
    if (!r.ok) return { ok: false, error: r.error, status: r.status };
    let raw;
    try { raw = await readAll(r.body, Math.min(provider.maxBody, provider.bufferMax ?? BUFFER_MAX), 'ERESP'); }
    catch (e) { r.body.destroy?.(); return { ok: false, error: e?.code === 'ERESP' ? 'filtered_too_large' : 'upstream_unreachable' }; }
    if (r.status < 200 || r.status >= 300) return { ok: false, error: 'upstream_status', status: r.status };
    if (!/application\/json/i.test(String(r.headers['content-type'] || ''))) return { ok: false, error: 'filtered_non_json' };
    if (!checkJsonDepth(raw)) return { ok: false, error: 'filtered_too_deep' };
    let json;
    try { json = JSON.parse(raw.toString('utf8')); } catch { return { ok: false, error: 'filtered_non_json' }; }
    const before = fieldNames(json);
    const flt = compileFilter(cred.filter, provider);
    const allowed = !flt || flt.allowMethod(route.method, route.path);
    const after = !flt ? before : allowed ? fieldNames(flt.filterBody(json, route.path, route.method).json) : [];
    return { ok: true, route: `${route.method} ${route.path}`, before, after, allowed };
  }

  return {
    preview,
    async call(input) {
      // вызов владельца без пропуска доступен только через preview(): снаружи ownerCredentialId отбрасывается
      try { return await run({ ...input, ownerCredentialId: undefined }); } catch (e) {
        // сбой базы до резерва (authorizeCall, лимитер, reserve): 503, как для остальных инфраструктурных ошибок (П-30)
        if (isInfraError(e)) { logger.error({ err: e?.message, code: e?.code, src: e?.infra }, 'infra error'); return { ...fail(503, 'service_unavailable'), retryAfter: RETRY_AFTER_SEC }; }
        throw e;
      }
    },
  };
}
