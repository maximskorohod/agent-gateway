// MCP-сервер (П-16, контракт access-mcp.md): Streamable HTTP на /mcp, сессия на агента, токены пропусков только в памяти.
// Тексты инструментов и ошибок для модели - английские константы (ТЗ §8), t() здесь не используется.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema, isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { sendApiError } from '../core/infra.js';
import { authAgent, sha256hex } from '../core/access.js';
import { createLimiter } from '../core/ratelimit.js';
import { clientKey } from '../web/client-key.js';
import { normalizeFilter, compileFilter, describeFilter } from '../core/filter.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

const POLL_AFTER = 5;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const MAX_HEADERS = 20;
const MAX_HEADER_VALUE = 1024;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
// заголовки ответа сервиса, которые видит модель (П-34)
const RESP_HEADERS = new Set(['content-type', 'content-language', 'etag', 'last-modified', 'retry-after', 'link', 'x-total-count']);
const RESP_HEADER_PREFIXES = ['x-ratelimit-'];
const TEXT_TYPE_RE = /^(text\/[^;]*|application\/(json|xml|x-www-form-urlencoded)|[^;]*\+(json|xml))$/;

const INSTRUCTIONS = 'Temporary access to third-party APIs without handling their keys. ' +
  'Call list_services to see available services, request_access to get a time-limited pass (the owner may need to approve it), ' +
  'check_request to poll a pending request, then call to make API calls. Passes never leave the server.';

const TOOLS = [
  {
    name: 'list_services',
    description: 'List services whose keys are bound to this agent, with limits, data filter and the state of the access pass in this session.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { title: 'List services', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'request_access',
    description: 'Ask for a time-limited pass to a service key. Returns approved at once for keys that need no confirmation, otherwise pending: poll with check_request. An approved answer carries `filter` when the owner limits what you see (data types, fields, read-only, masked personal data).',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'Service slug from list_services.' },
        credential_id: { type: 'string', description: 'Key id; required when several keys of the service are available.' },
        ttl: { type: 'number', description: 'Requested lifetime of the pass in seconds.' },
        calls: { type: 'number', description: 'Requested number of calls.' },
        reason: { type: 'string', description: 'Why the access is needed (shown to the owner).' },
      },
      required: ['service', 'reason'],
      additionalProperties: false,
    },
    annotations: { title: 'Request access', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: 'check_request',
    description: 'Check a pending access request. When approved, the pass is attached to this session.',
    inputSchema: {
      type: 'object',
      properties: { request_id: { type: 'string' } },
      required: ['request_id'],
      additionalProperties: false,
    },
    annotations: { title: 'Check request', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'call',
    description: 'Call a service API through the gateway with the pass attached to this session. The key is added by the gateway. The response body is truncated to a limit.',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'Service slug.' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        path: { type: 'string', description: 'Path with optional query, starting with "/".' },
        credential_id: { type: 'string', description: 'Key id; required when the session holds passes to several keys of the service.' },
        body: { description: 'Request body: a string or any JSON value. Not allowed for GET.' },
        headers: { type: 'object', additionalProperties: { type: 'string' }, description: 'Extra request headers (at most 20).' },
      },
      required: ['service', 'method', 'path'],
      additionalProperties: false,
    },
    annotations: { title: 'Call', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  },
];

const ok = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] });
const fail = (error, extra) => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error, ...extra }) }] });
const isStr = (v) => typeof v === 'string' && v.length > 0;

/** Хост из заголовка Host без порта (IPv6 в скобках). */
function hostnameOf(h) {
  if (typeof h !== 'string' || !h.trim()) return null;
  const v = h.trim().toLowerCase();
  if (v.startsWith('[')) { const i = v.indexOf(']'); return i > 0 ? v.slice(0, i + 1) : null; }
  return v.split(':')[0];
}

/** Первые байты ответа без оборванного в конце символа UTF-8. */
function cutUtf8(buf) {
  let i = buf.length - 1; let back = 0;
  while (i > 0 && back < 3 && (buf[i] & 0xc0) === 0x80) { i--; back++; }
  if (i < 0) return buf;
  const lead = buf[i];
  const need = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 1;
  return buf.length - i < need ? buf.subarray(0, i) : buf;
}

/** Читает поток не больше max байт; over=true, если байт было больше. Поток всегда разрушается. */
async function readLimited(body, max) {
  const chunks = []; let n = 0; let over = false;
  try {
    for await (const c of body) {
      const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
      if (n + b.length > max) { chunks.push(b.subarray(0, max - n)); n = max; over = true; break; }
      chunks.push(b); n += b.length;
    }
  } finally { body.destroy(); }
  return { buf: Buffer.concat(chunks), over };
}

/** Тело JSON-RPC запроса: не больше limit байт; null - превышено. */
function readBody(raw, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0; let done = false;
    const finish = (fn, v) => { if (!done) { done = true; fn(v); } };
    raw.on('data', (c) => {
      if (done) return;
      n += c.length;
      if (n > limit) { raw.pause(); finish(resolve, null); } else chunks.push(c);
    });
    raw.on('end', () => finish(resolve, Buffer.concat(chunks)));
    raw.on('error', (e) => finish(reject, e));
    raw.on('close', () => finish(reject, new Error('aborted')));
  });
}

function pickHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) {
    const lk = k.toLowerCase();
    if (RESP_HEADERS.has(lk) || RESP_HEADER_PREFIXES.some((p) => lk.startsWith(p))) out[lk] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

const AGG_MAX = 10000; // записей агрегации журнала

export async function mcpPlugin(fastify, { repo, catalog, requests, grants, access, proxy, limits, config, logger, now = Date.now, control = null }) {
  const sessions = new Map(); // id -> session
  const failLimiter = createLimiter({ limit: 20, windowSec: 60 }); // неудачная аутентификация по IP
  const tagOf = (id) => sha256hex(String(id)).slice(0, 8);
  const hostOk = new Set();
  try {
    hostOk.add(new URL(config.publicUrl).hostname.toLowerCase());
  } catch { /* publicUrl проверяется в config */ }
  if (['127.0.0.1', 'localhost', '::1', '[::1]'].includes(String(config.host).toLowerCase())) ['127.0.0.1', 'localhost', '[::1]'].forEach((h) => hostOk.add(h));
  const originOk = new Set((config.mcpOrigins || []).map((o) => String(o).trim().replace(/\/+$/, '').toLowerCase()).filter(Boolean));

  // ---- агрегация записей audit и логов: не чаще раза в минуту на ключ ----
  // Карта ограничена: при переполнении уходит самая старая запись, без прохода по всей карте.
  // Записи об анонимах идут через общий бюджет: смена адреса создаёт новый ключ, и без него журнал растёт на каждый запрос.
  // У записей об известных агентах бюджета нет: поток анонимных запросов не должен их вытеснять.
  const agg = new Map();
  const anonWrites = createLimiter({ limit: 60, windowSec: 60 });
  function aggregated(key, write, anonymous = false) {
    const t = now();
    const s = agg.get(key) || { last: -Infinity, skipped: 0 };
    if (t - s.last < 60_000) { s.skipped += 1; agg.set(key, s); return; }
    if (!anonymous || anonWrites.take('write')) write(s.skipped);
    agg.delete(key);
    agg.set(key, { last: t, skipped: 0 });
    if (agg.size > AGG_MAX) agg.delete(agg.keys().next().value);
  }
  const denied = (reason, who, actor, meta = {}) => aggregated(`d:${reason}:${who}`, (count) => {
    repo.audit(actor, 'mcp.denied', null, { via: 'mcp', reason, ...meta, ...(count > 0 && { count }) });
  }, actor === 'system');

  // ---- сессии ----
  const agentSessions = (agentId) => { let n = 0; for (const s of sessions.values()) if (s.agentId === agentId) n++; return n; };

  async function closeSession(s, reason) {
    if (s.closed) return;
    s.closed = true;
    if (s.id) sessions.delete(s.id);
    const n = s.tokens.size;
    s.tokens.clear();
    s.abort.abort(); // прерывает идущие call: их lease освобождает ядро по потоку
    if (s.id) {
      try { repo.audit(`agent:${s.agentId}`, 'mcp.session.close', s.tag, { via: 'mcp', session: s.tag, reason, tokens: n }); }
      catch (e) { logger.error({ err: e?.message, code: e?.code }, 'mcp.session.close audit failed'); }
    }
    try { await s.server.close(); } catch { /* уже закрыт */ }
  }

  function sweep() {
    const t = now();
    for (const s of [...sessions.values()]) {
      const a = repo.getAgent(s.agentId);
      if (!a || a.enabled !== 1) closeSession(s, 'agent_disabled');
      else if (t - s.lastSeen > config.mcpIdleSec * 1000) closeSession(s, 'idle');
      else if (t - s.createdAt > config.mcpMaxLifetimeSec * 1000) closeSession(s, 'lifetime');
    }
  }
  const sweepTimer = setInterval(() => { try { sweep(); } catch (e) { logger.error({ err: e?.message }, 'mcp.sweep'); } }, (config.mcpSweepSec || 30) * 1000);
  sweepTimer.unref();

  async function closeAll(reason) { await Promise.all([...sessions.values()].map((s) => closeSession(s, reason))); }
  if (control) Object.assign(control, { sweep, closeAll, count: () => sessions.size, aggSize: () => agg.size });
  fastify.addHook('onClose', async () => { clearInterval(sweepTimer); await closeAll('shutdown'); });

  // ---- токены сессии ----
  function bind(session, agent, grant, token, requestId, extra = {}) {
    const cred = repo.getCredential(grant.credential_id);
    session.tokens.set(grant.credential_id, { token, grantId: grant.id, requestId, expiresAt: grant.expires_at, provider: cred?.provider });
    repo.audit(`agent:${agent.id}`, 'mcp.token.bind', grant.id, { via: 'mcp', session: session.tag, credential: grant.credential_id, request: requestId, ...extra });
  }
  const currentAgent = (session) => { const a = repo.getAgent(session.agentId); return a && a.enabled === 1 ? a : null; };
  const usableKeys = (agent, provider) => repo.listCredentials().filter((c) => c.provider === provider.slug && repo.agentCanUse(agent.id, c.id));

  // ---- инструменты ----
  function listServices(session, agent) {
    const services = [];
    for (const provider of catalog.list()) {
      const creds = usableKeys(agent, provider);
      if (!creds.length) continue;
      services.push({
        slug: provider.slug, name: provider.name,
        credentials: creds.map((c) => {
          const flt = compileFilter(c.filter, provider);
          let filter = null;
          if (flt) {
            const n = normalizeFilter(c.filter, provider);
            filter = { methods: flt.methods, fields: n.enabled ? [...new Set([...Object.values(n.entities).flat(), ...n.fields])] : [], ...(flt.readOnly && { read_only: true }), ...(flt.mask && { mask: true }) };
          }
          const entry = session.tokens.get(c.id);
          const g = entry ? repo.getGrant(entry.grantId) : null;
          const live = g && !g.revoked_at && g.expires_at > Math.floor(Date.now() / 1000);
          return {
            id: c.id, label: c.label, usable: requests.credentialUsable(c) === null, mode: c.mode, max_ttl: c.max_ttl, max_calls: c.max_calls, filter,
            access: live ? { state: 'active', expires_at: g.expires_at, calls_left: Math.max(0, g.max_calls - g.calls_used) } : { state: 'none' },
          };
        }),
      });
    }
    return ok({ services });
  }

  // Что агент увидит по ключу (п. 7.3): { filter } или {}; без секретов — типы, методы, имена полей
  const filterOf = (cred) => {
    try { const f = cred && describeFilter(cred.filter, catalog.get(cred.provider)); return f ? { filter: f } : {}; } catch { return {}; }
  };

  function requestAccess(session, agent, a) {
    if (!isStr(a.service) || !isStr(a.reason)) return fail('bad_request');
    for (const k of ['ttl', 'calls', 'credential_id']) if (a[k] !== undefined && a[k] !== null && (k === 'credential_id' ? typeof a[k] !== 'string' : typeof a[k] !== 'number')) return fail('bad_request');
    if (!limits.requests.take(agent.id)) return fail('rate_limited');
    const provider = catalog.get(a.service);
    if (!provider) return fail('unknown_provider');
    const pick = access.pickCredential({ agent, provider, credentialId: a.credential_id || undefined });
    if (!pick.ok) return pick.error === 'credential_id_required' ? fail(pick.error, { credentials: pick.credentials }) : fail('no_credential');
    const cred = pick.credential;
    // активный пропуск этого агента на этот ключ подхватывается без новой заявки (решение 1)
    const existing = repo.listActiveGrants().filter((g) => g.agent_id === agent.id && g.credential_id === cred.id).sort((x, y) => y.expires_at - x.expires_at)[0];
    if (existing && requests.credentialUsable(cred) === null) {
      bind(session, agent, existing, grants.reissueToken(existing).token, existing.request_id, { reuse: true });
      return ok({ status: 'approved', credential_id: cred.id, expires_at: existing.expires_at, max_calls: existing.max_calls, ...filterOf(cred) });
    }
    const r = requests.submit({ agent, credential: cred, ttl: a.ttl, calls: a.calls, reason: a.reason, via: 'mcp' });
    if (r.kind === 'granted') {
      bind(session, agent, r.grant, r.token, r.grant.request_id);
      return ok({ status: 'approved', credential_id: cred.id, expires_at: r.grant.expires_at, max_calls: r.grant.max_calls, ...filterOf(cred) });
    }
    if (r.kind === 'pending') return ok({ status: 'pending', request_id: r.requestId, poll_after: POLL_AFTER });
    if (r.kind === 'too_many_pending') return fail('too_many_pending');
    if (r.kind === 'denied') return fail('denied', { reason: r.reason });
    return fail(String(r.error || 'internal'));
  }

  function checkRequest(session, agent, a) {
    if (!isStr(a.request_id)) return fail('bad_request');
    if (!limits.poll.take(`${agent.id}:${a.request_id}`)) return fail('rate_limited', { poll_after: POLL_AFTER });
    const r = repo.getRequest(a.request_id);
    if (!r || r.agent_id !== agent.id) return fail('not_found');
    if (r.status === 'pending') return ok({ status: 'pending', poll_after: POLL_AFTER });
    if (r.status === 'approved') {
      const grant = repo.listActiveGrants().find((g) => g.request_id === r.id && g.agent_id === agent.id);
      if (!grant) return ok({ status: 'revoked' });
      bind(session, agent, grant, grants.reissueToken(grant).token, r.id);
      return ok({ status: 'approved', credential_id: grant.credential_id, expires_at: grant.expires_at, max_calls: grant.max_calls, ...filterOf(repo.getCredential(grant.credential_id)) });
    }
    return ok({ status: r.status });
  }

  async function callTool(session, agent, a, extra) {
    const method = typeof a.method === 'string' ? a.method.toUpperCase() : '';
    if (!METHODS.has(method)) return fail('bad_method');
    if (!isStr(a.service) || typeof a.path !== 'string') return fail('bad_request');
    if (session.inflight >= config.mcpCallParallel) return fail('too_many_calls');
    const provider = catalog.get(a.service);
    // демо-каталог из одного провайдера: любой другой сервис — unknown_service (контракт rest-demo-notify.md); вне демо код прежний
    if (!provider) return fail(config.demo ? 'unknown_service' : 'unknown_provider');

    // ключ: явный или единственный, на который у сессии есть пропуск
    let credentialId;
    if (a.credential_id !== undefined && a.credential_id !== null) {
      if (typeof a.credential_id !== 'string') return fail('bad_request');
      credentialId = a.credential_id;
    } else {
      const own = [...session.tokens.entries()].filter(([, e]) => e.provider === provider.slug);
      if (own.length > 1) return fail('credential_id_required', { credentials: own.map(([id]) => ({ id, label: repo.getCredential(id)?.label ?? id })) });
      if (own.length === 1) credentialId = own[0][0];
    }
    const entry = credentialId !== undefined ? session.tokens.get(credentialId) : null;
    if (!entry || entry.provider !== provider.slug) return fail('no_grant', { hint: 'call request_access first' });

    // путь и query
    if (a.path.includes('#') || !a.path.startsWith('/')) return fail('bad_path');
    const qi = a.path.indexOf('?');
    const path = qi >= 0 ? a.path.slice(0, qi) : a.path;
    const query = qi >= 0 ? a.path.slice(qi) : '';

    // заголовки
    const headers = {};
    if (a.headers !== undefined && a.headers !== null) {
      if (typeof a.headers !== 'object' || Array.isArray(a.headers)) return fail('bad_headers');
      const ents = Object.entries(a.headers);
      if (ents.length > MAX_HEADERS) return fail('bad_headers');
      for (const [k, v] of ents) {
        // eslint-disable-next-line no-control-regex
        if (!HEADER_NAME_RE.test(k) || typeof v !== 'string' || v.length > MAX_HEADER_VALUE || /[\u0000-\u001f\u007f]/.test(v)) return fail('bad_headers');
        headers[k.toLowerCase()] = v;
      }
    }

    // тело
    let body = null;
    if (a.body !== undefined && a.body !== null) {
      if (method === 'GET') return fail('bad_request');
      if (typeof a.body === 'string') body = Buffer.from(a.body, 'utf8');
      else {
        body = Buffer.from(JSON.stringify(a.body), 'utf8');
        if (!headers['content-type']) headers['content-type'] = 'application/json';
      }
      if (body.length > Math.min(provider.maxBody, config.mcpBodyLimit)) return fail('body_too_large');
    }

    const signal = extra?.signal ? AbortSignal.any([session.abort.signal, extra.signal]) : session.abort.signal;
    session.inflight += 1;
    let result;
    try {
      result = await proxy.call({
        token: entry.token, provider: provider.slug, expectAgentId: session.agentId, expectCredentialId: credentialId,
        method, path, query, headers, body, contentLength: body ? body.length : null,
        signal, via: 'mcp', sessionTag: session.tag,
      });
      if (!result.ok) {
        // отозванный или истёкший пропуск: запись сессии больше не годится (следующий вызов -> no_grant)
        if (result.error === 'invalid_grant') session.tokens.delete(credentialId);
        return fail(result.error, { status: result.status, ...result.extra, ...(result.retryAfter && { retry_after: result.retryAfter }) });
      }
      let read;
      try { read = await readLimited(result.body, config.mcpMaxResponse); } catch { return fail('upstream_unreachable', { status: 502 }); }
      const type = String(result.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      const bytes = read.buf.length;
      const out = { status: result.status, headers: pickHeaders(result.headers), body: null, truncated: read.over, bytes };
      if (bytes === 0) out.body = '';
      else if (TEXT_TYPE_RE.test(type)) out.body = (read.over ? cutUtf8(read.buf) : read.buf).toString('utf8');
      else out.binary = true;
      return ok(out);
    } finally {
      session.inflight -= 1;
      result?.ok && result.body.destroy();
    }
  }

  function makeServer(session) {
    const server = new Server({ name: pkg.name, version: pkg.version }, { capabilities: { tools: {} }, instructions: INSTRUCTIONS });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const name = request.params?.name;
      const args = request.params?.arguments && typeof request.params.arguments === 'object' ? request.params.arguments : {};
      try {
        const agent = currentAgent(session);
        if (!agent) return fail('unauthorized');
        if (name === 'list_services') return listServices(session, agent);
        if (name === 'request_access') return requestAccess(session, agent, args);
        if (name === 'check_request') return checkRequest(session, agent, args);
        if (name === 'call') return await callTool(session, agent, args, extra);
        return fail('unknown_tool');
      } catch (e) {
        logger.error({ err: e?.message, code: e?.code, tool: String(name).slice(0, 32) }, 'mcp tool failed');
        return fail('service_unavailable');
      }
    });
    server.onclose = () => { closeSession(session, 'client'); };
    return server;
  }

  // ---- HTTP ----
  // Тело читаем сами (после проверок и с лимитом), поэтому парсеры Fastify отдают сырой поток
  fastify.removeContentTypeParser(['application/json', 'text/plain']);
  fastify.addContentTypeParser('application/json', (req, payload, done) => done(null, payload));
  fastify.addContentTypeParser('*', (req, payload, done) => done(null, payload));
  fastify.setErrorHandler((err, req, reply) => {
    if (err.code === 'FST_ERR_CTP_BODY_TOO_LARGE') return reply.code(413).send({ error: 'payload_too_large' });
    return sendApiError(err, req, reply, logger);
  });

  const bearer = (req) => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7).trim() : null; };

  async function handle(req, reply) {
    const send = (status, error, extra) => reply.code(status).send({ error, ...extra });
    const ip = clientKey(req.ip); // IPv6 сведён к /64, как на сайте: смена адреса внутри сети не даёт новых ключей

    // 1. Host/Origin (DNS rebinding): до тела и до аутентификации
    const host = hostnameOf(req.headers.host);
    if (!host || !hostOk.has(host)) {
      denied('host', ip, 'system');
      return send(403, 'host_not_allowed');
    }
    const origin = req.headers.origin;
    if (origin !== undefined && !originOk.has(String(origin).trim().replace(/\/+$/, '').toLowerCase())) {
      denied('origin', ip, 'system');
      return send(403, 'origin_not_allowed');
    }

    // 2. Bearer gwa_ на каждом запросе
    const sidHeader = typeof req.headers['mcp-session-id'] === 'string' ? req.headers['mcp-session-id'] : null;
    const agent = authAgent(repo, bearer(req));
    if (!agent) {
      // выключенный агент: его сессия закрывается на первом же запросе
      const known = sidHeader ? sessions.get(sidHeader) : null;
      if (known) { const a = repo.getAgent(known.agentId); if (!a || a.enabled !== 1) closeSession(known, 'agent_disabled'); }
      aggregated(`u:${ip}`, (count) => logger.warn({ ip, count: count + 1 }, 'mcp unauthorized'), true);
      reply.header('www-authenticate', 'Bearer');
      if (!failLimiter.take(ip)) return send(429, 'rate_limited');
      return send(401, 'unauthorized');
    }
    repo.touchAgent(agent.id); // успешная авторизация агента: last_seen_at (repo сам держит раз в минуту)

    // 3. лимит запросов на агента
    if (!limits.mcp.take(agent.id)) return send(429, 'rate_limited');

    // 4. сессия
    const method = req.method;
    let session = null;
    if (sidHeader !== null) {
      session = sessions.get(sidHeader) || null;
      if (!session || session.agentId !== agent.id) {
        denied('session_mismatch', agent.id, `agent:${agent.id}`, { session: tagOf(sidHeader) });
        return send(404, 'session_not_found');
      }
      if (method === 'DELETE') {
        await closeSession(session, 'client');
        return reply.code(200).send();
      }
    } else if (method !== 'POST') {
      return send(400, 'session_required');
    }

    // 5. размер тела до чтения и разбора
    let parsed;
    if (method === 'POST') {
      const cl = Number(req.headers['content-length']);
      // длина известна: тело не разбираем, но вычитываем в никуда, чтобы клиент дописал запрос и увидел 413, а не сброс соединения
      if (Number.isFinite(cl) && cl > config.mcpBodyLimit) { req.raw.resume(); return send(413, 'payload_too_large'); }
      let buf;
      try { buf = await readBody(req.raw, config.mcpBodyLimit); } catch { return send(400, 'bad_request'); }
      if (buf === null) { reply.header('connection', 'close'); return send(413, 'payload_too_large'); }
      try { parsed = JSON.parse(buf.toString('utf8')); } catch {
        return reply.code(400).send({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
      }
    }

    // новая сессия: только initialize
    if (!session) {
      if (!isInitializeRequest(parsed)) return send(400, 'session_required');
      if (agentSessions(agent.id) >= config.mcpMaxSessionsPerAgent || sessions.size >= config.mcpMaxSessions) {
        denied('too_many_sessions', agent.id, `agent:${agent.id}`);
        return send(429, 'too_many_sessions');
      }
      const s = { id: null, tag: null, agentId: agent.id, createdAt: now(), lastSeen: now(), abort: new AbortController(), tokens: new Map(), inflight: 0, closed: false, transport: null, server: null };
      const clientInfo = parsed?.params?.clientInfo;
      const client = clientInfo && typeof clientInfo === 'object' ? `${String(clientInfo.name ?? '')} ${String(clientInfo.version ?? '')}`.trim().slice(0, 64) : '';
      s.transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomBytes(16).toString('hex'),
        enableJsonResponse: true,
        onsessioninitialized: (id) => {
          s.id = id; s.tag = tagOf(id);
          sessions.set(id, s);
          repo.audit(`agent:${agent.id}`, 'mcp.session.open', s.tag, { via: 'mcp', session: s.tag, client });
        },
      });
      s.server = makeServer(s);
      await s.server.connect(s.transport);
      reply.hijack();
      try { await s.transport.handleRequest(req.raw, reply.raw, parsed); } catch (e) {
        logger.error({ err: e?.message }, 'mcp transport failed');
        if (!reply.raw.headersSent) { reply.raw.statusCode = 500; reply.raw.end(); }
      }
      if (!s.id) { s.closed = true; try { await s.server.close(); } catch { /* не успел открыться */ } }
      return reply;
    }

    // 6. lastSeen и передача в транспорт
    session.lastSeen = now();
    reply.hijack();
    try { await session.transport.handleRequest(req.raw, reply.raw, parsed); } catch (e) {
      logger.error({ err: e?.message }, 'mcp transport failed');
      if (!reply.raw.headersSent) { reply.raw.statusCode = 500; reply.raw.end(); }
    }
    return reply;
  }

  for (const m of ['POST', 'GET', 'DELETE']) {
    fastify.route({
      method: m, url: '/mcp',
      handler: async (req, reply) => {
        try { return await handle(req, reply); } catch (e) {
          if (reply.sent || reply.raw.headersSent) { logger.error({ err: e?.message }, 'mcp failed after reply'); return reply; }
          return sendApiError(e, req, reply, logger);
        }
      },
    });
  }
}
