// API для агентов (ТЗ §8): /v1/grants, /v1/grants/:id, /v1/proxy/:provider/*
import { sendApiError } from '../core/infra.js';
import { authAgent, sha256hex } from '../core/access.js';
import { describeFilter } from '../core/filter.js';

export { sha256hex };

export async function agentApi(fastify, { repo, catalog, requests, grants, proxy, access, limits, logger }) {
  // у плагина свой контекст: обработчик корня сюда не доходит, ошибки /v1/* (в т.ч. сбой базы -> 503) разбираем здесь (П-30)
  fastify.setErrorHandler((err, req, reply) => sendApiError(err, req, reply, logger));
  const limiter = limits.requests;
  const pollLimiter = limits.poll;

  // Ответы /v1/* не кэшируются нигде (Cloudflare, прокси по пути): заголовок сервиса перезаписываем.
  // Хук корневого приложения сюда не доходит — у плагина свой контекст.
  fastify.addHook('onSend', async (req, reply, payload) => {
    reply.header('cache-control', 'private, no-store');
    reply.header('x-content-type-options', 'nosniff');
    return payload;
  });

  // Тело прокси — сырой поток; JSON парсим только для /grants
  // Встроенный разбор text/plain вычитывает поток и теряет тело прокси: убираем, дальше работает '*'
  fastify.removeContentTypeParser('text/plain');
  fastify.addContentTypeParser('*', (req, payload, done) => done(null, payload));
  fastify.removeContentTypeParser('application/json');
  fastify.addContentTypeParser('application/json', (req, payload, done) => {
    if (req.url.startsWith('/v1/proxy/')) return done(null, payload);
    // сверх 64 KiB — 413; поток дочитывается вхолостую, а не рвётся: разрыв давал 502 у Caddy и запись в его журнал (ревью staging R-3)
    let data = ''; let n = 0; let over = false;
    payload.on('data', (c) => {
      if (over) return;
      n += c.length;
      if (n > 65536) { over = true; data = ''; done(Object.assign(new Error('body too large'), { statusCode: 413 })); return; }
      data += c;
    });
    payload.on('end', () => { if (over) return; try { done(null, data ? JSON.parse(data) : {}); } catch { done(Object.assign(new Error('bad json'), { statusCode: 400 })); } });
    payload.on('error', done);
  });

  // Что агент увидит по ключу: { filter } или {} (фильтра нет); описание без секретов — типы, методы, имена полей
  const filterOf = (cred) => {
    try { const f = cred && describeFilter(cred.filter, catalog.get(cred.provider)); return f ? { filter: f } : {}; } catch { return {}; }
  };

  const bearer = (req) => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7).trim() : null; };

  function requireAgent(req, reply) {
    const a = authAgent(repo, bearer(req));
    if (!a) { reply.code(401); return null; }
    if (!limiter.take(a.id)) { reply.code(429); return null; }
    repo.touchAgent(a.id); // успешная авторизация агента: last_seen_at (repo сам держит раз в минуту)
    return a;
  }

  fastify.post('/v1/grants', async (req, reply) => {
    const agent = requireAgent(req, reply);
    if (!agent) return { error: reply.statusCode === 429 ? 'rate_limited' : 'unauthorized' };
    const b = req.body || {};
    const provider = catalog.get(String(b.provider || ''));
    if (!provider) { reply.code(400); return { error: 'unknown_provider' }; }
    // Агент видит только привязанные к нему ключи; чужой ключ неотличим от несуществующего.
    const pick = access.pickCredential({ agent, provider, credentialId: b.credential_id });
    if (!pick.ok) {
      if (pick.error === 'credential_id_required') { reply.code(400); return { error: pick.error, credentials: pick.credentials }; }
      reply.code(403); return { error: 'no_credential' };
    }
    const r = requests.submit({ agent, credential: pick.credential, ttl: b.ttl, calls: b.calls, reason: b.reason, via: 'rest' });
    if (r.kind === 'granted') return { status: 'approved', token: r.token, expires_at: r.grant.expires_at, max_calls: r.grant.max_calls, ...filterOf(pick.credential) };
    if (r.kind === 'pending') { reply.code(202); return { status: 'pending', request_id: r.requestId, poll_after: 5 }; }
    if (r.kind === 'too_many_pending') { reply.code(429); return { error: 'too_many_pending' }; }
    reply.code(403); return { error: 'denied', reason: r.reason };
  });

  fastify.get('/v1/grants/:id', async (req, reply) => {
    const agent = requireAgent(req, reply);
    if (!agent) return { error: 'unauthorized' };
    if (!pollLimiter.take(`${agent.id}:${req.params.id}`)) { reply.code(429); return { error: 'rate_limited', poll_after: 5 }; }
    const r = repo.getRequest(req.params.id);
    if (!r || r.agent_id !== agent.id) { reply.code(404); return { error: 'not_found' }; }
    if (r.status === 'approved') {
      const grant = repo.listActiveGrants().find((g) => g.request_id === r.id);
      if (!grant) { reply.code(410); return { status: 'revoked' }; }
      // токен выдаём один раз: после первой выдачи помечаем в meta
      const k = `token_issued:${r.id}`;
      if (repo.getMeta(k)) { reply.code(410); return { status: 'approved', error: 'token_already_issued' }; }
      repo.setMeta(k, '1');
      const cred = repo.getCredential(r.credential_id);
      const { token } = grants.reissueToken ? grants.reissueToken(grant) : { token: null };
      return { status: 'approved', token, expires_at: grant.expires_at, max_calls: grant.max_calls, credential: cred?.id, ...filterOf(cred) };
    }
    if (r.status === 'pending') { reply.code(202); return { status: 'pending', poll_after: 5 }; }
    reply.code(403); return { status: r.status };
  });

  fastify.all('/v1/proxy/:provider/*', async (req, reply) => {
    // права проверяет access.authorizeCall внутри proxy.call (П-15), здесь только разбор запроса и отдача результата
    // сырой путь из URL (Fastify декодирует wildcard, нам нужен как есть); query отдельно
    // имя провайдера в каталоге без «%»: закодированное имя ломает отрезание префикса (путь превращался в «/»)
    const rawUrl = req.raw.url || req.url;
    const rawProvider = rawUrl.slice('/v1/proxy/'.length).split(/[/?]/)[0];
    if (rawProvider.includes('%')) { reply.code(400); return { error: 'bad_path' }; }
    const prefix = `/v1/proxy/${req.params.provider}`;
    const upstreamPath = rawUrl.startsWith(prefix) ? rawUrl.slice(prefix.length).split('?')[0] || '/' : '/';
    const qi = rawUrl.indexOf('?');
    const clHeader = req.headers['content-length'];

    // обрыв клиента: отмена запроса к сервису и разрушение потока тела (lease снимает ядро по потоку, П-11)
    const ac = new AbortController();
    let resBody = null;
    let closed = false;
    reply.raw.once('close', () => {
      closed = true;
      if (!reply.raw.writableEnded) ac.abort();
      resBody?.destroy();
    });

    const result = await proxy.call({
      token: bearer(req), provider: req.params.provider,
      method: req.method, path: upstreamPath, query: qi >= 0 ? rawUrl.slice(qi) : '',
      headers: req.headers, body: req.raw, contentLength: clHeader ? Number(clHeader) : null,
      signal: ac.signal, via: 'rest',
    });
    if (!result.ok) {
      reply.code(result.status);
      if (result.retryAfter) reply.header('retry-after', String(result.retryAfter));
      return { error: result.error, ...result.extra };
    }
    resBody = result.body;
    if (closed) { result.body.destroy(); return reply; }
    reply.code(result.status);
    for (const [k, v] of Object.entries(result.headers)) reply.header(k, v);
    return reply.send(result.body);
  });
}
