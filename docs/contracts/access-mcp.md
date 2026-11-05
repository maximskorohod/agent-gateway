# Контракт A: авторизация вызова, транспортно-независимый прокси, MCP-сервер

Черновик контрактов (только документ). Закрывает П-15, П-16, часть П-34 (ТЗ-release §10, §11, §21). Стиль и обозначения как в `docs/ARCHITECTURE.md`. После утверждения разделы переносятся в ARCHITECTURE (`core/access.js` новый; `core/proxy.js`, `api/agents.js` заменяются; `mcp/server.js` новый; `core/requests.js`: `submit` получает `via`).

Исходное положение (код до правок): проверки вызова (токен, ключ существует и принадлежит провайдеру из URL, `agentCanUse`, `credentialUsable`) стоят в обработчике `ANY /v1/proxy/:provider/*`; `agent.enabled` на вызове не проверяется вообще (спасает только `setAgentEnabled(0)` -> revoke грантов); `proxy.handle` принимает Fastify `req/reply`.

## core/access.js

```js
export function createAccess({ repo, catalog, grants, requests })
// -> {
//   authorizeCall({ token, provider, agentId?, credentialId? })
//        // СИНХРОННАЯ. -> { ok:true, agent, grant, credential, provider }
//        //             | { ok:false, code:'invalid_grant', reason:string }
//   pickCredential({ agent, provider /* Provider */, credentialId? })
//        // -> { ok:true, credential } | { ok:false, error:'credential_id_required', credentials:[{id,label}] }
//        //                            | { ok:false, error:'no_credential' }
// }
```

`authorizeCall`, порядок проверок (дешёвые первыми, первая неудача возвращает):
1. `grants.verifyToken(token)` (подпись, срок, `repo.getGrant`, не revoked) -> иначе `reason:'token'`.
2. `repo.getAgent(grant.agent_id)` существует и `enabled === 1` -> иначе `reason:'agent_disabled'`.
3. Если передан `agentId` (MCP: агент сессии) - `grant.agent_id === agentId`, иначе `reason:'agent_mismatch'`.
4. `repo.getCredential(grant.credential_id)` (без deleted) -> `reason:'key_missing'`. Если передан `credentialId` - совпадает с `grant.credential_id` -> `reason:'credential_mismatch'`.
5. `catalog.get(credential.provider)` существует и `slug === provider` (slug из URL или аргумента `call`) -> `reason:'provider_mismatch'`.
6. `repo.agentCanUse(agent.id, credential.id)` -> `reason:'not_bound'`.
7. `requests.credentialUsable(credential)` (срок ключа, mode, окно) -> `reason:'key_unusable'`.

Правила:
- Снаружи (REST-тело, MCP) любой отказ - один код `invalid_grant`, 401; различия видны только в `reason` для `logger.debug` и audit-мета. Это сохраняет сегодняшнюю неразличимость (ТЗ §8).
- Функция синхронная и без I/O кроме SQLite: между `authorizeCall` и `grants.reserve` в `proxy.call` нет `await` (иначе окно для отзыва; сам `reserveCall` остаётся последним решающим барьером: отозванный/истёкший grant резерв не получит).
- Секреты, значения токена и хост не попадают в `reason`.
- Вызывается ТОЛЬКО из `proxy.call` (шаг 1). Транспорты свои проверки не дублируют и не могут их пропустить: у `call` нет входа без `token`.

`pickCredential` - вынесенная логика выбора ключа из `POST /v1/grants`: ключи провайдера, доступные агенту по `agentCanUse`; явный `credentialId` не из доступных неотличим от несуществующего (`no_credential`); без `credentialId` и ровно один доступный - он; два и больше - `credential_id_required` + список `{id,label}` (без прочих полей); ноль - `no_credential`. Используется в REST `POST /v1/grants` и в MCP `request_access`/`call`.

## core/proxy.js (новый)

```js
export function createProxy({ repo, catalog, vault, grants, access, limits, logger, testUpstream = null })
// limits.proxy - createLimiter, один экземпляр на процесс (создаётся в app.js, общий для REST и MCP)
// -> { call(input) -> Promise<CallResult> }   // handle(req, reply, …) удаляется

/** @typedef {{
 *   token:string,                         // gwt_… ; единственный источник прав
 *   provider:string,                      // slug (из URL или из аргумента MCP)
 *   expectAgentId?:string, expectCredentialId?:string,   // MCP: сверка с сессией
 *   method:string,
 *   path:string,                          // СЫРОЙ путь, начинается с '/', без '?' и '#'
 *   query:string,                         // '' или '?a=b' (сырая строка)
 *   headers:Record<string,string|string[]>,  // имена в нижнем регистре
 *   body:Buffer|import('node:stream').Readable|null,
 *   contentLength:number|null,            // null = неизвестна (только у Readable)
 *   signal?:AbortSignal,                  // обрыв клиента / закрытие MCP-сессии
 *   via:'rest'|'mcp', sessionTag?:string  // для audit (sessionTag = 8 hex от sha256(session id))
 * }} CallInput */

/** @typedef {{ ok:false, status:number, error:string, extra?:object }
 *          | { ok:true, status:number, headers:Record<string,string|string[]>,
 *              body:import('node:stream').Readable }} CallResult */
```

Порядок шагов (как сегодня, плюс шаг 2 - лимит частоты; нумерация = порядок выполнения):
1. `access.authorizeCall(...)` - 401 `invalid_grant` (без audit, как сегодня).
2. `limits.proxy.take(agent.id)` - 429 `rate_limited`. Стоит ПЕРЕД фильтром, аудитом и сейфом (П-34); ключ - `agent.id` из шага 1.
3. Пути (П-1): `decodeURIComponent` (ошибка -> 400 `bad_path`), `validateAgentPath` для сырого и декодированного, `%` в декодированном -> 400 `bad_path`. Новое: `query` без управляющих символов и ≤ 4096, иначе 400 `bad_query`.
4. Фильтр: `compileFilter(credential.filter, provider)`, `allowMethod(decodedPath)` -> 403 `method_not_allowed` + `extra:{allowed}`; квота не тратится; audit `proxy.denied`. Повторные отказы одного агента: audit пишется не чаще раза в минуту на (agent, credential), остальные считаются в памяти и дописываются в мету следующей записи как `count` (П-34, агрегация).
5. Длина тела: `contentLength > provider.maxBody` -> 413 `body_too_large` (до резерва).
6. `grants.reserve(grant.id)` -> null: 429 `quota_exceeded`. Дальше любой выход обязан освободить lease (см. ниже).
7. Таймеры: `extend` каждые 30 с; общий `AbortController` на `provider.timeout`, объединённый с `input.signal` через `AbortSignal.any`.
8. `vault.get(cred/<id>)`; нет секрета -> 401 `invalid_grant` + audit `proxy.no_secret`.
9. Заголовки: тот же `HOP`-список, `catalog.redactHeaders()`, `accept-encoding: identity`, `extraHeaders`, инъекция ключа (header перезаписывает имя в нижнем регистре, path подставляет шаблон). `authorization` агента не передаётся. Логика одна, транспорты её не копируют.
10. Тело: при фильтре читается целиком (≤ `maxBody`, иначе `body_too_large`), `rewriteSelect`; без фильтра `Buffer` уходит как есть, `Readable` - через счётчик с лимитом `maxBody`. Для `GET/HEAD` тела нет.
11. `undici.request` (safeLookup, без редиректов), `signal`, `headersTimeout/bodyTimeout = provider.timeout`.
12. Ответ: `Content-Encoding` ≠ identity -> 502 `upstream_encoded` до отдачи байтов (П-4). Заголовки ответа: `RESP_DROP` убирается, значения через `redactText(secret)`. Фильтр: целиком в `maxBody`, не JSON -> 502 `filtered_non_json`, больше -> 502 `filtered_too_large`, иначе `filterBody` + `redactText`, `fields_removed:N`. Без фильтра - потоковый редактор секрета. Результат - всегда `Readable` (для фильтра `Readable.from(Buffer)`).
13. Audit `proxy.call` пишется, как сегодня, когда известен статус (не после тела): `{grant, agent, credential, provider, status, ms, via, session?, fields_removed?}`; цель `METHOD provider<maskPath>`.

Ошибки до шага 6 возвращаются как `{ok:false,…}` без lease. Ошибки после 6 (в т.ч. 413/502/401 из шага 8) освобождают lease и таймеры сами перед возвратом `{ok:false}`.

### Кто освобождает lease (П-11), в том числе для MCP

Единственный владелец - `core/proxy.js`. Привязка к потоку тела, а не к HTTP-ответу:
- При `ok:true` ядро вешает на `result.body` `stream.finished(body, done)`; `done` = `clearInterval(extend)`, `clearTimeout(deadline)`, `grants.release(leaseId)`, ровно один раз (флаг). Срабатывает при обычном конце, ошибке, `destroy()`, abort.
- `ok:false` после резерва: `done()` вызывается до `return`.
- Потребитель обязан дочитать тело до конца ИЛИ вызвать `body.destroy()`. Дочитывать молча не нужно: `destroy()` корректен, `done` отработает.
- Fastify-адаптер: `reply.send(body)`; плюс `reply.raw.once('close', () => { if (!reply.raw.writableEnded) abortController.abort(); body.destroy(); })`. Это та же защита, что сегодня (`close` ответа), но через `signal` и поток, а не внутри ядра.
- MCP (`close` у HTTP-ответа нет, ответ инструмента собирается в память): `call`-инструмент читает не больше `mcpMaxResponse + 1` байт, затем в `finally` ВСЕГДА `body.destroy()` (идемпотентно). Закрытие MCP-сессии, отзыв и отмена запроса клиентом (`extra.signal`) приходят через `signal` -> abort upstream -> поток падает -> `done`.
- Страховки: дедлайн `provider.timeout` (abort + `body.destroy`) и `repo.reapLeases()` раз в минуту (lease живёт 60 с без `extend`; `extend` останавливается вместе с `done`).
- Нарушение (потребитель потерял `body` и не прочитал) ограничено `provider.timeout`; тест это проверяет.

## api/agents.js (изменения)

- `agentApi(fastify, { repo, catalog, requests, grants, proxy, access, limits })`. Лимитеры `limits.requests` (30/мин), `limits.poll` (12/мин), `limits.proxy` создаются в `app.js` и общие с MCP (ТЗ §11: MCP - тот же лимит, что заявки и прокси).
- `ANY /v1/proxy/:provider/*` сводится к адаптеру: токен из Bearer, сырой путь и query из `req.raw.url`, тело `req.raw` (`Readable`) и `content-length`, `signal` от обрыва ответа, `via:'rest'`; вызов `proxy.call`; результат -> `reply.code(status)`, заголовки, `reply.send(body)` либо `{ error, …extra }`. Проверок прав в обработчике не остаётся (удаляются `verifyToken`, `getCredential`, `agentCanUse`, `credentialUsable`).
- `POST /v1/grants`: выбор ключа через `access.pickCredential` (тело ответов и коды прежние: 400 `credential_id_required` + `credentials`, 403 `no_credential`, 400 `unknown_provider`); `requests.submit({…, via:'rest'})`.
- `requireAgent` выносится в общий хелпер `authAgent(token)` (хэш, `enabled`), его же использует MCP.
- Контракт `core/requests.js`: `submit({ agent, credential, ttl, calls, reason, via='rest' })`, `via` пишется в meta audit `request.create` и `grant.auto`.

## mcp/server.js

```js
export async function mcpPlugin(fastify, { repo, catalog, requests, grants, access, proxy, limits, config, logger })
// маршруты: POST /mcp, GET /mcp, DELETE /mcp (Streamable HTTP, @modelcontextprotocol/sdk)
// транспорт: StreamableHTTPServerTransport на сессию (stateful), McpServer на сессию; Fastify: reply.hijack(), в SDK уходят req.raw/res.raw
export function createSessionStore({ config, repo, logger }) // внутреннее; наружу не экспортируется
```

Конфиг (`config.js`, env `GW_MCP_*`): `mcpEnabled=true`, `mcpOrigins=[]`, `mcpMaxSessionsPerAgent=5`, `mcpMaxSessions=200`, `mcpIdleSec=900`, `mcpMaxLifetimeSec=86400`, `mcpMaxResponse=65536` (байт, в модель), `mcpBodyLimit=262144` (JSON-RPC тело), `mcpCallParallel=4` (одновременных `call` на сессию).

### Проверки на КАЖДОМ запросе (POST, GET, DELETE), в этом порядке

1. **Host/Origin** (DNS rebinding). `Host` должен совпасть с хостом `config.publicUrl` (и с `127.0.0.1`/`localhost` только если `config.host` loopback), иначе 403 `host_not_allowed`. Если есть заголовок `Origin` - он обязан быть в `config.mcpOrigins` (пусто = любой запрос с `Origin` отвергается), иначе 403 `origin_not_allowed`. Запросы без `Origin` (CLI, десктоп-клиенты) проходят. Это до чтения тела и до аутентификации.
2. **Bearer `gwa_`** через `authAgent`: нет заголовка, не `gwa_`, неизвестен или `enabled=0` -> 401 `unauthorized` с `WWW-Authenticate: Bearer`. Проверяется на каждом запросе, не только на `initialize`. Неудачи считаются по IP (20/мин, потом 429 `rate_limited`).
3. **Лимит запросов** `limits.mcp` 120/мин на агента (до разбора JSON-RPC и любой работы инструментов) -> 429 `rate_limited`.
4. **Сессия** (заголовок `mcp-session-id`):
   - POST без id: допустим только JSON-RPC `initialize`, иначе 400 `session_required`.
   - Любой метод с id: сессия не найдена ИЛИ `session.agentId !== agent.id` -> 404 `session_not_found` (чужая сессия неотличима от несуществующей; audit `mcp.denied` reason `session_mismatch`, actor - предъявивший агент).
   - GET/DELETE без id -> 400 `session_required`.
   - DELETE: закрыть сессию (reason `client`) -> 200.
5. **Размер тела** POST > `mcpBodyLimit` -> 413 `payload_too_large` (до парсинга).
6. Обновить `lastSeen`; передать в транспорт.

Лимиты сессий: `initialize` при `activeSessions(agent) >= mcpMaxSessionsPerAgent` или глобальном лимите -> 429 `too_many_sessions` (старые не вытесняются). Простой: `now - lastSeen > mcpIdleSec` -> закрытие; абсолютный срок `mcpMaxLifetimeSec`. Проверка раз в 30 с (таймер `unref`), заодно проверка `agent.enabled` каждой сессии. Session id - 128 бит `crypto.randomBytes`, в логи/аудит только 8 hex от sha256.

### Состояние сессии (только память процесса)

```js
/** session = { id, agentId, createdAt, lastSeen, abort:AbortController,
 *    tokens:Map<credentialId, { token, grantId, requestId, expiresAt }>,   // expiresAt только для показа
 *    inflight:number } */
```
- Ключ карты - `credentialId`; сессия уже привязана к одному агенту, значит ключ фактически (агент, MCP-сессия, ключ). Две сессии одного агента хранят свои токены отдельно; токен не переходит между сессиями и между агентами.
- Токен попадает в карту: (а) `request_access`, если `requests.submit` вернул `granted`; (б) `check_request`, если заявка `approved`, `request.agent_id === agent.id`, grant активен: `grants.reissueToken(grant)`. Флаг REST `token_issued:*` MCP не трогает. Audit `mcp.token.bind` (`grant`, `credential`, `request`).
- Токен НИКОГДА не возвращается в MCP-клиент: ни в результате инструмента, ни в ошибке, ни в `structuredContent`, ни в логах. Тест ищет подстроку `gwt_` во всех ответах.
- Жизнь токена: не дольше grant. Решение о годности принимает не память, а `access.authorizeCall` на КАЖДОМ `call` - так обнаруживаются отзыв grant (`revokeGrant`, `softDeleteCredential`, смена привязки, `setAgentEnabled(0)`), истечение срока, окно, `agent.enabled=0`. Если `call` получил `invalid_grant`, запись удаляется из `tokens` (следующий вызов -> `no_grant`).
- Уничтожение: закрытие сессии (клиент, idle, lifetime, shutdown), выключение агента (обнаруживается на ближайшем запросе: шаг 2 даёт 401 и сессия закрывается, и таймером раз в 30 с), `tokens.clear()` и `session.abort.abort()` (прерывает идущие `call`, их lease освобождаются по потоку).
- Рестарт процесса теряет все сессии и токены; grant остаётся действовать до срока, клиент получает 404 и делает новый `initialize`.

### Инструменты

Описания инструментов и тексты ошибок для модели - константы на английском (как коды ошибок REST, ТЗ §8), `t()` не используется. Ошибка = `isError:true`, текст `{"error":"<code>", …}`.

| Инструмент | Вход | Выход (JSON в `content[0].text`) |
|---|---|---|
| `list_services` | - | `{services:[{slug,name,credentials:[{id,label,usable:boolean,mode:'always'|'ask',max_ttl,max_calls,filter:{methods,fields}|null,access:{state:'active'|'none',expires_at?,calls_left?}}]}]}` |
| `request_access` | `service`, `credential_id?`, `ttl?`, `calls?`, `reason` | `{status:'approved',credential_id,expires_at,max_calls}` или `{status:'pending',request_id,poll_after:5}` или ошибка |
| `check_request` | `request_id` | `{status:'pending',poll_after:5}` / `{status:'approved',credential_id,expires_at,max_calls}` / `{status:'denied'|'expired'|'revoked'}` |
| `call` | `service`, `method`, `path`, `credential_id?`, `body?`, `headers?` | `{status,headers,body,truncated,bytes}` |

- `list_services`: только сервисы, где у агента есть хотя бы один ключ по `agentCanUse`; значений ключей и host нет; `usable` = `credentialUsable(cred)===null`; `access` строится из `tokens` сессии + `repo.getGrant` (без токена); `filter` - шаблоны методов и пути полей из `compileFilter` (значений нет).
- `request_access`: `access.pickCredential` (ошибки `unknown_provider`, `no_credential`, `credential_id_required` + `credentials:[{id,label}]`, как в `POST /v1/grants`), `limits.requests`, `requests.submit({…, via:'mcp'})`. `denied` -> `{error:'denied', reason}` (reason - текст сервиса, язык владельца, как в REST). `too_many_pending` и прочие коды submit пробрасываются как есть.
- `check_request`: `limits.poll` на (агент, request_id); `repo.getRequest(id)`; `!r || r.agent_id !== agent.id` -> `not_found` (чужая заявка неотличима от несуществующей). Заявка другой сессии того же агента читается (агент один владелец), токен привязывается к текущей сессии.
- `call`:
  1. `method` из `GET|POST|PUT|PATCH|DELETE`, иначе `bad_method`. Не более `mcpCallParallel` одновременных на сессию (`too_many_calls`).
  2. Ключ: `credential_id` явно, иначе единственный доступный агенту ключ сервиса, иначе `credential_id_required` + `credentials:[{id,label}]`.
  3. Токен из `tokens.get(credentialId)`; нет - `no_grant` ("call request_access first"). Токен не найден != отказ доступа, это состояние собственной сессии.
  4. `path` режется по первому `?` на `path` и `query`; `#` -> `bad_path`; путь не с `/` -> `bad_path`.
  5. `body`: строка или JSON-значение; объект сериализуется в `Buffer` (`content-type: application/json`, если не задан); размер ≤ `provider.maxBody` и ≤ `mcpBodyLimit`, иначе `body_too_large`. Для GET `body` недопустим: `bad_request`.
  6. `headers`: объект строк, ≤ 20 штук, значение ≤ 1024 символа, без CR/LF; остальное фильтрует ядро (те же `HOP`, `authorization`, инъекция ключа).
  7. `proxy.call({ token, provider, expectAgentId: session.agentId, expectCredentialId, …, signal: session.abort.signal ⊕ extra.signal, via:'mcp', sessionTag })`.
  8. `ok:false` -> `isError` с `{error, status, …extra}` (те же коды, что в REST: `invalid_grant`, `bad_path`, `bad_query`, `method_not_allowed`+`allowed`, `body_too_large`, `rate_limited`, `quota_exceeded`, `upstream_encoded`, `filtered_non_json`, `filtered_too_large`, `upstream_unreachable`).
  9. `ok:true`: читается `body` не более `mcpMaxResponse + 1` байт, затем `finally { body.destroy() }`. `truncated:true`, если лимит превышен (обрезка по границе символа UTF-8). Секрет уже вычищен потоковым редактором ядра ДО обрезки.
  10. Результат: `status` (статус сервиса, 4xx/5xx сервиса - не `isError`), `headers` - только белый список (`content-type`, `content-language`, `etag`, `last-modified`, `retry-after`, `link`, `x-total-count`, `x-ratelimit-*`), `body` - UTF-8 текст для `text/*`, `application/json`, `*+json`, `application/xml`, `*+xml`, `application/x-www-form-urlencoded`; для прочих типов `body:null, binary:true`, `bytes` - число прочитанных байт.

## Audit для MCP

Actor всегда `agent:<id>`, в мете `via:'mcp'` и `session:<8 hex>`. Тела, значения query, заголовков, содержимое ответов и токены не пишутся; путь через `maskPath`.

| action | target | meta |
|---|---|---|
| `mcp.session.open` | session tag | `client` (name/version из `initialize`, ≤ 64 символов) |
| `mcp.session.close` | session tag | `reason: client\|idle\|lifetime\|agent_disabled\|shutdown`, `tokens: N` |
| `mcp.token.bind` | grant id | `credential`, `request` |
| `mcp.denied` | - | `reason: origin\|host\|session_mismatch\|too_many_sessions`; не чаще раза в минуту на (причина, агент/IP) со счётчиком `count` |
| `request.create`, `grant.auto` | как в REST | `via:'mcp'` |
| `proxy.call`, `proxy.denied`, `proxy.no_secret` | как в REST | `via:'mcp'`, `session` |

Неаутентифицированные отказы (шаг 2) в audit не пишутся (нет агента), только счётчик в `logger.warn` с агрегированием по IP.

## Тесты

Файлы: `test/access.test.js`, `test/proxy-core.test.js`, `test/mcp.test.js`. `node:test`, mock-upstream на localhost, `vault: file`, MCP-клиент SDK по `StreamableHTTPClientTransport` к `fastify.listen({port:0})` или сырые JSON-RPC `fetch` на localhost. Сети нет.

`access.test.js`
1. Каждая причина отказа даёт `invalid_grant`: битая подпись, истёкший токен, revoked grant, удалённый ключ, `provider` ≠ ключ, не привязан (`agent_credentials`), ключ истёк, `mode:'deny'`, вне окна.
2. `agent.enabled=0` при ещё активном grant (поставить флаг прямым `UPDATE`, мимо `setAgentEnabled`) -> `invalid_grant`, `reason:'agent_disabled'`.
3. `expectAgentId` другого агента -> `agent_mismatch`; `expectCredentialId` другой -> `credential_mismatch`.
4. `pickCredential`: ноль/один/два ключа; чужой привязанный ключ неотличим от несуществующего; список в ошибке только `{id,label}`.

`proxy-core.test.js`
5. REST и прямой `proxy.call` дают одинаковые коды на одинаковые входы (таблица кейсов прогоняется через оба).
6. Порядок: `/./batch.json` -> `bad_path`; закрытый метод -> 403 и `calls_used` не растёт; 413 по `contentLength` до резерва; `rate_limited` до записи audit.
7. 1000 запросов закрытого метода -> строк `proxy.denied` не больше N (агрегация, `count` в мете).
8. Lease: `inflight` = 1 пока тело не дочитано; после конца потока 0; после `body.destroy()` на середине 0; после `signal.abort()` 0 и upstream получил отмену; после дедлайна `provider.timeout` 0; на `ok:false` после резерва (нет секрета, `upstream_unreachable`, `upstream_encoded`) 0.
9. `max_parallel`: второй одновременный вызов при незакрытом теле первого -> `quota_exceeded`; после `destroy()` первого - проходит.
10. П-4 `upstream_encoded`, фильтр `filtered_non_json`/`filtered_too_large`, редактор секрета на границе чанков - сохраняются.

`mcp.test.js`
11. Bearer на каждом запросе: `initialize` с валидным токеном, затем POST с тем же session id без `Authorization` -> 401; GET и DELETE без токена -> 401; с неверным `gwa_` -> 401.
12. Агент A открыл сессию S; агент B с валидным своим токеном шлёт POST/GET/DELETE с S -> 404 `session_not_found`, сессия A жива и работает; в audit `mcp.denied` `session_mismatch`.
13. Два агента × две сессии × два ключа одного провайдера (K1, K2; A привязан к обоим, B только к K2): у A сессия 1 получила grant на K1, сессия 2 на K2; `call` без `credential_id` в сессии 1 идёт на K1 (единственный токен), в сессии 2 на K2; при токенах на оба ключа и без `credential_id` -> `credential_id_required` + `[{id,label}]`; у B `list_services` показывает только K2, `request_access` на K1 -> `no_credential`; upstream видит нужный секрет у каждого вызова и никогда чужой.
14. `check_request`: заявка агента B из сессии агента A -> `not_found`; несуществующий id -> тот же ответ; своя заявка из другой сессии того же агента -> статус и привязка токена к текущей сессии.
15. Отзыв grant посреди сессии (`repo.revokeGrant`, затем `softDeleteCredential`, затем смена привязки - три прогона): следующий `call` -> `invalid_grant`, запись в `tokens` удалена (следующий -> `no_grant`), upstream вызова не получил, `inflight` 0.
16. Отзыв во время идущего `call` с долгим ответом: `call` не рвётся мгновенно (как REST), но следующий отклонён; закрытие сессии во время `call` -> abort, `inflight` 0.
17. Агент выключен (`setAgentEnabled(0)`): следующий запрос 401, сессия закрыта (`mcp.session.close` reason `agent_disabled`); с прямым `UPDATE enabled=0` при активном grant - то же (проверка `agent.enabled` в access/MCP).
18. Origin: запрос с `Origin: http://evil.example` -> 403 `origin_not_allowed` до разбора тела; Origin из `mcpOrigins` проходит; без Origin проходит; `Host: evil.example` -> 403 `host_not_allowed`.
19. Тело POST > `mcpBodyLimit` -> 413 `payload_too_large`; `call.body` > `provider.maxBody` -> `body_too_large` и upstream не вызывался, квота не потрачена.
20. Ответ upstream 1 МБ: `truncated:true`, `bytes` = `mcpMaxResponse`, lease освобождён, UTF-8 не порван; бинарный `content-type` -> `body:null, binary:true`; ответ с секретом на границе обрезки не содержит секрета.
21. Токен `gwt_` не встречается ни в одном ответе инструментов, `structuredContent`, ошибках, audit и логах (поиск подстроки по перехваченному трафику и `repo.listAudit`).
22. Лимиты: 6-я сессия агента -> 429 `too_many_sessions`; простой > `mcpIdleSec` (таймеры подменены) закрывает сессию, токены очищены; общий `limits.proxy` исчерпывается суммой REST+MCP вызовов одного агента; `request_access` делит лимит 30/мин с REST.
23. Повтор session id после `DELETE` -> 404; session id той же сессии, но заголовок `Authorization` токена того же агента от другого запуска (токен ротирован) -> 401.
24. `call` вызывает только `GET|POST|PUT|PATCH|DELETE`; `path` с `#`, `..`, `%2e%2e`, `%252e` -> `bad_path`; `Authorization` из `headers` модели не доходит до upstream.
25. Закрытый фильтром метод через MCP -> `method_not_allowed` + `allowed`, `calls_used` не растёт, в audit `proxy.denied` с `via:'mcp'`.
26. Auto-grant (`mode:'always'`): `request_access` возвращает `approved` и сразу работает `call`; в `request_access`-ответе нет токена.

## Решения (03.11, проверка контракта)

1. Да: `request_access` подхватывает активный grant этого агента на этот ключ (reissue без новой заявки), audit `mcp.token.bind` с `reuse:true`; отзыв ловит `authorizeCall` на каждом `call`.
2. Флаг REST `token_issued:*` при выдаче через MCP не ставится.
3. Лимиты по умолчанию: 5 сессий на агента, idle 15 мин, 64 КиБ в модель, MCP 120 запросов/мин; `limits.proxy` — **300 вызовов/мин** на агента (120 мало для выгрузок).
4. `mcpOrigins` по умолчанию пусто, `GW_MCP_ORIGINS` для браузерных клиентов — в README.
5. `bad_query` вводится (query ≤ 4096, без управляющих символов), дописать в ТЗ §8.
6. Тексты MCP — английские константы (ТЗ: ответы агентам всегда на английском).
7. `list_services` — только сервисы с доступными агенту ключами.
8. `authorizeCall` вызывается внутри `proxy.call`.
9. `mcpCallParallel` и белый список заголовков ответа — в рамках П-34.
Итоговый порядок шагов прокси, общий с контрактом REST-фильтра, — в `docs/ARCHITECTURE.md`, раздел «Релиз 1.0».

## Исходные вопросы

1. Пересоздание токена: новая MCP-сессия того же агента после рестарта/переподключения видит ещё действующий grant, но токена в памяти нет. Разрешить `request_access` подхватывать активный grant агента на этот ключ (reissue без новой заявки) или всегда требовать новую заявку? Предлагаю подхват: grant принадлежит агенту, токен выдаётся только ему.
2. Флаг REST `token_issued:*` при выдаче токена через MCP: не ставим (REST-опрос может ещё раз выдать токен тому же агенту). Устраивает?
3. Лимиты по умолчанию: 5 сессий на агента, idle 15 мин, 64 КиБ в модель, 120 запросов/мин MCP, `limits.proxy` значение (предлагаю 120/мин на агента). Подтвердить.
4. `mcpOrigins` по умолчанию пусто (браузерные MCP-клиенты вроде Inspector требуют явного добавления через `GW_MCP_ORIGINS`). Допустимо?
5. Новая проверка `bad_query` (query ≤ 4096, без управляющих символов) не описана в ТЗ; добавить в §8 или не вводить?
6. Тексты `list_services` и описания инструментов на английском константами (как коды ошибок), без `t()`. Подтвердить исключение из правила проекта про `t()` (все тексты интерфейса через словари).
7. `list_services` показывает только сервисы с доступными агенту ключами (не весь каталог). Если нужен весь каталог для подсказки "попроси владельца привязать ключ" - вернуть каталог со `status:'no_key'`.
8. Выбор между "`access` вызывается внутри `proxy.call`" (предложено, пропустить нельзя) и "вызывает транспорт, `proxy.call` принимает готовый результат" (проще тестировать, но П-15 повторим). Предложено первое.
9. Лимит одновременных `call` на сессию (`mcpCallParallel=4`) и белый список заголовков ответа - допустимое добавление в рамках П-34/ТЗ §10, не отдельная функция?
