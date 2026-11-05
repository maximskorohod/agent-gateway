# Контракты модулей

Все пути относительно `src/`. Все модули — ESM. Ниже — публичные экспорты; остальное внутреннее.

## Общие типы (JSDoc, без TS)

```js
/** @typedef {{ id:string, provider:string, label:string, kind:'static'|'path', host:string,
 *   injection:Injection, vault_param:string, mode:'always'|'ask'|'deny',
 *   approval:'tg_button'|'tg_code'|'web_button'|'web_code',
 *   max_ttl:number, max_calls:number, max_parallel:number,
 *   window:Window|null, expires_at:number|null, always_until:number|null /* mode='always' до этого момента, null = бессрочно */,
 *   last4:string, created_at:number, deleted_at:number|null, filter:DataFilter|null }} Credential */
/** @typedef {{ enabled:boolean, entities:Record<string,string[]>, flags?:Record<string,string[]>, methods:string[], fields:string[] }} DataFilter
 *   // flags[тип] = ['search']: явные флаги extras типа (П-17); ключа нет, пока флагов нет (≡ []); readOnly?:true и mask?:true — слой 1 (п. 7.2), ключа нет, пока не включено
 *   // ТЗ v1.3: entities — открытые типы данных каталога (сделки, лиды…) → разрешённые поля этого типа;
 *   // methods + fields — дополнительное правило владельца: шаблоны пути со '*' и пути по JSON через точку
 *   // (массивы проходятся насквозь). Старая запись { preset, methods, fields } читается через normalizeFilter. */
/** @typedef {{ type:'header', name:string, prefix?:string } |
 *            { type:'path', template:string }      // template: '/bot{secret}' или '/rest/{secret}' — {secret} заменяется
 *           } Injection */
/** @typedef {{ days:number[], from:string, to:string, tz:string }} Window  // days: 1..7 (пн=1), from/to 'HH:MM' */
/** @typedef {{ id:string, name:string, enabled:0|1, created_at:number, last_seen_at:number|null }} Agent */
/** @typedef {{ id:string, agent_id:string, credential_id:string, ttl:number, calls:number, reason:string,
 *   status:'pending'|'approved'|'denied'|'expired', created_at:number, expires_at:number,
 *   decided_at:number|null, decided_via:string|null, tg_message_id:number|null }} Request */
/** @typedef {{ id:string, request_id:string, agent_id:string, credential_id:string, created_at:number,
 *   expires_at:number, max_calls:number, calls_used:number, max_parallel:number, inflight:number, revoked_at:number|null }} Grant */
/** @typedef {{ slug:string, name:string, host:string|'owner', hostPattern?:string, injection:Injection,
 *   kind:'static'|'path', keyPattern?:string, extraHeaders?:Record<string,string>,
 *   maxBody:number, timeout:number, fields:('key'|'webhook_url'|'account'|'host'|'header')[], icon:string,
 *   filter?:ProviderFilter }} Provider */
/** @typedef {{ keep:string[], deny:string[], selectParam?:string, selectFor?:string[],
 *   entities:Record<string,{name:string, methods:string[], fields:{path:string, label:string}[], defaults:string[]}> }} ProviderFilter
 *   // keep — служебные поля ответа (ошибки, пагинация), остаются всегда; deny — методы, закрытые при любом фильтре;
 *   // entities — типы данных с галочками на странице ключа, defaults — поля, отмеченные по умолчанию;
 *   // selectFor — методы, где шлюз подставляет select из полей типа (Bitrix24 crm.deal.list, crm.lead.list) */
```

## config.js
```js
export const config = {
  dataDir, dbPath, port, host /* 127.0.0.1 */, publicUrl /* https://gw.example.com */,
  vault: 'ssm'|'file', vaultPrefix /* /gateway */, vaultFile /* dataDir/vault.json для file */,
  ssmRegion, logLevel, bodyLimit /* 2 MiB */, trustProxy: true,
}
```
Читается из env: `GW_DATA_DIR, GW_PORT, GW_PUBLIC_URL, GW_VAULT, GW_VAULT_PREFIX, GW_SSM_REGION, GW_LOG_LEVEL, GW_PROXY_RATE_PER_MIN`.
`authProvider` (`GW_AUTH_PROVIDER`; пусто = провайдер по умолчанию из `src/auth/provider.js`, неизвестное имя — ошибка старта). `buildApp(overrides.auth)` — готовый провайдер входа (только тесты).
Демо (6.6): `demo` (`GW_DEMO=1|true|on`), `demoResetSec` (`GW_DEMO_RESET_SEC`, 3600), `dataDirExplicit` (задан ли `GW_DATA_DIR`), `prodHosts` (`GW_PROD_HOSTS`, через запятую); `buildApp(overrides.env)` — окружение для `assertDemoIsolation` (только тесты). Подробности — раздел `demo/`.
`proxyRatePerMin` (по умолчанию 300) — лимит вызовов прокси на агента в минуту (П-34). Через `buildApp(overrides)` (только тесты): `logStream` — приёмник pino вместо stdout, `now` — часы для агрегации audit в `core/proxy.js`, `mcpNow` — часы MCP-сессий (простой, срок жизни, агрегация audit).
MCP (`mcp/server.js`), env `GW_MCP_*`: `mcpEnabled` (`GW_MCP_ENABLED`, по умолчанию включён; `0|false|off` выключает), `mcpOrigins` (`GW_MCP_ORIGINS`, через запятую; пусто = любой запрос с `Origin` отвергается), `mcpMaxSessionsPerAgent=5`, `mcpMaxSessions=200`, `mcpIdleSec=900`, `mcpMaxLifetimeSec=86400`, `mcpMaxResponse=65536` (байт ответа сервиса в модель), `mcpBodyLimit=262144` (тело JSON-RPC), `mcpCallParallel=4` (одновременных `call` на сессию), `mcpSweepSec=30` (период проверки простоя; не из env, меняется только в тестах).

## logger.js
```js
export function createLogger(level, redactHeaders, destination?)   // pino; redact-пути из catalog.redactHeaders(); destination — только для тестов
export function maskPath(path, credential)   // '/rest/17/****/crm.lead.add.json'
export function maskUrl(url)   // URL для логов (П-33): без query/фрагмента; /l/<токен> и /setup/<код> -> /l/****, /setup/****
```
Все логи URL (access-log в `app.js`, обработчики ошибок, `sendApiError`) идут только через `maskUrl`. Fastify создаётся с `logger: false`.

## db/index.js
```js
export function openDb(path)   // -> Database (better-sqlite3), применяет schema.sql, WAL, foreign_keys
```
## db/repo.js  — все запросы к базе. Конструктор получает db.
```js
export function createRepo(db, { demo = false } = {}) => ({
  // демо (только при demo:true): demoWipe(), demoIsolationFacts(), demoResetAge(), demoMarkReset() — раздел demo/
  // meta
  getMeta(key), setMeta(key, value),
  // owner
  getOwner(), setPasswordHash(hash), setTotp(secretEnc, enabled), setTg(chatId, botParam), setSetupDone(),
  // backup codes
  replaceBackupCodes(hashes[]), useBackupCode(hash) /* -> bool, помечает used_at */,
  // sessions
  // Н-3: везде idHash = sha256(cookie) hex, сырой id в repo не попадает (хэш считает auth/session.js). Таблица sessions(id_hash, user_id, …).
  // user_id пока константа OWNER_USER_ID='owner' (экспорт repo.js) без FK: внешний ключ на users появится с миграцией команды (этап 6.x).
  createSession(idHash, expiresAt, ua, userId=OWNER_USER_ID), getSession(idHash) /* null если истекла */, touchSession(idHash, newExpiresAt),
  setSessionTotp(idHash), countFullSessions(), deleteSession(idHash), deleteAllSessions(), listSessions() /* строки с id_hash, новые первыми */,
  // использованные шаги TOTP (П-32), таблица totp_used(user_id, step, used_at, PK(user_id, step))
  takeTotpStep(userId, step) /* -> bool: INSERT OR IGNORE, changes===1; переживает перезапуск */, purgeTotpSteps() /* шаги старше 10 минут; -> n; вызывает таймер в app.js */,
  // черновики действий при 2FA (П-19), таблица pending_actions(id PK, session_hash UNIQUE FK sessions(id_hash) ON DELETE CASCADE, user_id, type, target_id, version, body_json, created_at, expires_at)
  // user_id = OWNER_USER_ID без FK (users позже). nowSec — необязательная подмена часов (по умолчанию unixepoch() в SQL); в боевом коде pending.js передаёт свои часы.
  savePending(sessionHash, { id, userId, type, targetId, version, body, expiresAt }) /* INSERT OR REPLACE: одна запись на сессию, прежний id мёртв */,
  getPending(sessionHash, id, nowSec?) /* -> {…строка, body} | null: нет, чужая сессия, просрочена */,
  consumePending(sessionHash, id, nowSec?) /* DELETE … RETURNING: -> строка | null; только внутри inTransaction вместе с исполнением */,
  deletePending(sessionHash) /* -> bool: отмена, смена пароля/2FA (выход и закрытие сессий удаляют каскадом) */, purgePending(nowSec?) /* просроченные; -> n; вызывает таймер в app.js */,
  inTransaction(fn) /* db.transaction(fn).immediate(): fn синхронна (без await), исключение откатывает всё; вложенные repo-транзакции становятся savepoint */,
  // one-time links
  createLink(tokenHash, purpose, expiresAt), consumeLink(tokenHash, purpose) /* -> bool, одноразово, атомарно */,
  // credentials
  createCredential(cred), getCredential(id) /* без deleted */, listCredentials(), updateCredentialPolicy(id, {mode, approval, max_ttl, max_calls, max_parallel, window, expires_at, always_until, label}),
  endExpiredAlways() /* mode='always' с прошедшим always_until → 'ask'; -> Credential[] для уведомлений (вызывает expireLoop) */,
  softDeleteCredential(id) /* deleted_at + revoke всех grants — одна транзакция */, updateCredentialSecretMeta(id, {last4, vault_param}),
  updateCredentialFilter(id, filter /* DataFilter|null */),
  // agents
  createAgent(agent), getAgent(id), getAgentByTokenHash(hash), listAgents(), setAgentEnabled(id, enabled) /* enabled=0 → revoke всех grants агента */, deleteAgent(id), touchAgent(id),
  // привязка ключей к агенту (agents.all_credentials=1 — все ключи, иначе только agent_credentials)
  listAgentCredentials(agentId) /* -> credentialId[] */, setAgentCredentials(agentId, {all, ids}) /* одна транзакция; revoke grants к отвязанным ключам; -> bool */,
  agentCanUse(agentId, credentialId) /* -> bool; проверяется в POST /v1/grants, при одобрении и на каждом вызове прокси */,
  // статистика (по audit action='proxy.call' и requests; days — период назад от unixepoch())
  callStats(days) /* -> [{agent_id, credential_id, calls, errors, last_at}] */, requestStats(days) /* -> [{agent_id, credential_id, total, approved, denied, unanswered}] */,
  listCalls({days, agentId, limit}) /* -> [{id, at, target, agent_id, credential_id, status, ms}] */, countOkCalls() /* -> число proxy.call со статусом 2xx за всё время (онбординг) */,
  // requests
  createRequest(req), getRequest(id), listPending(), countPendingRequests(agentId, credentialId) /* -> {pair, agent}: не истёкшие pending (потолок Н-6) */, decideRequest(id, status, via) /* только из pending; -> bool */,
  approveRequest(id, via, grant) /* pending и не истекла → approved + INSERT grant, одна транзакция; -> bool (П-10); UNIQUE grants(request_id) */,
  expireRequests() /* pending с expires_at < now → expired; -> n */, setRequestTgMessage(id, messageId),
  // grants
  createGrant(grant), getGrant(id), reserveCall(grantId, leaseTtlSec) /* -> leaseId | null; ОДНА синхронная транзакция (ТЗ §8) */,
  releaseCall(leaseId) /* inflight-1, delete lease */, extendLease(leaseId, ttlSec), reapLeases() /* просроченные lease → inflight-1 */,
  revokeGrant(id), revokeAllGrants() /* restore/init */, listActiveGrants(),
  // сброс незавершённых состояний (П-35), CLI restore/init
  resetPendingStates() /* одна транзакция: revoke всех grants, удалить sessions, one_time_links, totp_used; pending-заявки -> expired (decided_via 'timeout'); из meta удалить setup_totp_secret, setup_backup_codes, setup_tg_code, reissue_totp_secret, new_backup_codes и pending:%; -> {grants, sessions, links, requests, meta, totpSteps} */,
  resetOwnerSetup() /* init: пароль, TOTP, Telegram, setup_done=0, backup_codes пусто; ключи и агенты не трогает */, deleteAllLinks() /* -> n */,
  // audit
  audit(actor, action, target, meta) /* только INSERT */, listAudit({limit, before}),
  rotateAudit(days, writeArchive) /* П-37: одна транзакция; строки старше days дней -> writeArchive(rows) (синхронно, ДО подмены; бросил -> откат, таблица цела) -> audit_new, копия новых строк с теми же id, DROP audit (триггеры уходят с ней), RENAME, индексы и оба триггера append-only заново из schema.sql (db/index.js: AUDIT_DDL), счётчик AUTOINCREMENT сохраняется, запись audit.rotated {archived, cutoff, file}; -> {archived, cutoff, file}; если старых строк нет, ничего не меняется */,
})
```

## catalog.js
```js
export function loadCatalog(yamlPath, { demo = false } = {}) // demo: только провайдеры demoOnly:true, вне демо они скрыты (6.6)
   // -> { providers: Map<slug, Provider>, get(slug), list(), redactHeaders(): string[],
   //    secretForms(provider, secret): string[] }  // сырая, URL-кодированная, base64 формы (Basic: ещё отдельно ключ), длинные первыми; идут в makeRedactor/redactText
export function buildInjection(provider, ownerInput) // -> { host, injection, kind, last4, secret } — нормализует ввод владельца
   // выбор по provider.builder (П-23), не по полям: static (по умолчанию) | webhook | subdomain | basic | other (только slug other)
   // static: фиксированный host, поле key
   // webhook: Bitrix24 — parse URL вебхука → host=portal (hostPattern), secret='17/abc', injection {type:'path', template:'/rest/{secret}'}
   // subdomain: amoCRM — host из account по hostTemplate '{account}.amocrm.ru' (метка DNS или полный адрес) + hostPattern
   // basic (encode: base64): секрет в сейфе `логин:ключ`; Twilio — фиксированный host, логин = account (accountPattern); Zendesk — host из account по hostTemplate, логин `email/token` (basicLogin)
   // other: host из ввода, header name из ввода
   // Замена ключа (POST /keys/:id/replace, П-25): ввод тот же, что при добавлении (у other адрес и заголовок из сохранённого ключа); если built.host !== credential.host — отказ catalog.err.replace_host, в сейф ничего не пишется
   // Инвариант: при provider.host !== 'owner' результат host === provider.host при любом вводе; loadCatalog отклоняет фиксированный host с полем host/webhook_url или builder subdomain/webhook/other
   // Поля провайдера: builder, hostTemplate, basicLogin, accountPattern, accountPlaceholder (пример в поле account), getKeyUrl (https), getKeyHint, sensitive, warning (→ catalog.warn.<slug> на форме ключа), filterFrom (копия фильтра и readOnly другого провайдера)
   // Слой 1 (п. 7.2): readOnly — нет поля или false: у сервиса недоступен; true ≡ { style:'rest' } (GET/HEAD); объект { style:'rest'|'rpc', extraRoutes:['POST /маршрут'] (rest, POST-чтение вроде поиска),
   //   readMethods:['crm.*.list'] (rpc, обязателен), default:true (у новых ключей включён сразу: Bitrix24, amoCRM, HubSpot, Pipedrive, Zendesk) }; описание лежит на уровне провайдера, а не в filter,
   //   потому что readOnly работает и у сервиса без типов данных. mask: false — маскировка недоступна (LLM и потоковые: OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, Deepgram, ElevenLabs); по умолчанию доступна.
   //   bufferMax — необязательный предел буфера ответа при фильтре полей или mask (по умолчанию 8 MiB), берётся меньшее из bufferMax и maxBody.
   // REST-фильтры данных (п. 7.3): hubspot («Deals without contacts»: deals, extras.search, denyQuery associations/propertiesWithHistory/archived, selectFormat comma),
   //   pipedrive («Deals without persons»: v1 и v2 deals, deny persons/organizations/activities/notes, denyQuery person_id/org_id/filter_id; person_id/org_id/user_id — объекты и вырезаются, остаётся user_id.id),
   //   zendesk («Tickets without customer data»: tickets, tickets.json; deny users/organizations/requests/search/comments, denyQuery include; requester_id остаётся, via.channel виден, subject и description есть в списке, но не отмечены по умолчанию).
   //   filter.unverified: true — формы ответов взяты из документации и контракта, живой проверки на тестовом аккаунте не было (решения п.4); интерфейс показывает пометку; валидируется как boolean. Тесты: test/rest-providers.test.js, фикстуры test/fixtures/{hubspot-deals,pipedrive-deals,zendesk-tickets}.json.
// db/migrate-catalog.js: migrateCatalog(repo, catalog) -> id[] — при старте ключи bitrix24 с хостом вне облачного hostPattern переходят в bitrix24-box (audit catalog.migrated), секрет не трогается
export function validateKeyFormat(provider, key) // -> null | 'похоже, вы вставили не тот ключ: ожидается sk-…'
```

## vault/index.js
```js
export function createVault(config) // -> { get(name), put(name, value), del(name) } — всё async, name без префикса: 'cred/<id>', 'sys/signing'
// vault/ssm.js — SSM SecureString, кэш 5 мин в памяти, инвалидация на put/del.
//   createSsmVault(config, {client?, ttlMs?, now?}) — второй аргумент только для тестов.
//   П-31: поколения на имя — put/del увеличивают поколение до и после запроса; get, пересёкшийся с записью,
//   значение вызывающему отдаёт, но не кэширует (в том числе null при ParameterNotFound).
// vault/file.js — dev/тесты: JSON-файл, зашифрован AES-256-GCM мастер-ключом из dataDir/master.key (0600)
//   + names() -> string[] — только у file-сейфа, для проверки изоляции демо (contracts/rest-demo-notify.md)
```

## auth/password.js
```js
export async function hashPassword(pw)        // argon2id 64MiB/3/1, семафор на 1
export async function verifyPassword(hash, pw)
```
## auth/totp.js
```js
export function generateSecret()                       // base32
export function otpauthUrl(secret, label)              // для QR
export function verifyTotp(secret, code, usedStore)    // окно ±1; usedStore = { take(step:number):boolean } (П-32), реализация — repo.takeTotpStep(userId, step); шаг уже взят → false
export function generateBackupCodes()                  // 10 кодов по 10 символов
export function hashCode(code)                         // sha256 hex
export function encryptSecret(secret, key) / decryptSecret(enc, key)   // AES-256-GCM, key из vault sys/totp
```
## auth/provider.js — сменный модуль входа (6.2, подробно в `docs/AUTH.md`)
```js
export const DEFAULT_PROVIDER                          // имя провайдера при пустом config.authProvider
export function createAuthProvider({ config, repo, keys, logger })  // -> AuthProvider; неизвестное имя / не реализованный слот -> throw (ошибка старта)
// AuthUser = { id, login, name, role:'owner'|'viewer', disabled, totpEnabled, tgChatId, externalId }
// AuthProvider = { name, capabilities:{ password, secondFactor:'local'|'provider'|'none', external, manageCredentials },
//   verifyLogin({login?,password,ip?}) -> {ok:true,user}|{ok:false,reason:'bad'|'locked'|'disabled', alert?:'distributed'},  // ip — ключ клиента (IPv6 по /64); alert — порог распределённого перебора пароля, не чаще раза в 15 минут
//   verifySecondFactor({userId,code,ip?}) -> {ok:true,kind:'totp'|'backup'}|{ok:false,reason:'bad'|'locked'},
//   getUser(userId), getUserByTelegram(chatId),
//   // manageCredentials: setPassword(userId,pw), beginSecondFactorEnrollment(userId)->{secret,otpauthUrl},
//   //   confirmSecondFactorEnrollment(userId,secret,code)->{ok,backupCodes?}, regenerateBackupCodes(userId)->string[] (дополнение к контракту)
//   // external: startExternalLogin(req)->{redirect}, finishExternalLogin(req) — слот supabase, в 1.0 не реализован }
```
Реализован только `local`: пока нет таблицы `users` (6.4), единственный пользователь — владелец (`OWNER_USER_ID`, строка `owner`). Внутри: argon2 с фиктивным хэшем для неизвестного логина, `decryptSecret` + `verifyTotp` с `repo.takeTotpStep`, резервные коды, блокировки в памяти по паре «пользователь + адрес» (`u:<id>|<ip>` пароль, `uc:<id>|<ip>` код: 5 ошибок, 15 мин; IPv6 сводится к /64 хелпером `web/client-key.js`, он же ключ лимитов демо). Глобальный счётчик ошибок пароля (50 за 15 минут, любые адреса) вход не блокирует, а только возвращает `alert:'distributed'` (веб-слой шлёт владельцу `notify.login_distributed`); потолок ошибок кода — 30 в час на пользователя (защищает 6-значный TOTP; на сайте при его достижении `notify.totp_locked_hour`). Веб-слой вызывает провайдер только в `POST /login`, `POST /totp`, коде одобрения заявки, настройках и мастере; `/login` при `capabilities.external` редиректит, `/settings/password` и `/settings/2fa/*` при `!manageCredentials` отвечают 404 и скрыты на странице. В бот провайдер передаётся зависимостью `auth` (`getUserByTelegram`, `getUser`). Имена провайдеров как строки — только в `src/auth/`.

## auth/session.js  (fastify plugin)
```js
export function sessionPlugin(fastify, { repo, secure })
export function cookieNames(secure)                    // -> { sid, pre }: на https '__Host-gw_sid' / '__Host-gw_pre', иначе 'gw_sid' / 'gw_pre'
export function hashSessionId(id)                      // sha256 hex; единственное место, где считается хэш (Н-3)
// decorates: request.session (null | {id, idHash, userId, half, totpAt}), reply.startSession(), reply.endSession(), reply.endAllSessions(), request.markTotp(), request.hasRecentTotp()
//   id — сырое значение cookie, только в памяти запроса (нужно CSRF-HMAC); в базе, в ключах meta, в маршрутах и на страницах — только idHash
// лимиты (П-32): startSession выдаёт половинную сессию (не больше 5, самые старые удаляются) и НЕ вытесняет полные;
//   markTotp делает сессию полной и вытесняет самые давние по last_seen_at до 3 полных
// миграция Н-3 (db/index.js): старая sessions с колонкой id удаляется, все сессии закрыты, meta 'pending:*' удалены
// cookie: sid (см. cookieNames), HttpOnly, Secure, SameSite=Strict, 12ч, продление, не дольше 7 суток
// на https префикс __Host-: Path=/, Secure, без Domain — соседний поддомен такую cookie подсадить не может (П-22)
// request.requireOwner() — редирект на /login если нет сессии
// request.requireRecentTotp(maxAgeSec=300) — для опасных действий; хранится в сессии totp_at
```
## auth/links.js
```js
export function makeLink(repo, purpose, ttlSec) // -> { url, token } url = publicUrl + '/l/<token>'; в базе только sha256
export function consumeLink(repo, token, purpose) // -> bool
```

## core/ssrf.js
```js
export async function resolvePublic(host) // -> ip (string) или throw (code EPRIVATE); для Slack, демо, bitrix24-box
export function isPrivateIp(ip)           // true для приватных/неразобранных адресов; проверка хоста владельца — isValidOwnerHost в catalog.js, резолв прокси — safeLookup в proxy.js
export function validateAgentPath(path)   // -> bool: нет '..', '@', '://', '#', '?', управляющих символов, длина ≤ 2048 («#» режет undici, «?» — граница query; 9.1a; прокси проверяет сырой и декодированный путь, поэтому %23 и %3F тоже -> 400 bad_path)
```
// isPrivateIp разбирает адрес канонически (П-29): формы с лишними нулями, IPv4-mapped и т.п. приводятся к одному виду до проверки диапазонов
## core/infra.js — ошибки инфраструктуры (П-30), единая классификация
```js
export function isInfraError(err)       // -> bool: err.infra (помечена), SqliteError / code SQLITE_*, ошибки AWS SDK ($metadata, кроме ParameterNotFound)
export function markInfra(err, source)  // -> err (источник 'vault' | 'db')
export function wrapVault(vault)        // get/put/del: любой сбой помечается markInfra; применяется в vault/index.js
export function sendApiError(err, req, reply, logger) // JSON-ответ /v1/*: инфраструктурная -> 503 {error:'service_unavailable'} + Retry-After,
                                        // 400 -> bad_request, иначе internal; лог без query и без секретов
export const RETRY_AFTER_SEC            // 5
```
Единственные места отображения: обработчик ошибок плагина `/v1/*` (`api/agents.js`, у плагина свой контекст), корневой `setErrorHandler` в `web/server.js` (страницы сайта: 503 + `t('error.unavailable')` + Retry-After) и `catch` в `proxy.call` (результат `ok:false` 503 с `retryAfter`, заголовок ставит адаптер). Ошибки сервиса (сеть) сюда не относятся.
## core/redact.js
```js
export function makeRedactor(secrets: string[]) // -> { push(chunk:Buffer|string) -> Buffer|string, flush() -> Buffer } ; потоковая замена секрета на '****' с переносом хвоста между чанками; flush() отдаёт задержанный хвост в конце потока
export function redactText(text, secrets)
```
## core/mask.js  — маскировка персональных данных (п. 7.2), чистые функции
```js
export function maskText(s)            // -> { text, n }: карта (13–19 цифр, Luhn) → IBAN (mod-97) → e-mail → телефон, замена на '****'
export function maskJson(value, limit) // -> { json, n }: только значения-строки; ключи, числа, булевы, null не меняются; ключ "__proto__" — обычное поле
```
Линейный разбор по кодам символов без RegExp на данных ответа; кандидат, не прошедший проверку, повторно не просматривается (1 MiB «@@@…» и «1 1 1…» — десятки миллисекунд).
Отступления и уточнения контракта: (1) голая строка цифр без пробелов и дефисов считается картой, только если начинается с 2–6 (метки времени unix «1699…» совпадают с Luhn в 10 % случаев, пример контракта «не тронуто» иначе не выполняется); цифры с пробелами и дефисами проверяются без этого условия;
(2) телефон: кандидат не маскируется, если рядом «:», перед ним буква или цифра, он начинается с «ГГГГ-ММ-ДД», либо в нём единственный разделитель «.» (десятичная дробь «12345678901.50»); серия разделителей длиннее трёх обрывает кандидата; IP-адрес вида «192.168.100.200» (12 цифр, точки) маскируется как телефон;
(3) строка короче 6 символов не разбирается; e-mail: локальная часть ≤ 64, домен ≤ 255, хвостовые «.» и «-» в адрес не входят, последняя метка домена — только буквы, ≥ 2.

## core/filter.js  — фильтр данных (ТЗ v1.3), чистые функции без I/O
```js
// Слой 1 (п. 7.2): DataFilter.readOnly и DataFilter.mask (boolean, хранятся только когда true; normalizeFilter сохраняет их).
//   compileFilter -> null только если !enabled && !readOnly && !mask; результат дополнен { enabled, readOnly, mask, needsBuffer: enabled || mask }.
//   enabled:false при включённых readOnly/mask: типы, deny, select и query-правила не действуют, работают только они (allowMethod = только проверка чтения).
//   readOnly: REST — GET/HEAD и маршруты provider.readOnly.extraRoutes; RPC — шаблоны provider.readOnly.readMethods (HTTP-метод не участвует: Bitrix24 принимает методы и через GET).
//   Порядок внутри allowMethod: plainPath → deny → readOnly → правила. denyReason: 'write_not_allowed' для всего, что отсечено readOnly (и REST-запись, и RPC-метод вне readMethods), если путь не закрыт deny.
//   Провайдер без описания чтения (правка базы в обход формы) при readOnly:true закрывается, а не открывается: REST — GET/HEAD, RPC — ничего.
export function protectionOf(provider)    // -> { readOnly:boolean, mask:boolean }: доступность на форме и в checkFilter
export function defaultFilterFor(provider) // -> null | DataFilter с readOnly:true (provider.readOnly.default); применяется при создании ключа
// checkFilter добавляет filter.err.read_only_unavailable / filter.err.mask_unavailable; weakensFilter: снятие readOnly или mask — ослабление даже при выключенном фильтре полей.
// Форма: скрытое protect_form=1 + read_only=1 / mask=1 (parseFilter); без protect_form значения остаются прежними; форма только с защитой не трогает enabled.
// Новый ключ: server.js ставит defaultFilterFor, protect_form на форме создания переопределяет (без галочек — защиты нет). Действие key.filter сохраняется у любого провайдера, недоступное отклоняет checkFilter.
// Прокси: filterBody при mask вызывает maskJson после prune; audit proxy.call получает masked:N (число) рядом с fields_removed; ответ HEAD/204/304 идёт потоком; text/event-stream при needsBuffer → 502 filtered_stream.
export function compileFilter(filter /* DataFilter|null */, provider) // -> null (фильтр выключен) | {
//   allowMethod(httpMethod, path) -> bool  // П-17: путь после декодирования; plainPath → deny (любой метод) → правила (тип, флаги, ручное).
//                                       // rpc (Bitrix24, style по умолчанию): HTTP-метод не участвует (methodAgnostic), вызов allowMethod(path)
//                                       // с одним аргументом оставлен для совместимости. rest (style:'rest'): правило = МЕТОД + маршрут (ниже)
//   denyReason(httpMethod, path) -> null|'method_not_allowed'|'write_not_allowed'  // для 403 и audit (denied_reason); запись вне deny и вне флага — write_not_allowed
//   checkQuery(httpMethod, path, query) -> null|'query_not_allowed'|'hidden_field_filter'  // denyQuery каталога (имя параметра без учёта регистра и без [..]); прокси: 400 query_not_allowed.
//                                       // hidden_field_filter — хук П-18, в 1.0 всегда null
//   rewriteSelect(path, query, body?, contentType?, httpMethod='GET') -> {query, body, error?}  // только для selectFor; select агента заменяется
//                                       // (selectFormat 'comma' у REST: ?properties=a,b, остальные формы параметра удаляются; нет полей — параметр убирается)
//                                       // во всех формах (П-26): select/SELECT/select[]/select[N] в query, JSON-теле
//                                       // (массив, объект с числовыми ключами) и urlencoded-теле. error:'body_not_allowed' —
//                                       // тело неизвестного вида или битое: прокси отвечает 400 и до сервиса не идёт
//   filterBody(json, path, httpMethod='GET') -> {json, removed, masked} // masked — число замен mask (п. 7.2); поля берутся из правила, под которое попал метод (тип данных
//                                       // или дополнительное); остальное удаляется; removed — число вырезанных ключей.
//                                       // П-27: поле проходит только скаляром (строка > maxFieldLen=4000 обрезается);
//                                       // контейнер — только у поля каталога с object:true. keep — скаляры, строка ≤ keepMaxLen
//                                       // (256), вложенные пути через точку (time.start). prune не глубже 32 уровней
//   methods:string[]                   // для подсказки агенту
// }
export function normalizeFilter(filter, provider) // -> DataFilter: старую запись с preset переводит в entities, null -> выключенный
export function normalizeMethod(path)      // '/crm.deal.list.json' -> 'crm.deal.list' (нижний регистр, без .json/.xml)
export const FILTER_LIMITS                 // лимиты П-28: rules 64, segments 12, patternLen 200, stars 2, fields 200, fieldDepth 8, jsonDepth 32
export function globProblem(pattern)       // -> null | 'length' | 'segments' | 'stars'; используют loadCatalog и checkFilter
export function checkJsonDepth(buf, max?)  // -> bool: глубина JSON ≤ 32 линейным проходом по байтам до JSON.parse (скобки в строках
                                           // не считаются); прокси при false отвечает 502 filtered_too_deep (П-28)
export function parseRoute(pattern, { deny }?) // -> {method, segs:[{t:'lit'|'param'|'star'|'rest', v?}], text} | {problem:'length'|'segments'|'syntax'|'method'|'rest'}
export const WRITE_METHODS                 // POST PUT PATCH DELETE
// REST-стиль (П-17, П-28; каталог: filter.style:'rest', у типа routes:['GET /a/:id'] вместо methods, extras:{search:{label,routes}}, fields с paths:[…]):
// «МЕТОД /сегмент/:имя/*/**»; :имя и * — ровно один сегмент [A-Za-z0-9_.~-]{1,128}, не «.»/«..»; ** только последним и только в deny (там же ANY и метод
// любой); литералы без учёта регистра; один хвостовой «/» отбрасывается; HEAD совпадает с GET; OPTIONS/TRACE/CONNECT — отказ; в начале «//» — отказ.
// Матчер: сегменты шаблона один раз, путь режется один раз, один проход слева направо, без откатов и RegExp. ** в deny совпадает и с нулём сегментов.
// Запись (POST/PUT/PATCH/DELETE) тип и ручное правило не открывают никогда: routes с записью — ошибка loadCatalog, ручное правило — ошибка checkFilter;
// запись открывают только маршруты extras при flags[тип]∋флаг. Отмеченное поле с paths открывает все формы (идентификатор в форме — paths[0], он же path после loadCatalog).
// Шаблоны методов сопоставляются линейно (два указателя + последняя звезда), без RegExp; шаблон выше лимитов при
// выполнении ничего не открывает (в deny закрывает всё), путь длиннее 12 сегментов не совпадает.
// Этап B (п. 7.3), описание фильтра для агента и владельца:
export function describeFilter(filter, provider) // -> null | { types?:[{id,name,fields:[путь],flags?}], extra_fields?:[путь], methods:[…], read_only?, mask? }
                                           // null — у ключа нет фильтра полей, readOnly и mask. types только при enabled; значений и секретов нет.
                                           // Это тело поля `filter` в POST /v1/grants (200), GET /v1/grants/:id (200), MCP request_access и check_request (approved).
export function filterLine(filter, provider) // -> «Агент увидит: Сделки (ID, Название, +11); только чтение; личные данные скрыты» (i18n filter.line*): одна строка,
                                           // без управляющих символов, ≤ 400 символов, разметки нет; ключ без фильтра: «всё, что отдаёт сервис (фильтра нет)».
                                           // Идёт в текст заявки: Telegram (bot.js buildText), Slack/e-mail (notify.requestCreated), карточка заявки на сайте.
export function previewRoute(filter, provider) // -> { method:'GET', path, query:'?limit=1' } | null: первый маршрут без параметров у первого включённого типа
                                           // (фильтр выключен — у первого типа каталога). rpc: `/<метод>.json`, rest: первый `GET` из routes без :id и *
export function fieldNames(json)           // -> string[]: пути полей без значений (result.ID); ключ из одних цифр → «*», необычный ключ → «?», ≤ 500
// Признак каталога filter.unverified:true (HubSpot/Pipedrive/Zendesk, поля из документации): форма нового ключа и блок «Что видит агент» показывают filter.unverified.
export function checkFilter(filter, provider) // -> string[] ошибок для формы (метод из deny, ничего не открыто, тип без полей)
export function weakensFilter(next, current)  // -> bool: выключение, новый тип, метод или поле — нужен свежий код;
                                              // удаление типа при непустом ручном правиле — тоже (метод уйдёт под ручные поля, П-3)
// allowMethod отклоняет пути с «.»/«..», пустыми сегментами и «%» (П-1); сегменты __proto__/prototype/constructor
// в путях полей отклоняет checkFilter и пропускает buildTree, ключ "__proto__" в ответе — обычное поле (П-2)
```
## core/requests.js
```js
export function createRequestService({ repo, catalog, notify }) => ({
  submit({ agent, credential, ttl, calls, reason, via = 'rest' /* 'rest'|'mcp': в meta audit request.create и grant.auto */ }) // -> { kind:'granted', grant, token } | { kind:'pending', requestId } | { kind:'denied', reason } | { kind:'too_many_pending' } /* > 3 ожидающих на пару агент+ключ или > 10 на агента (автопропуск не считается); REST 429, MCP isError, код too_many_pending */
  decide({ requestId, approve:boolean, via:'tg'|'web', totp? }) // -> { ok, grant? } | { ok:false, error:'not_pending'|'unavailable'|'use_web'|'bad_code' }
    // approval *_code: код проверяется здесь при любом via; без кода или без verifyTotp — 'bad_code' (П-5).
    // После проверки кода ключ, агент, привязка и политика перечитываются синхронно; ttl/calls заявки
    // обрезаются текущими max_ttl/max_calls; одобрение и grant — repo.approveRequest одной транзакцией (П-10).
  status(requestId) // -> { status, grant?, token? } для опроса агентом
  expireLoop() // setInterval 10с: expireRequests + уведомление
})
```
Проверки submit: агент enabled, credential существует и не deleted/expired, окно (window), mode; ttl/calls обрезаются до max.

## core/grants.js
```js
export function createGrantService({ repo, signingKey, logger }) => ({  // signingKey — Buffer из vault sys/signing (loadOrCreateSigningKey)
  setKey(key)                  // подмена ключа подписи (старт, тесты)
  issue(request, credential, persist?) // -> { grant, token } | null; persist(grant) -> bool, по умолчанию repo.createGrant,
                               // при одобрении — repo.approveRequest (null: заявка уже не ждёт решения)
  reissueToken(grant)          // -> { token }  тот же пропуск заново (для повторной выдачи одобренной заявки)
  verifyToken(token)           // СИНХРОННО -> grant | null  (подпись HS256 ключом sys/signing, срок, затем проверка в базе: не отозван, не истёк)
  reserve(grantId)             // -> leaseId | null   (синхронно, repo.reserveCall)
  release(leaseId), extend(leaseId)
  reapLoop()                   // setInterval 60с: repo.reapLeases()
})
```
Токен: `gwt_` + base64url(JSON{grant_id, exp}) + '.' + base64url(HMAC-SHA256). Ключ подписи — vault `sys/signing` (32 байта), читается при старте.

## core/access.js (П-15, перенесено из contracts/access-mcp.md)
```js
export function createAccess({ repo, catalog, grants, requests }) => ({
  authorizeCall({ token, provider, agentId?, credentialId? }) // СИНХРОННАЯ -> { ok:true, agent, grant, credential, provider } | { ok:false, code:'invalid_grant', reason }
  pickCredential({ agent, provider /* Provider */, credentialId? }) // -> { ok:true, credential } | { ok:false, error:'credential_id_required', credentials:[{id,label}] } | { ok:false, error:'no_credential' }
})
export function authAgent(repo, token) // -> agent | null: токен gwa_…, хэш, enabled=1; общий хелпер REST (requireAgent) и MCP
export function sha256hex(s)           // реэкспортируется из api/agents.js
```
Порядок проверок `authorizeCall` (первая неудача возвращает): токен (`grants.verifyToken`) → `token`; агент существует и `enabled === 1` → `agent_disabled`; `agentId` совпадает с `grant.agent_id` → `agent_mismatch`; ключ существует → `key_missing`, `credentialId` совпадает → `credential_mismatch`; `catalog.get(credential.provider).slug === provider` → `provider_mismatch`; `agentCanUse` → `not_bound`; `requests.credentialUsable` → `key_unusable`. Снаружи любой отказ — 401 `invalid_grant`, `reason` только для `logger.debug`/audit, без токена, секретов и хоста. Между `authorizeCall` и `grants.reserve` нет `await`. Вызывается только из `proxy` (шаг 1).
`pickCredential`: ключи провайдера, доступные агенту по `agentCanUse`; явный `credentialId` не из доступных = `no_credential`; без `credentialId` один доступный — он, два и больше — `credential_id_required` + `{id,label}`, ноль — `no_credential`.

## core/proxy.js
```js
export function createProxy({ repo, catalog, vault, grants, access, limits, logger, now = Date.now, testUpstream = null, transport = undici.request /* в демо createDemoTransport() */ }) => ({
  async call(input) // -> Promise<CallResult>; без объектов Fastify. Доступен как app.ctx.proxy
  async preview(credentialId) // п. 7.3, «Проверить на одном вызове» (ТЗ §9.3) -> { ok:true, route:'GET /…', before:string[], after:string[], allowed:bool }
                              //   | { ok:false, error, status? } (preview_no_route | upstream_status | filtered_non_json | filtered_too_large | filtered_too_deep | not_found | service_unavailable…)
})
// preview идёт тем же run(): сейф, safeLookup (SSRF), фиксированный хост ключа, редактор секретов, потолок ответа bufferMax — но input.ownerCredentialId вместо токена:
// пропуска, limits.proxy, grants.reserve и фильтра нет (квоты агентов не тратятся). Вызов — previewRoute (GET, limit=1). Audit: actor 'owner', действие proxy.preview
// (вместо proxy.call), meta { credential, provider, via:'owner', status, ms }. Из ответа берутся имена полей (fieldNames), «после» — filterBody с фильтром ключа;
// значения не возвращаются, не сохраняются и не логируются. Маршрут сайта: POST /keys/:id/preview (владелец, CSRF), ответ — страница ключа с блоком результата.
/** CallInput = { token, provider /* slug */, expectAgentId?, expectCredentialId?, method, path /* сырой, с '/', без '?' */, query /* '' | '?a=b' */,
 *   headers /* имена в нижнем регистре */, body: Buffer|Readable|null, contentLength: number|null, signal?: AbortSignal, via: 'rest'|'mcp', sessionTag? } */
/** CallResult = { ok:false, status, error, extra?: object, retryAfter?: number }
 *             | { ok:true, status, headers, body: Readable } */
```
`expectAgentId`/`expectCredentialId` уходят в `access.authorizeCall` как `agentId`/`credentialId`. `extra` — поля, которые транспорт добавляет в тело ошибки (`{allowed}` у `method_not_allowed`). `retryAfter` (секунды) есть только у 503 `service_unavailable`: адаптер ставит заголовок `Retry-After`, в тело оно не попадает. Результат всегда `Readable`; при фильтре в `headers` есть `content-length` (ответ собран целиком), без фильтра ответ потоковый. `Buffer` в `body` уходит как есть, `Readable` проходит через счётчик с лимитом `maxBody` (превышение на лету -> 413 `body_too_large`, запрос к сервису отменяется).
`limits = { requests (30/мин), poll (12/мин), proxy (proxyRatePerMin), mcp (120/мин на агента, все запросы к /mcp) }` — `createLimiter`, создаются в `app.js`, `agentApi` и `mcpPlugin` получают их параметром `limits`.
Порядок шагов `call` — в разделе «Общий порядок шагов прокси» ниже. Коротко: `authorizeCall` → `limits.proxy.take(agent.id)` (429 `rate_limited` до фильтра, audit и сейфа; audit `proxy.rate_limited` не чаще раза в минуту на агента, остальное в `count`) → путь (сырой и декодированный, «%» после декодирования — 400 `bad_path`, П-1) и query (≤ 4096, без управляющих символов, иначе 400 `bad_query`) → фильтр данных: allowMethod (403 `method_not_allowed`, квота не тратится, audit `proxy.denied` не чаще раза в минуту на (агент, ключ), остальные считаются в памяти и пишутся как `count` в мету следующей записи, П-34) → `contentLength > maxBody` (413 до резерва) → `grants.reserve` (429 `quota_exceeded`) → таймеры → сейф → заголовки и инъекция ключа → undici → ответ. Audit `proxy.call` пишется, как только известен статус (до дочитывания тела): `{grant, agent, credential, provider, status, ms, via, session?, fields_removed?}`.
Lease (П-11): единственный владелец — `core/proxy.js`, привязка к потоку тела, а не к HTTP-ответу. При `ok:true` на `body` вешается `stream.finished(body, done)`; `done` один раз снимает `extend`-таймер и дедлайн и вызывает `grants.release`. Срабатывает при конце, ошибке, `destroy()` и abort. При `ok:false` после резерва `done()` вызывается до `return`. Поток тела собран через `pipeline` (сервис -> редактор секрета -> `PassThrough`): `body.destroy()` потребителем или abort разрушает запрос к сервису. Потребитель обязан дочитать `body` или вызвать `body.destroy()`; потерянное тело снимает дедлайн `provider.timeout` (abort + destroy) и `repo.reapLeases()`. Текущее число активных lease читается как `repo.getGrant(id).inflight`.
Адаптер REST (`api/agents.js`, `ANY /v1/proxy/:provider/*`): токен из Bearer, сырой путь и query из `req.raw.url`, `body = req.raw`, `contentLength` из заголовка, `signal` от `AbortController`, который срабатывает на `reply.raw` `close`, если ответ не дописан (там же `body.destroy()`), `via:'rest'`; `ok:false` -> `reply.code(status)` + `{error, ...extra}` (+ `Retry-After` при `retryAfter`), `ok:true` -> `reply.code`, заголовки, `reply.send(body)`.
Hop-by-hop заголовки удаляются; `Authorization` агента (пропуск) никогда не передаётся upstream; добавляются extraHeaders провайдера.
Заголовки (П-36), чистые функции, экспортируются из `proxy.js`: `filterRequestHeaders(headers, extraDrop)` убирает фиксированный список `HOP`, префиксы `x-forwarded-`, `cf-`, `x-real-`, `x-envoy-`, `x-amzn-`, `forwarded`, `via`, `accept-encoding`, `extraDrop` (redact-заголовки каталога) и всё, что названо в `Connection` запроса (через запятую, без регистра); `filterResponseHeaders(headers)` убирает `RESP_DROP` и всё, что названо в `Connection` ответа сервиса; `connectionTokens(value)` -> `Set<string>`.
Инфраструктурные ошибки (П-30): сбой `vault.get` до обращения к сервису -> 503 `service_unavailable` + `Retry-After`, сервис не вызывается, lease освобождается в `finally`. Сбой сейфа внутри `proxy.call` помечается `markInfra`; сбой базы до резерва (авторизация, лимитер, `reserve`) тоже даёт `{ok:false, status:503, error:'service_unavailable', retryAfter}`; сетевые ошибки до сервиса остаются 502 `upstream_unreachable`. Сбой `repo.audit`/`grants.release` логируется и не маскирует ответ.
Ответ с `Content-Encoding` ≠ identity → 502 `upstream_encoded` до отправки байтов (П-4). Общий срок вызова = `provider.timeout` (AbortController, объединён с `input.signal` через `AbortSignal.any`).

## notify.js
Реализовано в 6.3 (контракт `contracts/rest-demo-notify.md`, «Уведомления и лист ожидания»).
```js
export function createNotifier({ repo, getBot /* () => bot|null */, vault, logger, catalog? /* для строки «Агент увидит: …» в request.created */, publicUrl, channels? /* по умолчанию createChannels */, timeoutMs? /* 10 с на канал */, test? }) => ({
  channels: Channel[],                              // для демо: createNotifier с channels:[] -> channels.length === 0
  requestCreated(request, credential, agent)        // event request.created; telegram: sendRequest (кнопки при approval tg_*), slack/email: текст + ссылка publicUrl+'/requests'
  requestDecided(request, status)                   // event request.decided; telegram: editDecided
  grantAuto(grant, credential, agent)               // event grant.auto
  info(text, event='info')                          // event info | key.expired | security
  security(text)                                    // = info(text, 'security')
  async idle()                                      // ждёт запущенные рассылки (тесты)
})  // все методы возвращают Promise, который не отклоняется; вызывающие (requests.submit и др.) его не ждут
export function createChannels({ repo, getBot, vault, publicUrl, test }) // -> [telegram, slack, email]; Channel = { id, buttons, enabled(), events(), send(msg), test() }
export const EVENTS, DEFAULT_EVENTS, CHANNEL_IDS, SMTP_PORTS
export function checkSlackWebhook(raw) // -> {ok,value}|{ok:false,error:i18n-ключ}: https, hooks.slack.com, 443, /services/…, без учётных данных, query, фрагмента
export function checkSmtp(cfg)         // -> {ok,value:{host,port,user,pass,from,to[]}}|{ok:false,error}: host через isValidOwnerHost, порт 587+starttls или 465+tls, иначе flash.smtp_no_tls
export function emailMessage(msg) / slackPayload(msg)   // чистые: тема без CR/LF и управляющих; Slack: экранирование & < >
export function readChannelMeta(repo, id) / writeChannelMeta(repo, id, {enabled, events, configured}) // meta `notify.<id>`; configured = секрет сохранён (синхронный признак, значение в сейфе)
export const codeOf   // безопасный код сбоя для лога
```
NotifyMessage = `{ event, title, text, url?, raw? }`; `raw` (запрос, ключ, агент) нужен только telegram-каналу. Лог сбоя: `logger.error({ channel, errCode }, 'notify failed')` (поле не `code`: логгер закрывает его звёздочками), без `err.message`, текста и URL. Slack: POST через undici к проверенному `resolvePublic` IP (SNI и Host `hooks.slack.com`), без редиректов, таймаут 10 с. E-mail: `nodemailer` через `await import()` при отправке, `requireTLS`, `tls:{servername, rejectUnauthorized:true, minVersion:'TLSv1.2'}`, подключение к проверенному IP, только `text/plain`. Подмена для тестов: `buildApp(overrides)` принимает `notifyChannels`, `notifyTimeoutMs`, `notifyTest:{slackOrigin:'http://127.0.0.1:P', smtp:{host,port}}` (mock Slack и SMTP на localhost), из env не читаются.
Настройки: секреты в сейфе `sys/slack_webhook` (строка URL), `sys/smtp` (JSON `{host,port,user,pass,from,to[]}`); `meta notify.<id>` = `{enabled, events[], configured}`. Telegram включён, пока бот подключён.
Маршруты (`web/server.js`): `POST /settings/notify/{slack,email}/secret` и `/:id/clear` — только `requireRecentTotp` (формы с секретом не черновик); `POST /settings/notify/:id` — действие `notify.channel` реестра (включение со свежим кодом, остальное сразу); `POST /settings/notify/:id/test` — отправка проверочного сообщения; `GET /requests` -> редирект на `/`. Audit: `notify.secret`, `notify.clear`, `notify.channel` (без значений секретов). `config.waitlistUrl` (`GW_WAITLIST_URL`) проверяет `parseWaitlistUrl` (https, ≤300 символов) в `buildApp`, затем `setWaitlistUrl` (`web/views/html.js`) включает ссылку в подвале `layout()`.

## demo/ — демо-режим GW_DEMO=1 (П-20, реализовано в 6.6; контракт `contracts/rest-demo-notify.md`, «Демо-режим»)
Файлы: `demo/guard.js` (экспорт по контракту: `assertDemoIsolation`, `installNetworkGuard`, `demoRouteGuard`, `createDemoTransport`, `createDemoMock`, `createDemoReset`), `demo/mock.js` (мок «Demo CRM», хост `demo.invalid`), `demo/reset.js` (сид, цикл сброса, константы `DEMO_AGENT_ID`, `DEMO_CREDENTIAL_ID`, `DEMO_KEY`).
```js
// config.js: demo (GW_DEMO), demoResetSec (GW_DEMO_RESET_SEC, 3600), dataDirExplicit (задан ли GW_DATA_DIR), prodHosts (GW_PROD_HOSTS)
assertDemoIsolation({ cfg, db, vault, env = process.env, repo? }) // async; throw Error('demo_isolation: <правило>[ cred/<id>]')
assertDemoDataDirFresh(dataDir)         // buildApp зовёт до mkdir/openDb: каталог пуст или с .demo-data
installNetworkGuard() -> { attempts() } // идемпотентна; attempts() — число заблокированных попыток
demoRouteGuard(fastify, { repo, reset, logger })  // onRequest + onSend + preHandler на корне; зовётся до register(mcp/agentApi) и registerWeb
createDemoTransport({ mock? }) -> (url, opts) => { statusCode, headers, body }  // подставляется в createProxy({ transport })
createDemoReset({ repo, vault, cfg, logger, onReset? }) -> { runOnce({ hold? }), loop(), get resetting }  // hold — только тесты
```
- Правила отказа `assertDemoIsolation` (имена в тексте): `vault_not_file`, `cloud_env`, `public_url_is_prod`, `data_dir_not_explicit`, `data_dir_not_empty`, `vault_not_enumerable`, `vault_channel_secret`, `vault_foreign_name` (+ `cred/<id>`), `db_foreign_credential` (+ `cred/<id>`), `db_owner_telegram`, `db_notify_settings`, `db_owner_password`. Маркер `.demo-data` создаётся при первом запуске; собственные файлы шлюза (`gw.db*`, `master.key`, `vault.json*`) в проверке каталога не считаются чужими. Порядок в `buildApp`: `assertDemoDataDirFresh` → `openDb` → `createVault` → `assertDemoIsolation` → ключ подписи пропусков → остальное → `runOnce()` (сид) до `listen`.
- `catalog.loadCatalog(path, { demo })`: в демо остаются провайдеры с `demoOnly: true` (`demo`), вне демо они скрыты. `repo.createRepo(db, { demo })`: `demoWipe`, `demoIsolationFacts`, `demoResetAge`, `demoMarkReset` существуют только при `demo: true`. `core/proxy.js`: параметр `transport` (по умолчанию `undici.request`). `vault/file.js`: `names()` (`wrapVault` его пропускает). `session.js`: опция `demo` (до 500 полных сессий, `hasRecentTotp` истинно для любой полной сессии). `views/html.js`: `setDemoMode()`, баннер в `layout()`, в демо нет ссылок «Settings» и «Sign out». `views/keys.js`: `keysPage({ demo })` показывает кнопку `POST /demo/simulate`.
- Сброс: `meta` очищается кроме `csrf_key` (ключ HMAC уже в памяти плагина CSRF); `audit` пустеется временным снятием триггера append-only (AUDIT_DDL ставит его обратно в той же транзакции); `sys/*` сейфа остаются, все `cred/*` заменяются `cred/demo`. Сам сброс в audit не пишется (после него audit пуст). Во время сброса и `onReset` (закрытие MCP-сессий) все запросы, кроме `/healthz`, получают 503 `demo_resetting` + `Retry-After: 2`.
- Allowlist: таблица в `demoRouteGuard`, всё вне неё — 404 (JSON `{error:'not_found'}` для `/v1` и `/mcp`). Поверх контракта разрешён `GET /keys/new` (выбор сервиса, кнопка «+» на главной; в каталоге один провайдер). Условия: `POST /keys/:id/policy|filter` только для ключа провайдера `demo`; `POST /keys/new/demo` — ключей меньше 3; `POST /agents` — агентов (с `demo-agent`) меньше 5, иначе 403 `demo_limit`; в телах `name`/`label` ≤ 40 символов, `approval` только `web_button` (кода 2FA в демо нет), иначе 400. Лимиты по IP (`demo:<класс>:<ip>`, IP из `trustProxy`): сайт 120/мин (без `/healthz` и `/public/*`), API 60, MCP 60, simulate 6, заявки `POST /v1/grants` 10; превышение — 429. Тело > 64 KiB по `Content-Length` — 413; потоковые тела режут `bodyLimit` Fastify (64 KiB в демо), `maxBody` провайдера `demo` (64 KiB) и `mcpBodyLimit`.
- MCP в демо: каталог из одного провайдера, `call` с другим сервисом → `unknown_service` (вне демо код `unknown_provider`).
- Сеть: `installNetworkGuard` заменяет `net.Socket.prototype.connect` (асинхронная ошибка `demo_network_disabled`, loopback тоже), `dns.lookup`/`dns.promises.lookup` (IP-литералы проходят: `listen` вызывает lookup), `dns.resolve*`, глобальный диспетчер undici. Ставится в `bin/gateway.js` до `buildApp`. UDP/`dgram` и исходящие через дочерние процессы не перехватываются (закрывает уровень сервера, `docs/DEPLOY.md`).
- Отступления от контракта: модуль `vault/ssm.js` загружается статическим импортом в `vault/index.js` (клиент SSM в демо не создаётся, `vault !== file` — отказ до `createVault`); `unknown_service` только в демо; `GET /keys/new` разрешён; `approval` ≠ `web_button` отклоняется; сессий в демо до 500.

## tg/bot.js
```js
export function createBot({ token, repo, requests, notify, links, logger, signingKey, auth /* AuthProvider: кто владелец чата */, filterLine? /* (cred) => строка «Агент увидит: …», по умолчанию '' */, apiRoot? /* только тесты: адрес поддельного Telegram API */ }) // -> { start(), stop(), sendRequest(req, cred, agent), editDecided(req, status), send(text) }
export function buildText(req, cred, agent, filterLine?) // -> текст заявки (экспорт для тестов); строка фильтра добавляется после причины, сбой filterLine её пропускает
export function isPrivateFromSelf(chat, from) // -> bool: личный чат и from.id === chat.id (П-8); всё остальное бот игнорирует
```
Команды: `/start <код>` (привязка владельца через one_time_links purpose tg_link), `/open` (ссылка входа), `/keys` (список без значений). Кнопки `approve:<id>:<hmac>` / `deny:<id>:<hmac>`. Для approval tg_code после нажатия бот ждёт 6 цифр в следующем сообщении (60 с). Любой chat, для которого `auth.getUserByTelegram(chatId)` не вернул активного owner → молча игнорировать. Превью ссылок отключено. Текст причины — без parse_mode.

## web/views/*.js — чистые функции (data) => html string
```
layout(title, body, {csrf, flash})      login(), setupWizard(step, data), totpPrompt(action), keys(list, pending),
pickProvider(providers), keyForm(provider, errors), keyDetail(cred), agents(list, credentials, bindings), agentCreated(token),
settings(owner, sessions), audit(rows), statsPage({days, agentId, calls, requests, recent, agents, credentials}), pendingPage({csrf, id, summary, flash}) /* «было → стало», П-19 */, error(code, text)
```
Онбординг (ТЗ §5): `web/onboarding.js` — `KINDS`, `isKind`, `agentNameOf(kind)`, `onboardingState(repo, {telegramConnected}) -> {agent, key, notify, count, skipped, pending, calls}`, `needsWelcome(state)`, `snippetFor(kind, {publicUrl, token})`; `views/welcome.js` — `welcomePage({csrf, state, providers, flash})`, `welcomeAgentCreated({csrf, agent, token, kind, publicUrl})`. Маршруты: `GET /welcome`, `POST /welcome/agent/:kind` (действие `agent.create` с полем `kind`; свежий 2FA и черновик как у `/agents`), `POST /welcome/skip`, `POST /welcome/skip-notify`. Мета: `onboarding_pending` (ставит мастер), `onboarding_skipped`, `onboarding_notify_skipped`. Мастер ведёт на `/welcome`; корень `/` не редиректит, а показывает ссылку на онбординг, пока нет ни агента, ни ключа. Токен только на странице ответа (no-store), в адреса не попадает. `keysPage` принимает `onboarding` (`{count}` или null).
Экранирование всех данных обязательно (`esc()` в views/html.js). Иконки `<img src="/public/icons/<slug>.svg">`.

## web/actions.js и web/pending.js — черновики 2FA (П-19, реализовано; контракт `contracts/drafts-team-auth.md` перенесён сюда)
```js
// actions.js: реестр действий, у которых может понадобиться свежий код. Маршрут и черновик вызывают одну запись реестра.
export const ACTIONS   // frozen: 'key.policy' | 'key.filter' | 'agent.create' | 'agent.keys' | 'notify.channel' (6.3: enabled, events; включение канала требует свежий код); формы с секретом (/keys/new/*, /keys/:id/replace) в реестре НЕТ и не будет
// ActionCtx = { userId, user, sessionHash, hasRecentTotp:boolean, repo, catalog, now, csrf?, telegramConnected? }  (csrf — для html-ответа agent.create, telegramConnected — для parsePolicy)
// ActionDef = { type, perm, fields:(string|RegExp)[] /* allowlist тела; RegExp — ent_<id>, f_<id>, x_<id> фильтра */, targetOf(params), version(ctx,id):string|null /* null = цели нет */,
//   parse(ctx,id,body):{input,errors}, needsFresh(ctx,id,input), apply(ctx,id,input,{fromDraft}):ActionResult /* синхронно: repo + audit; fromDraft -> via:'draft' в audit */,
//   summary(ctx,id,input):{title,before?,after?} /* значения — уже локализованные строки, только изменившиеся поля */, back(id):путь возврата, notFound(ctx,id):ActionResult }
// ActionResult = { redirect, flash?:{type,text} } | { html, code? }
export function runAction(ctx, type, targetId, body, { fromDraft=false }) // -> ActionResult | { needFresh:true, back } | { errors:string[], back }
// pending.js
export const PENDING_TTL = 300
export function pickBody(def, body)   // срез до allowlist; имя key|secret|password|token|code вне RegExp-полей -> throw (значение в сообщение не попадает)
export function createPending({ repo, can?, getUser?, now? }) => {
  save(ctx, type, targetId, body)  // -> id (22 симв.) | null (нет цели/прав); тип вне ACTIONS -> throw. Заменяет черновик сессии. audit pending.saved (type)
  view(ctx, id)                    // -> {status:'ok',id,summary,back} | {status:'gone'|'stale'|'forbidden'|'invalid',back?,errors?}; состояния не меняет
  apply(ctx, id)                   // одна repo.inTransaction: consume -> forbidden -> version (stale) -> hasRecentTotp (needFresh) -> parse заново -> apply; -> ActionResult | {status:'gone'|'stale'|'forbidden'|'needFresh',back?} | {errors,back}
                                   // needFresh, errors и исключение откатывают consume (запись жива до срока); gone/stale/forbidden оставляют запись удалённой. audit pending.applied / pending.stale
  cancel(ctx, id)                  // -> {status:'ok',back} | {status:'gone'}; audit pending.cancelled
}
```
Без `users` (этап 6.4): `getUser` по умолчанию возвращает владельца, если мастер пройден (`owner.setup_done`), `can` пускает только его (`role==='owner'`, не `disabled_at`); `pending_actions.user_id` = `OWNER_USER_ID`, без FK. С появлением `auth/permissions.js` в `createPending` передаётся настоящий `can`, `getUser` читает `users`. Отличия от контракта: `apply` действия принимает 4-й аргумент `{fromDraft}`; в контексте есть `csrf` и `telegramConnected`; `view` может вернуть `invalid` (ошибки разбора при показе); ActionResult с html несёт `code`; сообщение «сохранено как черновик» показывает страница `/totp` (текст в `action`), а не flash, чтобы оно не всплывало после ввода кода; audit `pending.forbidden` не пишется.

## web/server.js
Вход и коды идут через `ctx.auth` (`auth/provider.js`): `POST /login` -> `verifyLogin`, `POST /totp` и код одобрения -> `verifySecondFactor`; блокировки по IP/сессии и потолок ошибок кода на сайт остаются здесь. Смена пароля, перевыпуск 2FA и новые резервные коды (`/settings/password`, `/settings/2fa/{reissue,confirm,backup-codes}`) — через методы провайдера и только при `capabilities.manageCredentials` (иначе 404). Мастер первого запуска тоже ставит пароль и 2FA через провайдер.
Черновик 2FA: `POST /keys/:id/{policy,filter}`, `POST /agents`, `POST /agents/:id/keys` идут через `runDirect` -> `runAction`; нужен код, а его нет — тело сохраняется (`pending.save`) и редирект `/totp?next=/pending/<id>`. `GET /pending/:id` (нет свежего кода -> `/totp?next=/pending/<id>`; иначе страница «было → стало», состояние не меняет), `POST /pending/:id/apply`, `POST /pending/:id/cancel` (обычный CSRF). Выход и закрытие сессий удаляют черновик каскадом, смена пароля и 2FA — `repo.deletePending`, просроченные чистит таймер в `app.js`.
`GET /healthz` → `{ok:true}` (для setup.sh и мониторинга). Маршруты: `GET /setup/:code`, `POST /setup/{password,totp,telegram}`, `GET/POST /login`, `GET /l/:token` (one-time), `POST /totp`, `GET /` (экран 1), `GET /keys/new`, `GET/POST /keys/new/:provider`, `GET /keys/:id`, `POST /keys/:id/{policy,filter,delete,replace}`, `GET/POST /agents...`, `POST /agents/:id/keys` (привязка ключей; расширение доступа — только со свежим кодом), `POST /requests/:id/{approve,deny}` (для approval *_code approve только перенаправляет на форму кода), `GET /requests/:id/approve-confirm` (только форма кода, состояние не меняет, П-6), `POST /requests/:id/approve-code` (код для этой заявки; ошибки копятся в общем счётчике с ботом, П-9), `GET/POST /settings/...` (новый секрет TOTP при перевыпуске и резервные коды — в meta `pending:<вид>:<sha256(сессии)>`, зашифрованы, 10 мин, видит и подтверждает только начавшая сессия; смена пароля и 2FA закрывает остальные сессии, П-7), `GET /stats?d=1|7|30&agent=<id>` (страница «Запросы»), `GET /audit`.
CSRF (П-22, `web/csrf.js`, `csrfPlugin(fastify, { secure, repo, publicUrl })`): токен в каждой форме, `request.csrf` для вью. Токен = base64url(HMAC-SHA256(ключ, 'sid:' + id сессии)); без сессии (в том числе на странице входа) — HMAC от значения pre-session cookie (`gw_pre` / `__Host-gw_pre`, HttpOnly, SameSite=Strict, 1 ч): `'pre:' + значение`. В cookie токен не хранится. Ключ HMAC — 32 случайных байта, создаются один раз, лежат в meta `csrf_key`, в логи не попадают. После входа id сессии меняется, токен тоже: форма, показанная до входа, новой сессией отвергается. Для каждого POST вне `/v1/*` и `/mcp` (у MCP свои проверки Host/Origin) сначала проверяется `Origin` (при его отсутствии `Referer`): origin должен совпасть с origin `publicUrl`, `Origin: null` и чужой — 403 `error.bad_origin`; нет ни того ни другого — проходит дальше; затем сверка тела `_csrf` (`timingSafeEqual`), ошибка — 403 `error.form_expired`. CSP `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'`.

## api/agents.js (fastify plugin, префикс /v1)
`agentApi(fastify, { repo, catalog, requests, grants, proxy, access, limits, logger })`. `POST /v1/grants` выбирает ключ через `access.pickCredential`, `requests.submit({…, via:'rest'})`; агент по токену — `authAgent` из `core/access.js`; прокси-маршрут проверок прав не делает (их выполняет `access.authorizeCall` внутри `proxy.call`), это тонкий адаптер (см. «core/proxy.js»).
`POST /v1/grants`, `GET /v1/grants/:requestId`, `ANY /v1/proxy/:provider/*`. Аутентификация: `Authorization: Bearer gwa_…` (токен агента) для первых двух, `Bearer gwt_…` (пропуск) для proxy. Ошибки: 401/403/429/502 с телом `{ error: code }`.
П. 7.3: одобренный ответ `POST /v1/grants` (200) и `GET /v1/grants/:id` (200) несёт `filter` (`describeFilter`) — только когда у ключа есть фильтр полей, readOnly или mask; без фильтра поля нет. MCP `request_access` и `check_request` (approved) — то же поле `filter` в JSON результата. Скилл `gw.sh`: код выхода 3 — `method_not_allowed`, 4 — `write_not_allowed` (403 прокси), 1 — прочие ошибки, 2 — неверный вызов.

## mcp/server.js (fastify plugin, П-16; перенесено из contracts/access-mcp.md)
```js
export async function mcpPlugin(fastify, { repo, catalog, requests, grants, access, proxy, limits, config, logger, now = Date.now, control = null })
// POST/GET/DELETE /mcp, Streamable HTTP (@modelcontextprotocol/sdk): StreamableHTTPServerTransport + низкоуровневый Server на сессию,
// enableJsonResponse (ответы на POST - JSON), reply.hijack(): в SDK уходят req.raw/res.raw и уже разобранное тело.
// control (необязательный объект) заполняется { sweep(), closeAll(reason), count() }: app.js отдаёт его как app.mcp (тесты, остановка).
```
- Плагин не обёрнут `fastify-plugin`: свои парсеры тела (сырой поток; тело читается после проверок, не больше `mcpBodyLimit`), свой обработчик ошибок. Регистрируется в `app.js` до сайта, когда `config.mcpEnabled`; хуки сайта (cookie, CSRF) на него не действуют, `web/csrf.js` дополнительно пропускает `/mcp`.
- Порядок проверок на каждом запросе: Host (по имени без порта: хост `publicUrl`, плюс `127.0.0.1`/`localhost` при loopback `config.host`) и Origin (`mcpOrigins`; нет Origin - проходит) → Bearer `gwa_` через `authAgent` (неудачи 20/мин на IP, затем 429; у выключенного агента закрывается его сессия) → `limits.mcp` → сессия (`mcp-session-id`; чужая и несуществующая - 404 `session_not_found`, audit `mcp.denied`; DELETE закрывает) → размер тела (413 `payload_too_large`; длина известна - до чтения) → `lastSeen` → транспорт. Сессия создаётся только на `initialize` без id (иначе 400 `session_required`); лимиты сессий - 429 `too_many_sessions`.
- Сессия (только память): `{ id, agentId, createdAt, lastSeen, abort, tokens: Map<credentialId, { token, grantId, requestId, expiresAt, provider }>, inflight }`. Токен `gwt_` попадает в карту из `request_access` (в т.ч. подхват действующего пропуска агента на этот ключ, `mcp.token.bind` с `reuse:true`) и `check_request`; клиенту, в ответы и логи не уходит никогда. `call` без `credential_id` выбирает единственный ключ сервиса, на который у СЕССИИ есть токен. Закрытие (`client|idle|lifetime|agent_disabled|shutdown`): `tokens.clear()`, `abort.abort()`, audit `mcp.session.close`. Проверка простоя, срока жизни и `agent.enabled` - `sweep()` раз в `mcpSweepSec`.
- Инструменты (описания и ошибки - английские константы): `list_services`, `request_access`, `check_request`, `call`; ошибка = `isError:true` и `{"error":"<code>",…}`. Коды, добавленные к REST: `no_grant`, `credential_id_required`, `too_many_calls`, `bad_method`, `bad_headers`, `bad_request`, `unknown_provider`, `unknown_tool`. `call` читает не больше `mcpMaxResponse` байт, обрезка по границе символа UTF-8, в `finally` всегда `body.destroy()`; в ответе `{status,headers,body,truncated,bytes}` (+`binary:true` и `body:null` для не-текстовых типов), заголовки по белому списку.
- Audit: `mcp.session.open` (client), `mcp.session.close` (reason, tokens), `mcp.token.bind` (credential, request, reuse?), `mcp.denied` (origin|host|session_mismatch|too_many_sessions, не чаще раза в минуту, `count`); во всех `via:'mcp'`, `session:<8 hex от sha256(id)>`. Session id целиком в логи и audit не пишется.

## cli.js
```js
export function runInit({ repo, config, log })                       // -> {url, ...счётчики}; resetOwnerSetup + resetPendingStates + audit 'init' + ссылка мастера
export async function runRestore({ config, vault, file, log })       // подмена gw.db, vault.put('sys/signing'), resetPendingStates (П-35), soft-delete ключей без значения в сейфе, audit 'restore'; -> {...счётчики, missing}
export function runAuditRotate({ repo, config, days=90, outDir, log, warn })  // П-37; warn печатает «остановите шлюз» (t('cli.audit_stop_warning'))
```
Ошибки аргументов — `Error` с `exitCode: 2`. Архив аудита: JSON Lines, по строке на запись audit (id, at, actor, action, target, meta_json), файл `audit-ГГГГММДД-ГГГГММДД.jsonl` (диапазон дат строк), режим 0600, пишется во временный файл, fsync, rename; каталог по умолчанию `<dataDir>/audit-archive` (0700). Таблица audit пересоздаётся (триггер append-only запрещает DELETE), поэтому ротация запускается при остановленном шлюзе; планового DELETE нет нигде.

## bin/gateway.js
Тонкая обёртка над `cli.js`. `start` — запуск; `init` — печатает одноразовую ссылку мастера, сбрасывает сессии/пропуска/2FA/пароль (ключи и агенты остаются); `restore <file>` — копирует бэкап, ротирует sys/signing, `resetPendingStates()` (пропуска, сессии, ссылки, pending-заявки, временные секреты 2FA, шаги TOTP), сверяет credentials с сейфом; `audit rotate [--days 90] [--out <dir>]`; `key list`.

## scripts/backup.sh (П-35)
Бэкап только шифрованный: age (`backup.age.pub`) или gpg (`backup.pass`); нет ни того ни другого — ошибка, код 1, открытой копии не остаётся (trap). Сейф ssm: файл `gw-ДАТА.db.age|gpg`. Сейф file (`GW_VAULT=file` в `/etc/agent-gateway/env`): `gw-ДАТА.tar.age|gpg` с `gw.db`, `vault.json` и `master.key`. Мастер-ключ лежит в том же шифруемом архиве: сейф без ключа не восстановить, а отдельное хранение ключа теряется при аварии первым; защита целиком на шифровании архива. Порядок восстановления — `docs/DEPLOY.md`, раздел 5.

---

## Релиз 1.0: контракты новых модулей (утверждены 03.11)

Разделы выше описывают код, который есть сейчас. Контракты того, что делается в релизе 1.0, лежат в `docs/contracts/` и обязательны так же, как этот файл; при реализации модуля его раздел переносится сюда, а файл контракта помечается «перенесено».

| Файл | Что | Находки ТЗ §21 | Этап §19 |
|---|---|---|---|
| `contracts/access-mcp.md` | `core/access.js` (одна проверка вызова для REST и MCP, включая `agent.enabled`), `core/proxy.js` → `call(input)` без Fastify + тонкий адаптер, `mcp/server.js` (сессии, токены пропусков только в памяти сервера, Origin/Host, лимиты) | П-15, П-16, П-34 | 5 (MCP), адаптер — раньше, в 4. `core/access.js` (5.1) и `core/proxy.js` `call(input)` + адаптер REST (5.2) реализованы, перенесены в разделы выше; `mcp/server.js` (5.3) реализован, перенесён в раздел выше |
| `contracts/drafts-team-auth.md` | черновик действия при уходе на 2FA (`web/actions.js`, `web/pending.js`), пользователи и роли (`auth/permissions.js`), `auth/provider.js` (local, слот supabase), сессии по sha256, шаги TOTP в базе | П-19, П-21, П-7, П-32, Н-3 | 0б (черновики), 4 (сессии, TOTP), 8 (команда). Черновики 2FA (`web/actions.js`, `web/pending.js`, 6.1) реализованы и перенесены в разделы выше; сессии по хэшу и `totp_used` — тоже; `auth/provider.js` (6.2, только `local`) реализован, см. раздел выше и `docs/AUTH.md`; остальное (users, роли) ещё нет |
| `contracts/rest-demo-notify.md` | правила фильтра «HTTP-метод + маршрут» для REST, линейный матчер, `readOnly` и `mask` для всех сервисов, демо-режим с изоляцией, каналы уведомлений, лист ожидания, `buildInjection` по типу провайдера, `bitrix24-box` | П-17, П-18, П-20, П-23, П-24, П-27, П-28 | 3 (каталог), 6 (демо), 7 (фильтр B), 8 (уведомления) |

### Общий порядок шагов прокси (сводит contracts/access-mcp.md и contracts/rest-demo-notify.md)

`proxy.call(input)`; первая неудача возвращает `{ok:false,status,error}`, квота тратится только с шага 8.
1. `access.authorizeCall` → 401 `invalid_grant` (одинаково для всех причин).
2. `limits.proxy.take(agent.id)` (300/мин) → 429 `rate_limited`.
3. Путь: decode (400 `bad_path`), `validateAgentPath` сырого и декодированного, `%` после декодирования → 400 `bad_path`; query ≤ 4096 без управляющих символов и «#» → 400 `bad_query`. «#» и «?» в пути (в том числе после декодирования, `%23`/`%3F`) → 400 `bad_path`. Из запроса к сервису убираются `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`. В rpc-фильтре (readOnly.style: rpc, Bitrix24, Telegram) `*` в разрешающих шаблонах (readMethods, методы, типы) не пересекает «/»; в deny «*» по-прежнему покрывает «/» (9.1c).
4. `compileFilter`: `allowMethod(httpMethod, path)` — deny → readOnly/запись → правила и флаги → 403 `method_not_allowed` | `write_not_allowed`; `checkQuery` → 400 `query_not_allowed`. Audit `proxy.denied` агрегируется (не чаще раза в минуту на агента и ключ, со счётчиком).
5. `contentLength > maxBody` → 413 `body_too_large`.
6. `grants.reserve` → 429 `quota_exceeded`; с этого места любой выход освобождает lease.
7. Таймеры: продление lease, общий срок `provider.timeout` через `AbortSignal.any` с `input.signal`.
8. Сейф, заголовки, инъекция ключа, тело (`rewriteSelect` при фильтре), upstream с `accept-encoding: identity`.
9. `Content-Encoding` ≠ identity → 502 `upstream_encoded`.
10. `needsBuffer` (фильтр полей или `mask`): целиком в `min(maxBody, 8 MiB)`, глубина ≤ 32, JSON, `filterBody` → `mask` → `redactText` всех форм секрета; иначе поток через редактор.
11. Lease освобождается по концу или `destroy()` потока тела (`stream.finished`), не по HTTP-ответу. REST-адаптер отменяет по `close` ответа, MCP читает ≤ 64 КиБ и всегда `destroy()`.
12. Audit `proxy.call` со `status, ms, via, session?, fields_removed?, masked?`.
