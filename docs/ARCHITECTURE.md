# Module contracts

All paths are relative to `src/`. All modules are ESM. Below are the public exports; everything else is internal.

## Shared types (JSDoc, no TypeScript)

```js
/** @typedef {{ id:string, provider:string, label:string, kind:'static'|'path', host:string,
 *   injection:Injection, vault_param:string, mode:'always'|'ask'|'deny',
 *   approval:'tg_button'|'tg_code'|'web_button'|'web_code',
 *   max_ttl:number, max_calls:number, max_parallel:number,
 *   window:Window|null, expires_at:number|null, always_until:number|null /* mode='always' until this moment, null = no end */,
 *   last4:string, created_at:number, deleted_at:number|null, filter:DataFilter|null }} Credential */
/** @typedef {{ enabled:boolean, entities:Record<string,string[]>, flags?:Record<string,string[]>, methods:string[], fields:string[] }} DataFilter
 *   // flags[type] = ['search']: explicit extras flags of a type; the key is absent while there are no flags (same as []);
 *   // readOnly?:true and mask?:true are layer 1 protections; the key is absent while they are off
 *   // entities: the data types the catalog opens (deals, leads, ...) -> allowed fields of that type;
 *   // methods + fields: an additional owner rule: path templates with '*' and JSON paths separated by dots
 *   // (arrays are walked through). An old record { preset, methods, fields } is read through normalizeFilter. */
/** @typedef {{ type:'header', name:string, prefix?:string } |
 *            { type:'path', template:string }      // template: '/bot{secret}' or '/rest/{secret}'; {secret} is replaced
 *           } Injection */
/** @typedef {{ days:number[], from:string, to:string, tz:string }} Window  // days: 1..7 (Mon=1), from/to 'HH:MM' */
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
 *   // keep: service fields of the response (errors, pagination) that always stay; deny: methods closed under any filter;
 *   // entities: data types with checkboxes on the key page, defaults: fields checked by default;
 *   // selectFor: methods where the gateway substitutes select from the type's fields (Bitrix24 crm.deal.list, crm.lead.list) */
```

## config.js
```js
export const config = {
  dataDir, dbPath, port, host /* 127.0.0.1 */, publicUrl /* https://gw.example.com */,
  vault: 'ssm'|'file', vaultPrefix /* /gateway */, vaultFile /* dataDir/vault.json for file */,
  ssmRegion, logLevel, bodyLimit /* 2 MiB */, trustProxy: true,
}
```
Read from env: `GW_DATA_DIR, GW_PORT, GW_PUBLIC_URL, GW_VAULT, GW_VAULT_PREFIX, GW_SSM_REGION, GW_LOG_LEVEL, GW_PROXY_RATE_PER_MIN`.
`authProvider` (`GW_AUTH_PROVIDER`; empty = the default provider from `src/auth/provider.js`, an unknown name is a startup error). `buildApp(overrides.auth)` is a ready login provider (tests only).
Demo mode: `demo` (`GW_DEMO=1|true|on`), `demoResetSec` (`GW_DEMO_RESET_SEC`, 3600), `dataDirExplicit` (whether `GW_DATA_DIR` is set), `prodHosts` (`GW_PROD_HOSTS`, comma separated); `buildApp(overrides.env)` is the environment for `assertDemoIsolation` (tests only). Details are in the `demo/` section.
`proxyRatePerMin` (default 300) is the proxy call limit per agent per minute. Through `buildApp(overrides)` (tests only): `logStream` is a pino destination instead of stdout, `now` is the clock for audit aggregation in `core/proxy.js`, `mcpNow` is the clock for MCP sessions (idle time, lifetime, audit aggregation).
MCP (`mcp/server.js`), env `GW_MCP_*`: `mcpEnabled` (`GW_MCP_ENABLED`, on by default; `0|false|off` turns it off), `mcpOrigins` (`GW_MCP_ORIGINS`, comma separated; empty = any request with an `Origin` is rejected), `mcpMaxSessionsPerAgent=5`, `mcpMaxSessions=200`, `mcpIdleSec=900`, `mcpMaxLifetimeSec=86400`, `mcpMaxResponse=65536` (bytes of the service response passed to the model), `mcpBodyLimit=262144` (JSON-RPC body), `mcpCallParallel=4` (concurrent `call` per session), `mcpSweepSec=30` (idle check period; not from env, changed only in tests).
Waiting list link: `config.waitlistUrl` (`GW_WAITLIST_URL`), see the `notify.js` section.

## logger.js
```js
export function createLogger(level, redactHeaders, destination?)   // pino; redact paths come from catalog.redactHeaders(); destination is for tests only
export function maskPath(path, credential)   // '/rest/17/****/crm.lead.add.json'
export function maskUrl(url)   // URL for logs: no query or fragment; /l/<token> and /setup/<code> -> /l/****, /setup/****
```
All URL logging (the access log in `app.js`, error handlers, `sendApiError`) goes only through `maskUrl`. Fastify is created with `logger: false`.

## db/index.js
```js
export function openDb(path)   // -> Database (better-sqlite3), applies schema.sql, WAL, foreign_keys
```
## db/repo.js: all database queries. The constructor takes db.
```js
export function createRepo(db, { demo = false } = {}) => ({
  // demo (only with demo:true): demoWipe(), demoIsolationFacts(), demoResetAge(), demoMarkReset(): see the demo/ section
  // meta
  getMeta(key), setMeta(key, value),
  // owner
  getOwner(), setPasswordHash(hash), setTotp(secretEnc, enabled), setTg(chatId, botParam), setSetupDone(),
  // backup codes
  replaceBackupCodes(hashes[]), useBackupCode(hash) /* -> bool, sets used_at */,
  // sessions
  // Everywhere idHash = sha256(cookie) hex; the raw id never reaches repo (the hash is computed by auth/session.js). Table sessions(id_hash, user_id, ...).
  // user_id is still the constant OWNER_USER_ID='owner' (exported from repo.js) without a foreign key: a key to users will come with the team migration.
  createSession(idHash, expiresAt, ua, userId=OWNER_USER_ID), getSession(idHash) /* null if expired */, touchSession(idHash, newExpiresAt),
  setSessionTotp(idHash), countFullSessions(), deleteSession(idHash), deleteAllSessions(), listSessions() /* rows with id_hash, newest first */,
  // used TOTP steps, table totp_used(user_id, step, used_at, PK(user_id, step))
  takeTotpStep(userId, step) /* -> bool: INSERT OR IGNORE, changes===1; survives a restart */, purgeTotpSteps() /* steps older than 10 minutes; -> n; called by a timer in app.js */,
  // 2FA action drafts, table pending_actions(id PK, session_hash UNIQUE FK sessions(id_hash) ON DELETE CASCADE, user_id, type, target_id, version, body_json, created_at, expires_at)
  // user_id = OWNER_USER_ID without a foreign key (users come later). nowSec is an optional clock override (default unixepoch() in SQL); in production pending.js passes its own clock.
  savePending(sessionHash, { id, userId, type, targetId, version, body, expiresAt }) /* INSERT OR REPLACE: one record per session, the previous id is dead */,
  getPending(sessionHash, id, nowSec?) /* -> {...row, body} | null: missing, another session's, expired */,
  consumePending(sessionHash, id, nowSec?) /* DELETE ... RETURNING: -> row | null; only inside inTransaction together with the execution */,
  deletePending(sessionHash) /* -> bool: cancel, password/2FA change (logout and session close delete by cascade) */, purgePending(nowSec?) /* expired; -> n; called by a timer in app.js */,
  inTransaction(fn) /* db.transaction(fn).immediate(): fn is synchronous (no await), an exception rolls everything back; nested repo transactions become savepoints */,
  // one-time links
  createLink(tokenHash, purpose, expiresAt), consumeLink(tokenHash, purpose) /* -> bool, one-time, atomic */,
  // credentials
  createCredential(cred), getCredential(id) /* without deleted */, listCredentials(), updateCredentialPolicy(id, {mode, approval, max_ttl, max_calls, max_parallel, window, expires_at, always_until, label}),
  endExpiredAlways() /* mode='always' with always_until in the past -> 'ask'; -> Credential[] for notifications (called by expireLoop) */,
  softDeleteCredential(id) /* deleted_at + revoke of all grants: one transaction */, updateCredentialSecretMeta(id, {last4, vault_param}),
  updateCredentialFilter(id, filter /* DataFilter|null */),
  // agents
  createAgent(agent), getAgent(id), getAgentByTokenHash(hash), listAgents(), setAgentEnabled(id, enabled) /* enabled=0 -> revoke all grants of the agent */, deleteAgent(id), touchAgent(id),
  // binding keys to an agent (agents.all_credentials=1: all keys, otherwise only agent_credentials)
  listAgentCredentials(agentId) /* -> credentialId[] */, setAgentCredentials(agentId, {all, ids}) /* one transaction; revokes grants to unbound keys; -> bool */,
  agentCanUse(agentId, credentialId) /* -> bool; checked in POST /v1/grants, on approval and on every proxy call */,
  // statistics (from audit action='proxy.call' and from requests; days is the period back from unixepoch())
  callStats(days) /* -> [{agent_id, credential_id, calls, errors, last_at}] */, requestStats(days) /* -> [{agent_id, credential_id, total, approved, denied, unanswered}] */,
  listCalls({days, agentId, limit}) /* -> [{id, at, target, agent_id, credential_id, status, ms}] */, countOkCalls() /* -> number of proxy.call with a 2xx status over all time (onboarding) */,
  // requests
  createRequest(req), getRequest(id), listPending(), countPendingRequests(agentId, credentialId) /* -> {pair, agent}: non-expired pending requests (the pending cap) */, decideRequest(id, status, via) /* only from pending; -> bool */,
  approveRequest(id, via, grant) /* pending and not expired -> approved + INSERT grant, one transaction; -> bool; UNIQUE grants(request_id) */,
  expireRequests() /* pending with expires_at < now -> expired; -> n */, setRequestTgMessage(id, messageId),
  // grants
  createGrant(grant), getGrant(id), reserveCall(grantId, leaseTtlSec) /* -> leaseId | null; ONE synchronous transaction */,
  releaseCall(leaseId) /* inflight-1, delete lease */, extendLease(leaseId, ttlSec), reapLeases() /* expired leases -> inflight-1 */,
  revokeGrant(id), revokeAllGrants() /* restore/init */, listActiveGrants(),
  // reset of unfinished states, CLI restore/init
  resetPendingStates() /* one transaction: revoke all grants, delete sessions, one_time_links, totp_used; pending requests -> expired (decided_via 'timeout'); remove from meta setup_totp_secret, setup_backup_codes, setup_tg_code, reissue_totp_secret, new_backup_codes and pending:%; -> {grants, sessions, links, requests, meta, totpSteps} */,
  resetOwnerSetup() /* init: password, TOTP, Telegram, setup_done=0, backup_codes empty; keys and agents are untouched */, deleteAllLinks() /* -> n */,
  // audit
  audit(actor, action, target, meta) /* INSERT only */, listAudit({limit, before}),
  rotateAudit(days, writeArchive) /* one transaction; rows older than days days -> writeArchive(rows) (synchronous, BEFORE the swap; if it throws, everything rolls back and the table is intact) -> audit_new, a copy of the newer rows with the same ids, DROP audit (the triggers go with it), RENAME, indexes and both append-only triggers recreated from schema.sql (db/index.js: AUDIT_DDL), the AUTOINCREMENT counter is kept, an audit.rotated record {archived, cutoff, file}; -> {archived, cutoff, file}; if there are no old rows, nothing changes */,
})
```

## catalog.js
```js
export function loadCatalog(yamlPath, { demo = false } = {}) // demo: only providers with demoOnly:true; outside demo mode they are hidden
   // -> { providers: Map<slug, Provider>, get(slug), list(), redactHeaders(): string[],
   //    secretForms(provider, secret): string[] }  // raw, URL-encoded and base64 forms (Basic: also the bare key), longest first; fed to makeRedactor/redactText
export function buildInjection(provider, ownerInput) // -> { host, injection, kind, last4, secret }: normalizes the owner's input
   // chosen by provider.builder, not by fields: static (default) | webhook | subdomain | basic | other (only slug other)
   // static: fixed host, field key
   // webhook: Bitrix24: parse the webhook URL -> host=portal (hostPattern), secret='17/abc', injection {type:'path', template:'/rest/{secret}'}
   // subdomain: amoCRM: host from account by hostTemplate '{account}.amocrm.ru' (a DNS label or a full address) + hostPattern
   // basic (encode: base64): the secret in the vault is `login:key`; Twilio: fixed host, login = account (accountPattern); Zendesk: host from account by hostTemplate, login `email/token` (basicLogin)
   // other: host from the input, header name from the input
   // Key replacement (POST /keys/:id/replace): the same input as when adding (for other, the address and header come from the stored key); if built.host !== credential.host the request is refused with catalog.err.replace_host and nothing is written to the vault
   // Invariant: when provider.host !== 'owner', the result host === provider.host for any input; loadCatalog rejects a fixed host combined with the host or webhook_url field or with builder subdomain/webhook/other
   // Provider fields: builder, hostTemplate, basicLogin, accountPattern, accountPlaceholder (example in the account field), getKeyUrl (https), getKeyHint, onboarding (false hides the card on the first-run screen), sensitive, warning (-> catalog.warn.<slug> on the key form), filterFrom (a copy of another provider's filter and readOnly)
   // Layer 1: readOnly: no field or false: unavailable for the service; true is the same as { style:'rest' } (GET/HEAD); an object { style:'rest'|'rpc', extraRoutes:['POST /route'] (rest, POST reads such as search),
   //   readMethods:['crm.*.list'] (rpc, required), default:true (on at once for new keys: Bitrix24, amoCRM, HubSpot, Pipedrive, Zendesk) }; the description lives at provider level, not inside filter,
   //   because readOnly also works for a service without data types. mask: false means masking is unavailable (LLM and streaming services: OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, Deepgram, ElevenLabs); available by default.
   //   bufferMax is an optional response buffer limit for the field filter or mask (default 8 MiB); the smaller of bufferMax and maxBody is used.
   // REST data filters: hubspot ("Deals without contacts": deals, extras.search, denyQuery associations/propertiesWithHistory/archived, selectFormat comma),
   //   pipedrive ("Deals without persons": v1 and v2 deals, deny persons/organizations/activities/notes, denyQuery person_id/org_id/filter_id; person_id/org_id/user_id are objects and get cut out, user_id.id stays),
   //   zendesk ("Tickets without customer data": tickets, tickets.json; deny users/organizations/requests/search/comments, denyQuery include; requester_id stays, via.channel is visible, subject and description are in the list but not checked by default).
   //   filter.unverified: true means the response shapes were taken from documentation and there was no live check on a test account; the UI shows a note; validated as boolean. Tests: test/rest-providers.test.js, fixtures test/fixtures/{hubspot-deals,pipedrive-deals,zendesk-tickets}.json.
// db/migrate-catalog.js: migrateCatalog(repo, catalog) -> id[]: at startup, bitrix24 keys with a host outside the cloud hostPattern move to bitrix24-box (audit catalog.migrated); the secret is untouched
export function validateKeyFormat(provider, key) // -> null | a message like "this does not look like the right key: expected sk-..."
```

## vault/index.js
```js
export function createVault(config) // -> { get(name), put(name, value), del(name) }: all async, name without prefix: 'cred/<id>', 'sys/signing'
// vault/ssm.js: SSM SecureString, 5 minute in-memory cache, invalidated on put/del.
//   createSsmVault(config, {client?, ttlMs?, now?}): the second argument is for tests only.
//   Generations per name: put/del increase the generation before and after the request; a get that overlaps a write
//   returns the value to the caller but does not cache it (including null on ParameterNotFound).
// vault/file.js: dev/tests: a JSON file encrypted with AES-256-GCM using the master key from dataDir/master.key (0600)
//   + names() -> string[]: file vault only, used to check demo isolation (see the demo/ section)
```

## auth/password.js
```js
export async function hashPassword(pw)        // argon2id 64MiB/3/1, semaphore of 1
export async function verifyPassword(hash, pw)
```
## auth/totp.js
```js
export function generateSecret()                       // base32
export function otpauthUrl(secret, label)              // for the QR code
export function verifyTotp(secret, code, usedStore)    // window +-1; usedStore = { take(step:number):boolean }, implemented by repo.takeTotpStep(userId, step); a step already taken -> false
export function generateBackupCodes()                  // 10 codes of 10 characters
export function hashCode(code)                         // sha256 hex
export function encryptSecret(secret, key) / decryptSecret(enc, key)   // AES-256-GCM, key from vault sys/totp
```
## auth/provider.js: pluggable login module (details in `docs/AUTH.md`)
```js
export const DEFAULT_PROVIDER                          // provider name when config.authProvider is empty
export function createAuthProvider({ config, repo, keys, logger })  // -> AuthProvider; unknown name / unimplemented slot -> throw (startup error)
// AuthUser = { id, login, name, role:'owner'|'viewer', disabled, totpEnabled, tgChatId, externalId }
// AuthProvider = { name, capabilities:{ password, secondFactor:'local'|'provider'|'none', external, manageCredentials },
//   verifyLogin({login?,password,ip?}) -> {ok:true,user}|{ok:false,reason:'bad'|'locked'|'disabled', alert?:'distributed'},  // ip is the client key (IPv6 by /64); alert is the threshold of distributed password guessing, at most once per 15 minutes
//   verifySecondFactor({userId,code,ip?}) -> {ok:true,kind:'totp'|'backup'}|{ok:false,reason:'bad'|'locked'},
//   getUser(userId), getUserByTelegram(chatId),
//   // manageCredentials: setPassword(userId,pw), beginSecondFactorEnrollment(userId)->{secret,otpauthUrl},
//   //   confirmSecondFactorEnrollment(userId,secret,code)->{ok,backupCodes?}, regenerateBackupCodes(userId)->string[] (an addition to the contract)
//   // external: startExternalLogin(req)->{redirect}, finishExternalLogin(req): the supabase slot, not implemented in 1.0 }
```
Only `local` is implemented. Until a `users` table exists, the only user is the owner (`OWNER_USER_ID`, the string `owner`). Inside: argon2 with a dummy hash for an unknown login, `decryptSecret` + `verifyTotp` with `repo.takeTotpStep`, backup codes, in-memory lockouts per "user + address" pair (`u:<id>|<ip>` for the password, `uc:<id>|<ip>` for the code: 5 errors, 15 minutes; IPv6 is collapsed to /64 by the helper `web/client-key.js`, which also keys the demo limits). The global password error counter (50 per 15 minutes, any address) does not block login; it only returns `alert:'distributed'` (the web layer sends the owner `notify.login_distributed`). The code error cap is 30 per hour per user (it protects the 6-digit TOTP; when it is reached the site sends `notify.totp_locked_hour`). The web layer calls the provider only in `POST /login`, `POST /totp`, the request approval code, settings and the setup wizard. With `capabilities.external`, `/login` redirects; with `!manageCredentials`, `/settings/password` and `/settings/2fa/*` answer 404 and are hidden on the page. The bot receives the provider as the `auth` dependency (`getUserByTelegram`, `getUser`). Provider names as strings appear only in `src/auth/`.

## auth/session.js  (fastify plugin)
```js
export function sessionPlugin(fastify, { repo, secure })
export function cookieNames(secure)                    // -> { sid, pre }: on https '__Host-gw_sid' / '__Host-gw_pre', otherwise 'gw_sid' / 'gw_pre'
export function hashSessionId(id)                      // sha256 hex; the only place where the hash is computed
// decorates: request.session (null | {id, idHash, userId, half, totpAt}), reply.startSession(), reply.endSession(), reply.endAllSessions(), request.markTotp(), request.hasRecentTotp()
//   id is the raw cookie value, kept only in request memory (needed for the CSRF HMAC); the database, meta keys, routes and pages use only idHash
// limits: startSession issues a half session (at most 5, the oldest are deleted) and does NOT evict full ones;
//   markTotp makes the session full and evicts the least recently seen (by last_seen_at) down to 3 full sessions
// migration (db/index.js): an old sessions table with an id column is dropped, all sessions are closed, meta 'pending:*' is deleted
// cookie: sid (see cookieNames), HttpOnly, Secure, SameSite=Strict, 12 h, sliding, no longer than 7 days
// on https the __Host- prefix: Path=/, Secure, no Domain; a neighboring subdomain cannot plant such a cookie
// request.requireOwner(): redirect to /login if there is no session
// request.requireRecentTotp(maxAgeSec=300): for dangerous actions; stored in the session as totp_at
```
## auth/links.js
```js
export function makeLink(repo, purpose, ttlSec) // -> { url, token } url = publicUrl + '/l/<token>'; only the sha256 is stored in the database
export function consumeLink(repo, token, purpose) // -> bool
```

## core/ssrf.js
```js
export async function resolvePublic(host) // -> ip (string) or throw (code EPRIVATE); used for Slack, demo, bitrix24-box
export function isPrivateIp(ip)           // true for private or unparseable addresses; the owner host check is isValidOwnerHost in catalog.js, the proxy resolves through safeLookup in proxy.js
export function validateAgentPath(path)   // -> bool: no '..', '@', '://', '#', '?', control characters, length <= 2048 ('#' is cut by undici, '?' is the query boundary; the proxy checks both the raw and the decoded path, so %23 and %3F also give 400 bad_path)
```
// isPrivateIp parses the address canonically: forms with extra zeros, IPv4-mapped and similar are brought to one form before range checks
## core/infra.js: infrastructure errors, one classification
```js
export function isInfraError(err)       // -> bool: err.infra (marked), SqliteError / code SQLITE_*, AWS SDK errors ($metadata, except ParameterNotFound)
export function markInfra(err, source)  // -> err (source 'vault' | 'db')
export function wrapVault(vault)        // get/put/del: any failure is marked with markInfra; applied in vault/index.js
export function sendApiError(err, req, reply, logger) // JSON response of /v1/*: infrastructure -> 503 {error:'service_unavailable'} + Retry-After,
                                        // 400 -> bad_request, otherwise internal; the log has no query and no secrets
export const RETRY_AFTER_SEC            // 5
```
The only places that render these errors: the error handler of the `/v1/*` plugin (`api/agents.js`, the plugin has its own context), the root `setErrorHandler` in `web/server.js` (site pages: 503 + `t('error.unavailable')` + Retry-After) and the `catch` in `proxy.call` (result `ok:false` 503 with `retryAfter`, the header is set by the adapter). Service (network) errors are not covered here.
## core/redact.js
```js
export function makeRedactor(secrets: string[]) // -> { push(chunk:Buffer|string) -> Buffer|string, flush() -> Buffer } ; streaming replacement of the secret with '****', carrying the tail between chunks; flush() returns the held tail at the end of the stream
export function redactText(text, secrets)
```
## core/mask.js: masking of personal data (layer 1), pure functions
```js
export function maskText(s)            // -> { text, n }: card (13-19 digits, Luhn) -> IBAN (mod-97) -> e-mail -> phone, replaced with '****'
export function maskJson(value, limit) // -> { json, n }: string values only; keys, numbers, booleans, null are unchanged; the key "__proto__" is an ordinary field
```
Linear scan by character codes, no RegExp on response data; a candidate that fails the check is not rescanned (1 MiB of "@@@..." and "1 1 1..." take tens of milliseconds).
Deviations and clarifications:
(1) a bare digit string without spaces or dashes counts as a card only if it starts with 2-6 (unix timestamps like "1699..." pass Luhn in 10% of cases, so otherwise "left untouched" examples would fail); digits with spaces and dashes are checked without this condition;
(2) phone: a candidate is not masked if there is ":" next to it, a letter or digit before it, it starts with "YYYY-MM-DD", or it has a single "." separator (a decimal fraction like "12345678901.50"); a run of separators longer than three ends the candidate; an IP address like "192.168.100.200" (12 digits, dots) is masked as a phone;
(3) a string shorter than 6 characters is not scanned; e-mail: local part <= 64, domain <= 255, trailing "." and "-" are not part of the address, the last domain label is letters only, >= 2.

## core/filter.js: data filter, pure functions without I/O
```js
// Layer 1: DataFilter.readOnly and DataFilter.mask (boolean, stored only when true; normalizeFilter keeps them).
//   compileFilter -> null only if !enabled && !readOnly && !mask; the result is extended with { enabled, readOnly, mask, needsBuffer: enabled || mask }.
//   enabled:false with readOnly/mask on: types, deny, select and query rules do not apply, only those two work (allowMethod = the read check only).
//   readOnly: REST: GET/HEAD and the routes of provider.readOnly.extraRoutes; RPC: the templates provider.readOnly.readMethods (the HTTP method does not take part: Bitrix24 accepts methods over GET too).
//   Order inside allowMethod: plainPath -> deny -> readOnly -> rules. denyReason: 'write_not_allowed' for everything cut by readOnly (both REST writes and RPC methods outside readMethods) if the path is not closed by deny.
//   A provider without a read description (a database edit that bypasses the form) with readOnly:true fails closed: REST allows GET/HEAD, RPC allows nothing.
export function protectionOf(provider)    // -> { readOnly:boolean, mask:boolean }: availability on the form and in checkFilter
export function defaultFilterFor(provider) // -> null | DataFilter with readOnly:true (provider.readOnly.default); applied when a key is created
// checkFilter adds filter.err.read_only_unavailable / filter.err.mask_unavailable; weakensFilter: removing readOnly or mask is a weakening even when the field filter is off.
// Form: hidden protect_form=1 + read_only=1 / mask=1 (parseFilter); without protect_form the values stay as they were; a form with protection only does not touch enabled.
// New key: server.js applies defaultFilterFor, protect_form on the create form overrides it (no checkboxes means no protection). The key.filter action is saved for any provider, checkFilter rejects an unavailable one.
// Proxy: with mask, filterBody calls maskJson after prune; audit proxy.call gets masked:N (a number) next to fields_removed; a HEAD/204/304 response is streamed; text/event-stream with needsBuffer -> 502 filtered_stream.
export function compileFilter(filter /* DataFilter|null */, provider) // -> null (filter off) | {
//   allowMethod(httpMethod, path) -> bool  // the path after decoding; plainPath -> deny (any method) -> rules (type, flags, manual).
//                                       // rpc (Bitrix24, default style): the HTTP method does not take part (methodAgnostic), allowMethod(path)
//                                       // with one argument is kept for compatibility. rest (style:'rest'): a rule = METHOD + route (below)
//   denyReason(httpMethod, path) -> null|'method_not_allowed'|'write_not_allowed'  // for 403 and audit (denied_reason); a write outside deny and without a flag is write_not_allowed
//   checkQuery(httpMethod, path, query) -> null|'query_not_allowed'|'hidden_field_filter'  // catalog denyQuery (parameter name, case-insensitive, without [..]); proxy: 400 query_not_allowed.
//                                       // hidden_field_filter is a hook for a later stage and is always null in 1.0
//   rewriteSelect(path, query, body?, contentType?, httpMethod='GET') -> {query, body, error?}  // only for selectFor; the agent's select is replaced
//                                       // (selectFormat 'comma' for REST: ?properties=a,b, other forms of the parameter are removed; no fields: the parameter is removed)
//                                       // in all forms: select/SELECT/select[]/select[N] in the query, the JSON body
//                                       // (array, object with numeric keys) and the urlencoded body. error:'body_not_allowed':
//                                       // a body of an unknown kind or a broken one: the proxy answers 400 and does not reach the service
//   filterBody(json, path, httpMethod='GET') -> {json, removed, masked} // masked is the number of mask replacements; the fields come from the rule the method matched (data type
//                                       // or additional); everything else is removed; removed is the number of cut keys.
//                                       // A field passes only as a scalar (a string longer than maxFieldLen=4000 is truncated);
//                                       // a container only for a catalog field with object:true. keep: scalars, string <= keepMaxLen
//                                       // (256), nested paths through a dot (time.start). prune goes no deeper than 32 levels
//   methods:string[]                   // a hint for the agent
// }
export function normalizeFilter(filter, provider) // -> DataFilter: converts an old record with preset to entities, null -> a disabled filter
export function normalizeMethod(path)      // '/crm.deal.list.json' -> 'crm.deal.list' (lower case, without .json/.xml)
export const FILTER_LIMITS                 // limits: rules 64, segments 12, patternLen 200, stars 2, fields 200, fieldDepth 8, jsonDepth 32
export function globProblem(pattern)       // -> null | 'length' | 'segments' | 'stars'; used by loadCatalog and checkFilter
export function checkJsonDepth(buf, max?)  // -> bool: JSON depth <= 32 by a linear byte pass before JSON.parse (brackets inside strings
                                           // are not counted); on false the proxy answers 502 filtered_too_deep
export function parseRoute(pattern, { deny }?) // -> {method, segs:[{t:'lit'|'param'|'star'|'rest', v?}], text} | {problem:'length'|'segments'|'syntax'|'method'|'rest'}
export const WRITE_METHODS                 // POST PUT PATCH DELETE
// REST style (catalog: filter.style:'rest', a type has routes:['GET /a/:id'] instead of methods, extras:{search:{label,routes}}, fields with paths:[...]):
// "METHOD /segment/:name/*/**"; :name and * match exactly one segment [A-Za-z0-9_.~-]{1,128}, not "." or "..": ** only last and only in deny (where the method is also ANY and
// any method matches); literals are case-insensitive; one trailing "/" is dropped; HEAD matches GET; OPTIONS/TRACE/CONNECT are refused; a leading "//" is refused.
// Matcher: the template segments are built once, the path is split once, one left-to-right pass, no backtracking and no RegExp. ** in deny also matches zero segments.
// A write (POST/PUT/PATCH/DELETE) is never opened by a type or a manual rule: routes with a write are a loadCatalog error, a manual rule is a checkFilter error;
// writes are opened only by extras routes when flags[type] contains the flag. A checked field with paths opens all forms (the identifier in the form is paths[0], also the path after loadCatalog).
// Method templates are matched linearly (two pointers + the last star), without RegExp; a template over the limits
// opens nothing at runtime (in deny it closes everything), a path longer than 12 segments does not match.
// Description of the filter for the agent and the owner:
export function describeFilter(filter, provider) // -> null | { types?:[{id,name,fields:[path],flags?}], extra_fields?:[path], methods:[...], read_only?, mask? }
                                           // null: the key has no field filter, readOnly or mask. types only when enabled; no values and no secrets.
                                           // This is the body of the `filter` field in POST /v1/grants (200), GET /v1/grants/:id (200), MCP request_access and check_request (approved).
export function filterLine(filter, provider) // -> "Agent will see: Deals (ID, Title, +11); read only; personal data hidden" (i18n filter.line*): one line,
                                           // no control characters, <= 400 characters, no markup; a key without a filter: "everything the service returns (no filter)".
                                           // Goes into the request text: Telegram (bot.js buildText), Slack/e-mail (notify.requestCreated), the request card on the site.
export function previewRoute(filter, provider) // -> { method:'GET', path, query:'?limit=1' } | null: the first route without parameters of the first enabled type
                                           // (filter off: of the first catalog type). rpc: `/<method>.json`, rest: the first `GET` from routes without :id and *
export function fieldNames(json)           // -> string[]: field paths without values (result.ID); a key made only of digits -> "*", an unusual key -> "?", <= 500
// Catalog flag filter.unverified:true (HubSpot/Pipedrive/Zendesk, fields from documentation): the new key form and the "What the agent sees" block show filter.unverified.
export function checkFilter(filter, provider) // -> string[] of errors for the form (a method from deny, nothing opened, a type without fields)
export function weakensFilter(next, current)  // -> bool: turning off, a new type, method or field needs a fresh code;
                                              // removing a type while the manual rule is non-empty counts too (the method would fall under the manual fields)
// allowMethod rejects paths with "." or "..", empty segments and "%";
// the segments __proto__/prototype/constructor in field paths are rejected by checkFilter and skipped by buildTree; the key "__proto__" in a response is an ordinary field
```
## core/requests.js
```js
export function createRequestService({ repo, catalog, notify }) => ({
  submit({ agent, credential, ttl, calls, reason, via = 'rest' /* 'rest'|'mcp': goes into meta of audit request.create and grant.auto */ }) // -> { kind:'granted', grant, token } | { kind:'pending', requestId } | { kind:'denied', reason } | { kind:'too_many_pending' } /* > 3 pending for an agent+key pair or > 10 per agent (an automatic pass is not counted); REST 429, MCP isError, code too_many_pending */
  decide({ requestId, approve:boolean, via:'tg'|'web', totp? }) // -> { ok, grant? } | { ok:false, error:'not_pending'|'unavailable'|'use_web'|'bad_code' }
    // approval *_code: the code is checked here for any via; no code, or no verifyTotp, gives 'bad_code'.
    // After the code check, the key, agent, binding and policy are re-read synchronously; the request's ttl/calls
    // are clamped to the current max_ttl/max_calls; the approval and the grant go through repo.approveRequest in one transaction.
  status(requestId) // -> { status, grant?, token? } for the agent's polling
  expireLoop() // setInterval 10s: expireRequests + notification
})
```
Checks in submit: the agent is enabled, the credential exists and is not deleted or expired, the window, the mode; ttl/calls are clamped to the maximums.

## core/grants.js
```js
export function createGrantService({ repo, signingKey, logger }) => ({  // signingKey is a Buffer from vault sys/signing (loadOrCreateSigningKey)
  setKey(key)                  // replace the signing key (startup, tests)
  issue(request, credential, persist?) // -> { grant, token } | null; persist(grant) -> bool, repo.createGrant by default,
                               // on approval it is repo.approveRequest (null: the request is no longer waiting for a decision)
  reissueToken(grant)          // -> { token }  the same pass again (to re-issue an approved request)
  verifyToken(token)           // SYNCHRONOUS -> grant | null  (HS256 signature with the sys/signing key, expiry, then a database check: not revoked, not expired)
  reserve(grantId)             // -> leaseId | null   (synchronous, repo.reserveCall)
  release(leaseId), extend(leaseId)
  reapLoop()                   // setInterval 60s: repo.reapLeases()
})
```
Token: `gwt_` + base64url(JSON{grant_id, exp}) + '.' + base64url(HMAC-SHA256). The signing key is the vault entry `sys/signing` (32 bytes), read at startup.

## core/access.js
```js
export function createAccess({ repo, catalog, grants, requests }) => ({
  authorizeCall({ token, provider, agentId?, credentialId? }) // SYNCHRONOUS -> { ok:true, agent, grant, credential, provider } | { ok:false, code:'invalid_grant', reason }
  pickCredential({ agent, provider /* Provider */, credentialId? }) // -> { ok:true, credential } | { ok:false, error:'credential_id_required', credentials:[{id,label}] } | { ok:false, error:'no_credential' }
})
export function authAgent(repo, token) // -> agent | null: a gwa_... token, its hash, enabled=1; a shared helper for REST (requireAgent) and MCP
export function sha256hex(s)           // re-exported from api/agents.js
```
Order of checks in `authorizeCall` (the first failure returns): token (`grants.verifyToken`) -> `token`; the agent exists and `enabled === 1` -> `agent_disabled`; `agentId` equals `grant.agent_id` -> `agent_mismatch`; the key exists -> `key_missing`, `credentialId` matches -> `credential_mismatch`; `catalog.get(credential.provider).slug === provider` -> `provider_mismatch`; `agentCanUse` -> `not_bound`; `requests.credentialUsable` -> `key_unusable`. From the outside any refusal is 401 `invalid_grant`; `reason` goes only to `logger.debug`/audit, with no token, secrets or host. There is no `await` between `authorizeCall` and `grants.reserve`. It is called only from `proxy` (step 1).
`pickCredential`: the provider's keys available to the agent by `agentCanUse`; an explicit `credentialId` outside the available ones is `no_credential`; without `credentialId`, one available key is used, two or more give `credential_id_required` + `{id,label}`, zero gives `no_credential`.

## core/proxy.js
```js
export function createProxy({ repo, catalog, vault, grants, access, limits, logger, now = Date.now, testUpstream = null, transport = undici.request /* in demo mode createDemoTransport() */ }) => ({
  async call(input) // -> Promise<CallResult>; no Fastify objects. Available as app.ctx.proxy
  async preview(credentialId) // "Check on one call" on the key page -> { ok:true, route:'GET /...', before:string[], after:string[], allowed:bool }
                              //   | { ok:false, error, status? } (preview_no_route | upstream_status | filtered_non_json | filtered_too_large | filtered_too_deep | not_found | service_unavailable...)
})
// preview goes through the same run(): vault, safeLookup (SSRF), the key's fixed host, the secret redactor, the bufferMax response cap; but input.ownerCredentialId is used instead of a token:
// no pass, no limits.proxy, no grants.reserve and no filter (agent quotas are not spent). The call is previewRoute (GET, limit=1). Audit: actor 'owner', action proxy.preview
// (instead of proxy.call), meta { credential, provider, via:'owner', status, ms }. Field names (fieldNames) are taken from the response, "after" is filterBody with the key's filter;
// values are not returned, stored or logged. Site route: POST /keys/:id/preview (owner, CSRF), the response is the key page with a result block.
/** CallInput = { token, provider /* slug */, expectAgentId?, expectCredentialId?, method, path /* raw, with '/', without '?' */, query /* '' | '?a=b' */,
 *   headers /* names in lower case */, body: Buffer|Readable|null, contentLength: number|null, signal?: AbortSignal, via: 'rest'|'mcp', sessionTag? } */
/** CallResult = { ok:false, status, error, extra?: object, retryAfter?: number }
 *             | { ok:true, status, headers, body: Readable } */
```
`expectAgentId`/`expectCredentialId` go to `access.authorizeCall` as `agentId`/`credentialId`. `extra` holds fields the transport adds to the error body (`{allowed}` for `method_not_allowed`). `retryAfter` (seconds) exists only for 503 `service_unavailable`: the adapter sets the `Retry-After` header, it does not go into the body. The result is always a `Readable`; with a filter, `headers` contains `content-length` (the response is assembled whole), without a filter the response is streamed. A `Buffer` in `body` is sent as is; a `Readable` passes through a counter with the `maxBody` limit (exceeding it on the fly gives 413 `body_too_large` and the request to the service is cancelled).
`limits = { requests (30/min), poll (12/min), proxy (proxyRatePerMin), mcp (120/min per agent, all requests to /mcp) }`: `createLimiter`, created in `app.js`; `agentApi` and `mcpPlugin` receive them through the `limits` parameter.
The order of steps in `call` is in the "Proxy step order" section below. In short: `authorizeCall` -> `limits.proxy.take(agent.id)` (429 `rate_limited` before the filter, audit and vault; audit `proxy.rate_limited` at most once a minute per agent, the rest in `count`) -> path (raw and decoded; "%" after decoding gives 400 `bad_path`) and query (<= 4096, no control characters, otherwise 400 `bad_query`) -> data filter: allowMethod (403 `method_not_allowed`, the quota is not spent, audit `proxy.denied` at most once a minute per (agent, key), the others are counted in memory and written as `count` in the meta of the next record) -> `contentLength > maxBody` (413 before the reserve) -> `grants.reserve` (429 `quota_exceeded`) -> timers -> vault -> headers and key injection -> undici -> response. Audit `proxy.call` is written as soon as the status is known (before the body is read to the end): `{grant, agent, credential, provider, status, ms, via, session?, fields_removed?}`.
Lease: the only owner is `core/proxy.js`, tied to the body stream, not to the HTTP response. With `ok:true`, `stream.finished(body, done)` is attached to `body`; `done` once removes the `extend` timer and the deadline and calls `grants.release`. It fires on end, error, `destroy()` and abort. With `ok:false` after the reserve, `done()` is called before `return`. The body stream is built with `pipeline` (service -> secret redactor -> `PassThrough`): `body.destroy()` by the consumer or an abort destroys the request to the service. The consumer must read `body` to the end or call `body.destroy()`; a lost body is cleaned up by the `provider.timeout` deadline (abort + destroy) and `repo.reapLeases()`. The current number of active leases is read as `repo.getGrant(id).inflight`.
REST adapter (`api/agents.js`, `ANY /v1/proxy/:provider/*`): the token from Bearer, the raw path and query from `req.raw.url`, `body = req.raw`, `contentLength` from the header, `signal` from an `AbortController` that fires on `reply.raw` `close` if the response was not finished (`body.destroy()` is called there too), `via:'rest'`; `ok:false` -> `reply.code(status)` + `{error, ...extra}` (+ `Retry-After` when `retryAfter` is set), `ok:true` -> `reply.code`, headers, `reply.send(body)`.
Hop-by-hop headers are removed; the agent's `Authorization` (the pass) is never forwarded upstream; the provider's extraHeaders are added.
Headers are handled by pure functions exported from `proxy.js`: `filterRequestHeaders(headers, extraDrop)` removes the fixed `HOP` list, the prefixes `x-forwarded-`, `cf-`, `x-real-`, `x-envoy-`, `x-amzn-`, `forwarded`, `via`, `accept-encoding`, `extraDrop` (catalog redact headers) and everything named in the request's `Connection` header (comma separated, case-insensitive); `filterResponseHeaders(headers)` removes `RESP_DROP` and everything named in the service response's `Connection`; `connectionTokens(value)` -> `Set<string>`.
Infrastructure errors: a `vault.get` failure before the service is contacted gives 503 `service_unavailable` + `Retry-After`, the service is not called, the lease is released in `finally`. A vault failure inside `proxy.call` is marked with `markInfra`; a database failure before the reserve (authorization, limiter, `reserve`) also gives `{ok:false, status:503, error:'service_unavailable', retryAfter}`; network errors before the service stay 502 `upstream_unreachable`. A failure of `repo.audit`/`grants.release` is logged and does not mask the response.
A response with `Content-Encoding` other than identity gives 502 `upstream_encoded` before any bytes are sent. The total call deadline is `provider.timeout` (an AbortController, combined with `input.signal` through `AbortSignal.any`).

## notify.js
```js
export function createNotifier({ repo, getBot /* () => bot|null */, vault, logger, catalog? /* for the "Agent will see: ..." line in request.created */, publicUrl, channels? /* default createChannels */, timeoutMs? /* 10 s per channel */, test? }) => ({
  channels: Channel[],                              // for demo mode: createNotifier with channels:[] -> channels.length === 0
  requestCreated(request, credential, agent)        // event request.created; telegram: sendRequest (buttons for approval tg_*), slack/email: text + link publicUrl+'/requests'
  requestDecided(request, status)                   // event request.decided; telegram: editDecided
  grantAuto(grant, credential, agent)               // event grant.auto
  info(text, event='info')                          // event info | key.expired | security
  security(text)                                    // = info(text, 'security')
  async idle()                                      // waits for started deliveries (tests)
})  // all methods return a Promise that does not reject; callers (requests.submit and others) do not wait for it
export function createChannels({ repo, getBot, vault, publicUrl, test }) // -> [telegram, slack, email]; Channel = { id, buttons, enabled(), events(), send(msg), test() }
export const EVENTS, DEFAULT_EVENTS, CHANNEL_IDS, SMTP_PORTS
export function checkSlackWebhook(raw) // -> {ok,value}|{ok:false,error:i18n-key}: https, hooks.slack.com, 443, /services/..., no credentials, query or fragment
export function checkSmtp(cfg)         // -> {ok,value:{host,port,user,pass,from,to[]}}|{ok:false,error}: host through isValidOwnerHost, port 587+starttls or 465+tls, otherwise flash.smtp_no_tls
export function emailMessage(msg) / slackPayload(msg)   // pure: the subject has no CR/LF or control characters; Slack: escaping of & < >
export function readChannelMeta(repo, id) / writeChannelMeta(repo, id, {enabled, events, configured}) // meta `notify.<id>`; configured = the secret is saved (a synchronous flag, the value is in the vault)
export const codeOf   // a safe failure code for the log
```
NotifyMessage = `{ event, title, text, url?, raw? }`; `raw` (request, key, agent) is needed only by the telegram channel. A failure log line is `logger.error({ channel, errCode }, 'notify failed')` (the field is not `code`: the logger masks it with stars), without `err.message`, text or URL. Slack: POST through undici to the verified `resolvePublic` IP (SNI and Host `hooks.slack.com`), no redirects, 10 s timeout. E-mail: `nodemailer` through `await import()` at send time, `requireTLS`, `tls:{servername, rejectUnauthorized:true, minVersion:'TLSv1.2'}`, connection to the verified IP, `text/plain` only. Test overrides: `buildApp(overrides)` accepts `notifyChannels`, `notifyTimeoutMs`, `notifyTest:{slackOrigin:'http://127.0.0.1:P', smtp:{host,port}}` (mock Slack and SMTP on localhost); they are not read from env.
Settings: secrets in the vault at `sys/slack_webhook` (a URL string) and `sys/smtp` (JSON `{host,port,user,pass,from,to[]}`); `meta notify.<id>` = `{enabled, events[], configured}`. Telegram is on while the bot is connected.
Routes (`web/server.js`): `POST /settings/notify/{slack,email}/secret` and `/:id/clear` need `requireRecentTotp` (forms with a secret are not drafts); `POST /settings/notify/:id` is the `notify.channel` action of the registry (enabling needs a fresh code, the rest applies at once); `POST /settings/notify/:id/test` sends a test message; `GET /requests` redirects to `/`. Audit: `notify.secret`, `notify.clear`, `notify.channel` (without secret values). `config.waitlistUrl` (`GW_WAITLIST_URL`) is checked by `parseWaitlistUrl` (https, <= 300 characters) in `buildApp`, then `setWaitlistUrl` (`web/views/html.js`) enables the link in the footer of `layout()`.

## demo/: demo mode GW_DEMO=1
Files: `demo/guard.js` (exports `assertDemoIsolation`, `installNetworkGuard`, `demoRouteGuard`, `createDemoTransport`, `createDemoMock`, `createDemoReset`), `demo/mock.js` (the "Demo CRM" mock, host `demo.invalid`), `demo/reset.js` (seed, reset loop, constants `DEMO_AGENT_ID`, `DEMO_CREDENTIAL_ID`, `DEMO_KEY`, `DEMO_KEY_PATTERN`).
```js
// config.js: demo (GW_DEMO), demoResetSec (GW_DEMO_RESET_SEC, 3600), dataDirExplicit (whether GW_DATA_DIR is set), prodHosts (GW_PROD_HOSTS)
assertDemoIsolation({ cfg, db, vault, env = process.env, repo? }) // async; throw Error('demo_isolation: <rule>[ cred/<id>]')
assertDemoDataDirFresh(dataDir)         // buildApp calls it before mkdir/openDb: the directory is empty or has .demo-data
installNetworkGuard() -> { attempts() } // idempotent; attempts() is the number of blocked attempts
demoRouteGuard(fastify, { repo, reset, logger })  // onRequest + onSend + preHandler at the root; called before register(mcp/agentApi) and registerWeb
createDemoTransport({ mock? }) -> (url, opts) => { statusCode, headers, body }  // passed to createProxy({ transport })
createDemoReset({ repo, vault, cfg, logger, onReset? }) -> { runOnce({ hold? }), loop(), get resetting }  // hold is for tests only
```
- Refusal rules of `assertDemoIsolation` (names appear in the message): `vault_not_file`, `cloud_env`, `public_url_is_prod`, `data_dir_not_explicit`, `data_dir_not_empty`, `vault_not_enumerable`, `vault_channel_secret`, `vault_foreign_name` (+ `cred/<id>`), `db_foreign_credential` (+ `cred/<id>`), `db_owner_telegram`, `db_notify_settings`, `db_owner_password`. The `.demo-data` marker is created on the first start; the gateway's own files (`gw.db*`, `master.key`, `vault.json*`) are not counted as foreign in the directory check. Order in `buildApp`: `assertDemoDataDirFresh` -> `openDb` -> `createVault` -> `assertDemoIsolation` -> pass signing key -> the rest -> `runOnce()` (seed) before `listen`.
- `catalog.loadCatalog(path, { demo })`: in demo mode only providers with `demoOnly: true` (`demo`) remain, outside demo mode they are hidden. `repo.createRepo(db, { demo })`: `demoWipe`, `demoIsolationFacts`, `demoResetAge`, `demoMarkReset` exist only with `demo: true`. `core/proxy.js`: the `transport` parameter (default `undici.request`). `vault/file.js`: `names()` (`wrapVault` passes it through). `session.js`: the `demo` option (up to 500 full sessions, `hasRecentTotp` is true for any full session). `views/html.js`: `setDemoMode()`, `isDemo()`, a banner in `layout()`, no "Settings" and "Sign out" links in demo mode; screens hide controls for routes closed by the allowlist (key check, replace, delete; agent enable, disable, delete; approval by code). `views/keys.js`: `keysPage({ demo, scenario })` shows the 3-step scenario, `scenario` is `{ step: 1 }`, `{ step: 2, requestId }` or `{ step: 3, curl }`; the step follows from the visitor's request (per session, in memory), the pass in `curl` comes from `grants.reissueToken` and is not stored.
- A key a visitor added before a restart does not block the start: `assertDemoIsolation` accepts `cred/<id>` only if the database has a credential of the `demo` provider with that id and the value matches `DEMO_KEY_PATTERN`. The reset on start removes it.
- Reset: `meta` is cleared except `csrf_key` (the HMAC key is already in memory in the CSRF plugin); `audit` is emptied by temporarily dropping the append-only trigger (AUDIT_DDL puts it back in the same transaction); `sys/*` in the vault stay, all `cred/*` are replaced by `cred/demo`. The reset itself is not written to audit (audit is empty after it). During the reset and `onReset` (closing MCP sessions), every request except `/healthz` gets 503 `demo_resetting` + `Retry-After: 2`.
- Allowlist: a table in `demoRouteGuard`, everything outside it is 404 (JSON `{error:'not_found'}` for `/v1` and `/mcp`). In addition, `GET /keys/new` is allowed (service choice, the "+" button on the main page; the catalog has one provider). Conditions: `POST /keys/:id/policy|filter` only for a key of the `demo` provider; `POST /keys/new/demo` while there are fewer than 3 keys; `POST /agents` while there are fewer than 5 agents (including `demo-agent`), otherwise 403 `demo_limit`; in bodies `name`/`label` <= 40 characters, `approval` only `web_button` (there is no 2FA code in demo mode), otherwise 400. Limits per IP (`demo:<class>:<ip>`, the IP comes from `trustProxy`): site 120/min (without `/healthz` and `/public/*`), API 60, MCP 60, simulate 6, requests `POST /v1/grants` 10; exceeding gives 429. A body > 64 KiB by `Content-Length` gives 413; streamed bodies are cut by the Fastify `bodyLimit` (64 KiB in demo mode), the `maxBody` of the `demo` provider (64 KiB) and `mcpBodyLimit`.
- MCP in demo mode: the catalog has one provider, `call` with another service gives `unknown_service` (outside demo mode the code is `unknown_provider`).
- Network: `installNetworkGuard` replaces `net.Socket.prototype.connect` (asynchronous error `demo_network_disabled`, loopback too), `dns.lookup`/`dns.promises.lookup` (IP literals pass: `listen` calls lookup), `dns.resolve*`, and the global undici dispatcher. It is installed in `bin/gateway.js` before `buildApp`. UDP/`dgram` and outgoing connections from child processes are not intercepted (the server level covers this, see `docs/DEPLOY.md`).
- Notes: the `vault/ssm.js` module is loaded with a static import in `vault/index.js` (the SSM client is not created in demo mode; `vault !== file` is refused before `createVault`); `unknown_service` exists only in demo mode; `GET /keys/new` is allowed; an `approval` other than `web_button` is rejected; up to 500 sessions in demo mode.

## tg/bot.js
```js
export function createBot({ token, repo, requests, notify, links, logger, signingKey, auth /* AuthProvider: who owns the chat */, filterLine? /* (cred) => the "Agent will see: ..." line, default '' */, apiRoot? /* tests only: address of a fake Telegram API */ }) // -> { start(), stop(), sendRequest(req, cred, agent), editDecided(req, status), send(text) }
export function buildText(req, cred, agent, filterLine?) // -> request text (exported for tests); the filter line is added after the reason, a filterLine failure skips it
export function isPrivateFromSelf(chat, from) // -> bool: a private chat and from.id === chat.id; the bot ignores everything else
```
Commands: `/start <code>` (binds the owner through one_time_links purpose tg_link), `/open` (a login link), `/keys` (a list without values). Buttons `approve:<id>:<hmac>` / `deny:<id>:<hmac>`. For approval tg_code, after the button press the bot waits for 6 digits in the next message (60 s). Any chat for which `auth.getUserByTelegram(chatId)` did not return an active owner is silently ignored. Link previews are disabled. The reason text is sent without parse_mode.

## web/views/*.js: pure functions (data) => html string
```
layout(title, body, {csrf, flash})      login(), setupWizard(step, data), totpPrompt(action), keys(list, pending),
pickProvider(providers), keyForm(provider, errors), keyDetail(cred), agents(list, credentials, bindings), agentCreated(token),
settings(owner, sessions), audit(rows), statsPage({days, agentId, calls, requests, recent, agents, credentials}), pendingPage({csrf, id, summary, flash}) /* "was -> now" */, error(code, text)
```
Onboarding: `web/onboarding.js` has `KINDS`, `isKind`, `agentNameOf(kind)`, `onboardingState(repo, {telegramConnected}) -> {agent, key, notify, count, skipped, pending, calls}`, `needsWelcome(state)`, `snippetFor(kind, {publicUrl, token})`; `views/welcome.js` has `welcomePage({csrf, state, providers, flash})`, `welcomeAgentCreated({csrf, agent, token, kind, publicUrl})`. Routes: `GET /welcome`, `POST /welcome/agent/:kind` (the `agent.create` action with a `kind` field; fresh 2FA and a draft, same as `/agents`), `POST /welcome/skip`, `POST /welcome/skip-notify`. Meta: `onboarding_pending` (set by the wizard), `onboarding_skipped`, `onboarding_notify_skipped`. The wizard leads to `/welcome`; the root `/` does not redirect but shows a link to onboarding while there is no agent and no key. The token appears only on the response page (no-store) and never in URLs. `keysPage` accepts `onboarding` (`{count}` or null).
Request screen: `requestPage({csrf, request, providers, filterLine, flash})`, route `GET /requests/:id` (shows only; decisions stay `POST /requests/:id/approve|deny` with CSRF). `keysPage` takes `keyLine` (the "agent will see" line of the key in the summary card); `keyDetail` optionally takes `credentials`, `pending`, `providers` for the list column; `layout` options `list`, `listHome`, `pendingCount`, `dim`.
Escaping of all data is mandatory (`esc()` in views/html.js). Icons are `<img src="/public/icons/<slug>.svg">`.

## web/actions.js and web/pending.js: 2FA drafts
```js
// actions.js: the registry of actions that may need a fresh code. The route and the draft call the same registry entry.
export const ACTIONS   // frozen: 'key.policy' | 'key.filter' | 'agent.create' | 'agent.keys' | 'notify.channel' (enabled, events; enabling a channel needs a fresh code); forms with a secret (/keys/new/*, /keys/:id/replace) are NOT in the registry and never will be
// ActionCtx = { userId, user, sessionHash, hasRecentTotp:boolean, repo, catalog, now, csrf?, telegramConnected? }  (csrf is for the html response of agent.create, telegramConnected is for parsePolicy)
// ActionDef = { type, perm, fields:(string|RegExp)[] /* body allowlist; a RegExp is ent_<id>, f_<id>, x_<id> of the filter */, targetOf(params), version(ctx,id):string|null /* null = no target */,
//   parse(ctx,id,body):{input,errors}, needsFresh(ctx,id,input), apply(ctx,id,input,{fromDraft}):ActionResult /* synchronous: repo + audit; fromDraft -> via:'draft' in audit */,
//   summary(ctx,id,input):{title,before?,after?} /* values are already localized strings, only changed fields */, back(id):return path, notFound(ctx,id):ActionResult }
// ActionResult = { redirect, flash?:{type,text} } | { html, code? }
export function runAction(ctx, type, targetId, body, { fromDraft=false }) // -> ActionResult | { needFresh:true, back } | { errors:string[], back }
// pending.js
export const PENDING_TTL = 300
export function pickBody(def, body)   // cut to the allowlist; a name key|secret|password|token|code outside the RegExp fields -> throw (the value does not enter the message)
export function createPending({ repo, can?, getUser?, now? }) => {
  save(ctx, type, targetId, body)  // -> id (22 chars) | null (no target or no rights); a type outside ACTIONS -> throw. Replaces the session's draft. audit pending.saved (type)
  view(ctx, id)                    // -> {status:'ok',id,summary,back} | {status:'gone'|'stale'|'forbidden'|'invalid',back?,errors?}; does not change state
  apply(ctx, id)                   // one repo.inTransaction: consume -> forbidden -> version (stale) -> hasRecentTotp (needFresh) -> parse again -> apply; -> ActionResult | {status:'gone'|'stale'|'forbidden'|'needFresh',back?} | {errors,back}
                                   // needFresh, errors and an exception roll back the consume (the record lives until expiry); gone/stale/forbidden leave the record deleted. audit pending.applied / pending.stale
  cancel(ctx, id)                  // -> {status:'ok',back} | {status:'gone'}; audit pending.cancelled
}
```
Without a `users` table: `getUser` returns the owner by default if the wizard is done (`owner.setup_done`), `can` lets in only the owner (`role==='owner'`, not `disabled_at`); `pending_actions.user_id` = `OWNER_USER_ID`, without a foreign key. When `auth/permissions.js` appears, a real `can` is passed to `createPending` and `getUser` reads `users`. Notes: the action's `apply` takes a 4th argument `{fromDraft}`; the context carries `csrf` and `telegramConnected`; `view` may return `invalid` (parse errors at display time); an ActionResult with html carries `code`; the "saved as a draft" message is shown by the `/totp` page (the text is in `action`), not by a flash, so it does not pop up after the code is entered; audit `pending.forbidden` is not written.

## web/server.js
Login and codes go through `ctx.auth` (`auth/provider.js`): `POST /login` -> `verifyLogin`, `POST /totp` and the approval code -> `verifySecondFactor`; lockouts by IP and session and the cap of code errors per site stay here. Password change, 2FA re-issue and new backup codes (`/settings/password`, `/settings/2fa/{reissue,confirm,backup-codes}`) go through the provider methods and only with `capabilities.manageCredentials` (otherwise 404). The first-run wizard also sets the password and 2FA through the provider.
2FA draft: `POST /keys/:id/{policy,filter}`, `POST /agents`, `POST /agents/:id/keys` go through `runDirect` -> `runAction`; if a code is needed and there is none, the body is saved (`pending.save`) and the redirect is `/totp?next=/pending/<id>`. `GET /pending/:id` (no fresh code -> `/totp?next=/pending/<id>`; otherwise a "was -> now" page, state does not change), `POST /pending/:id/apply`, `POST /pending/:id/cancel` (normal CSRF). Logout and session close delete the draft by cascade, a password or 2FA change calls `repo.deletePending`, and expired drafts are cleaned by a timer in `app.js`.
`GET /healthz` -> `{ok:true}` (for setup.sh and monitoring). Routes: `GET /setup/:code`, `POST /setup/{password,totp,telegram}`, `GET/POST /login`, `GET /l/:token` (one-time), `POST /totp`, `GET /` (screen 1), `GET /keys/new`, `GET/POST /keys/new/:provider`, `GET /keys/:id`, `POST /keys/:id/{policy,filter,delete,replace}`, `GET/POST /agents...`, `POST /agents/:id/keys` (key binding; widening access only with a fresh code), `POST /requests/:id/{approve,deny}` (for approval *_code, approve only redirects to the code form), `GET /requests/:id/approve-confirm` (the code form only, state does not change), `POST /requests/:id/approve-code` (the code for this request; errors accumulate in the counter shared with the bot), `GET/POST /settings/...` (a new TOTP secret on re-issue and backup codes are kept in meta `pending:<kind>:<sha256(session)>`, encrypted, 10 minutes, visible and confirmable only by the session that started it; a password or 2FA change closes the other sessions), `GET /stats?d=1|7|30&agent=<id>` (the "Requests" page), `GET /audit`.
CSRF (`web/csrf.js`, `csrfPlugin(fastify, { secure, repo, publicUrl })`): a token in every form, `request.csrf` for views. Token = base64url(HMAC-SHA256(key, 'sid:' + session id)); without a session (including the login page) it is an HMAC of the pre-session cookie value (`gw_pre` / `__Host-gw_pre`, HttpOnly, SameSite=Strict, 1 h): `'pre:' + value`. The token is not stored in a cookie. The HMAC key is 32 random bytes created once and kept in meta `csrf_key`; it never reaches logs. After login the session id changes and so does the token: a form shown before login is rejected by the new session. For every POST outside `/v1/*` and `/mcp` (MCP has its own Host/Origin checks), `Origin` is checked first (`Referer` if it is missing): the origin must match the origin of `publicUrl`; `Origin: null` or a foreign one gives 403 `error.bad_origin`; if neither header is present the request passes on; then the body `_csrf` is compared (`timingSafeEqual`), an error gives 403 `error.form_expired`. CSP `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'`.

## api/agents.js (fastify plugin, prefix /v1)
`agentApi(fastify, { repo, catalog, requests, grants, proxy, access, limits, logger })`. `POST /v1/grants` picks the key through `access.pickCredential` and calls `requests.submit({..., via:'rest'})`; the agent is found by token with `authAgent` from `core/access.js`; the proxy route does no permission checks itself (`access.authorizeCall` does them inside `proxy.call`), it is a thin adapter (see "core/proxy.js").
`POST /v1/grants`, `GET /v1/grants/:requestId`, `ANY /v1/proxy/:provider/*`. Authentication: `Authorization: Bearer gwa_...` (the agent token) for the first two, `Bearer gwt_...` (the pass) for proxy. Errors: 401/403/429/502 with the body `{ error: code }`.
The approved response of `POST /v1/grants` (200) and `GET /v1/grants/:id` (200) carries `filter` (`describeFilter`) only when the key has a field filter, readOnly or mask; without a filter the field is absent. MCP `request_access` and `check_request` (approved) put the same `filter` field in the JSON result. The `gw.sh` skill: exit code 3 is `method_not_allowed`, 4 is `write_not_allowed` (proxy 403), 1 is any other error, 2 is a wrong invocation.

## mcp/server.js (fastify plugin)
```js
export async function mcpPlugin(fastify, { repo, catalog, requests, grants, access, proxy, limits, config, logger, now = Date.now, control = null })
// POST/GET/DELETE /mcp, Streamable HTTP (@modelcontextprotocol/sdk): StreamableHTTPServerTransport + a low-level Server per session,
// enableJsonResponse (POST responses are JSON), reply.hijack(): req.raw/res.raw and the already parsed body go to the SDK.
// control (an optional object) is filled with { sweep(), closeAll(reason), count() }: app.js exposes it as app.mcp (tests, shutdown).
```
- The plugin is not wrapped with `fastify-plugin`: it has its own body parsers (a raw stream; the body is read after the checks, no more than `mcpBodyLimit`) and its own error handler. It is registered in `app.js` before the site, when `config.mcpEnabled`; the site hooks (cookie, CSRF) do not apply to it, and `web/csrf.js` additionally skips `/mcp`.
- Order of checks on every request: Host (by name without port: the host of `publicUrl`, plus `127.0.0.1`/`localhost` when `config.host` is loopback) and Origin (`mcpOrigins`; no Origin passes) -> Bearer `gwa_` through `authAgent` (failures: 20/min per IP, then 429; for a disabled agent its session is closed) -> `limits.mcp` -> session (`mcp-session-id`; a foreign or nonexistent one gives 404 `session_not_found`, audit `mcp.denied`; DELETE closes it) -> body size (413 `payload_too_large`; when the length is known, before reading) -> `lastSeen` -> transport. A session is created only on `initialize` without an id (otherwise 400 `session_required`); session limits give 429 `too_many_sessions`.
- Session (memory only): `{ id, agentId, createdAt, lastSeen, abort, tokens: Map<credentialId, { token, grantId, requestId, expiresAt, provider }>, inflight }`. A `gwt_` token enters the map from `request_access` (including picking up the agent's active pass for that key, `mcp.token.bind` with `reuse:true`) and from `check_request`; it never goes to the client, responses or logs. `call` without `credential_id` selects the only key of the service for which the SESSION has a token. Closing (`client|idle|lifetime|agent_disabled|shutdown`): `tokens.clear()`, `abort.abort()`, audit `mcp.session.close`. The idle, lifetime and `agent.enabled` checks run in `sweep()` every `mcpSweepSec`. A process restart loses all sessions and tokens; a grant stays valid until it expires, and the client gets 404 and makes a new `initialize`.
- Tools (descriptions and errors are English constants, `t()` is not used): `list_services`, `request_access`, `check_request`, `call`; an error is `isError:true` and `{"error":"<code>",...}`. Codes added on top of REST: `no_grant`, `credential_id_required`, `too_many_calls`, `bad_method`, `bad_headers`, `bad_request`, `unknown_provider`, `unknown_tool`. `call` reads at most `mcpMaxResponse` bytes, truncating on a UTF-8 character boundary, and always runs `body.destroy()` in `finally`; the response is `{status,headers,body,truncated,bytes}` (+`binary:true` and `body:null` for non-text types), with headers from an allowlist.
- Audit: `mcp.session.open` (client), `mcp.session.close` (reason, tokens), `mcp.token.bind` (credential, request, reuse?), `mcp.denied` (origin|host|session_mismatch|too_many_sessions, at most once a minute, `count`); all with `via:'mcp'`, `session:<8 hex of sha256(id)>`. The full session id is never written to logs or audit.

### MCP tool reference

| Tool | Input | Output (JSON in `content[0].text`) |
|---|---|---|
| `list_services` | none | `{services:[{slug,name,credentials:[{id,label,usable:boolean,mode:'always'\|'ask',max_ttl,max_calls,filter:{methods,fields}\|null,access:{state:'active'\|'none',expires_at?,calls_left?}}]}]}` |
| `request_access` | `service`, `credential_id?`, `ttl?`, `calls?`, `reason` | `{status:'approved',credential_id,expires_at,max_calls}` or `{status:'pending',request_id,poll_after:5}` or an error |
| `check_request` | `request_id` | `{status:'pending',poll_after:5}` / `{status:'approved',credential_id,expires_at,max_calls}` / `{status:'denied'\|'expired'\|'revoked'}` |
| `call` | `service`, `method`, `path`, `credential_id?`, `body?`, `headers?` | `{status,headers,body,truncated,bytes}` |

- `list_services`: only services where the agent has at least one key by `agentCanUse`; no key values and no host; `usable` = `credentialUsable(cred)===null`; `access` is built from the session `tokens` + `repo.getGrant` (without the token); `filter` holds method templates and field paths from `compileFilter` (no values).
- `request_access`: `access.pickCredential` (errors `unknown_provider`, `no_credential`, `credential_id_required` + `credentials:[{id,label}]`, as in `POST /v1/grants`), `limits.requests`, `requests.submit({..., via:'mcp'})`. `denied` gives `{error:'denied', reason}` (reason is the service text in the owner's language, as in REST). `too_many_pending` and other submit codes are passed through as is.
- `check_request`: `limits.poll` per (agent, request_id); `repo.getRequest(id)`; `!r || r.agent_id !== agent.id` gives `not_found` (a foreign request looks the same as a missing one). A request made by another session of the same agent can be read (one owner per agent); the token is bound to the current session.
- `call`: (1) `method` is one of `GET|POST|PUT|PATCH|DELETE`, otherwise `bad_method`; at most `mcpCallParallel` concurrent calls per session (`too_many_calls`). (2) Key: an explicit `credential_id`, otherwise the only key of the service available to the agent, otherwise `credential_id_required` + `credentials:[{id,label}]`. (3) The token comes from `tokens.get(credentialId)`; none gives `no_grant` ("call request_access first"); a missing token is the state of the session itself, not an access refusal. (4) `path` is split at the first `?` into `path` and `query`; `#` gives `bad_path`; a path not starting with `/` gives `bad_path`. (5) `body` is a string or a JSON value; an object is serialized to a `Buffer` (`content-type: application/json` unless set); size <= `provider.maxBody` and <= `mcpBodyLimit`, otherwise `body_too_large`; for GET a `body` is not allowed (`bad_request`). (6) `headers` is an object of strings, <= 20 entries, a value <= 1024 characters, no CR/LF; the core filters the rest (the same `HOP`, `authorization`, key injection). (7) `proxy.call({ token, provider, expectAgentId: session.agentId, expectCredentialId, ..., signal: session.abort.signal combined with extra.signal, via:'mcp', sessionTag })`. (8) `ok:false` gives `isError` with `{error, status, ...extra}` (the same codes as REST: `invalid_grant`, `bad_path`, `bad_query`, `method_not_allowed`+`allowed`, `body_too_large`, `rate_limited`, `quota_exceeded`, `upstream_encoded`, `filtered_non_json`, `filtered_too_large`, `upstream_unreachable`). (9) With `ok:true`, `body` is read up to `mcpMaxResponse + 1` bytes, then `finally { body.destroy() }`; `truncated:true` if the limit is exceeded (cut on a UTF-8 character boundary); the secret has already been scrubbed by the core's streaming redactor BEFORE truncation. (10) Result: `status` is the service status (a 4xx/5xx from the service is not `isError`); `headers` come only from an allowlist (`content-type`, `content-language`, `etag`, `last-modified`, `retry-after`, `link`, `x-total-count`, `x-ratelimit-*`); `body` is UTF-8 text for `text/*`, `application/json`, `*+json`, `application/xml`, `*+xml`, `application/x-www-form-urlencoded`; for other types `body:null, binary:true`, and `bytes` is the number of bytes read.

## cli.js
```js
export function runInit({ repo, config, log })                       // -> {url, ...counters}; resetOwnerSetup + resetPendingStates + audit 'init' + the wizard link
export async function runRestore({ config, vault, file, log })       // swaps gw.db, vault.put('sys/signing'), resetPendingStates, soft-deletes keys with no value in the vault, audit 'restore'; -> {...counters, missing}
export function runAuditRotate({ repo, config, days=90, outDir, log, warn })  // warn prints "stop the gateway" (t('cli.audit_stop_warning'))
```
Argument errors are an `Error` with `exitCode: 2`. The audit archive is JSON Lines, one line per audit record (id, at, actor, action, target, meta_json), in the file `audit-YYYYMMDD-YYYYMMDD.jsonl` (the date range of the rows), mode 0600, written to a temporary file, fsync, rename; the default directory is `<dataDir>/audit-archive` (0700). The audit table is recreated (the append-only trigger forbids DELETE), so rotation runs while the gateway is stopped; there is no scheduled DELETE anywhere.

## bin/gateway.js
A thin wrapper over `cli.js`. `start` starts the gateway; `init` prints the one-time wizard link and resets sessions, passes, 2FA and password (keys and agents stay); `restore <file>` copies the backup, rotates sys/signing, runs `resetPendingStates()` (passes, sessions, links, pending requests, temporary 2FA secrets, TOTP steps) and checks credentials against the vault; `audit rotate [--days 90] [--out <dir>]`; `key list`.

## scripts/backup.sh
Backups are encrypted only: age (`backup.age.pub`) or gpg (`backup.pass`); with neither, it exits with code 1 and no plain copy is left (trap). SSM vault: the file `gw-DATE.db.age|gpg`. File vault (`GW_VAULT=file` in `/etc/agentkeygate/env`): `gw-DATE.tar.age|gpg` containing `gw.db`, `vault.json` and `master.key`. The master key is in the same encrypted archive: a vault cannot be restored without it, and a separately stored key is the first thing lost in a disaster; all protection rests on encrypting the archive. The restore procedure is in `docs/DEPLOY.md`, section 5.

---

## Not implemented yet

- A `users` table, roles and `auth/permissions.js` (team access). Today the only user is the owner (`OWNER_USER_ID`); `sessions.user_id`, `pending_actions.user_id` and `totp_used.user_id` are plain columns without a foreign key.
- The `supabase` slot of the login provider (see `docs/AUTH.md`).
- A hook for filtering by field values (`hidden_field_filter` in `checkQuery`), always `null` today.

## Proxy step order

`proxy.call(input)`; the first failure returns `{ok:false,status,error}`; the quota is spent only from step 6.
1. `access.authorizeCall` -> 401 `invalid_grant` (the same for every reason).
2. `limits.proxy.take(agent.id)` (300/min) -> 429 `rate_limited`.
3. Path: decode (400 `bad_path`), `validateAgentPath` on the raw and the decoded path, "%" after decoding -> 400 `bad_path`; query <= 4096 without control characters and "#" -> 400 `bad_query`. "#" and "?" in the path (also after decoding, `%23`/`%3F`) -> 400 `bad_path`. `X-HTTP-Method-Override`, `X-Method-Override` and `X-HTTP-Method` are removed from the request to the service. In an rpc filter (readOnly.style: rpc, Bitrix24, Telegram) `*` in allowing templates (readMethods, methods, types) does not cross "/"; in deny, "*" still covers "/".
4. `compileFilter`: `allowMethod(httpMethod, path)`: deny -> readOnly/write -> rules and flags -> 403 `method_not_allowed` | `write_not_allowed`; `checkQuery` -> 400 `query_not_allowed`. Audit `proxy.denied` is aggregated (at most once a minute per agent and key, with a counter).
5. `contentLength > maxBody` -> 413 `body_too_large`.
6. `grants.reserve` -> 429 `quota_exceeded`; from here every exit releases the lease.
7. Timers: lease extension, the total deadline `provider.timeout` through `AbortSignal.any` with `input.signal`.
8. Vault, headers, key injection, body (`rewriteSelect` with a filter), upstream with `accept-encoding: identity`.
9. `Content-Encoding` other than identity -> 502 `upstream_encoded`.
10. `needsBuffer` (field filter or `mask`): the whole response up to `min(maxBody, 8 MiB)`, depth <= 32, JSON, `filterBody` -> `mask` -> `redactText` of all secret forms; otherwise a stream through the redactor.
11. The lease is released at the end or on `destroy()` of the body stream (`stream.finished`), not at the HTTP response. The REST adapter cancels on `close` of the response, MCP reads <= 64 KiB and always calls `destroy()`.
12. Audit `proxy.call` with `status, ms, via, session?, fields_removed?, masked?`.
