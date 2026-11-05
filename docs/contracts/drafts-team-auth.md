# Контракты B: черновики 2FA, команда, auth/provider

Черновик правок для `docs/ARCHITECTURE.md` (код не трогаем). Покрывает ТЗ §5 (сохранение формы при 2FA), §6, §13, §21 П-19, П-21, П-7, П-22 (в части CSRF черновика), П-32, Н-3. Расхождения с ТЗ помечены «ТЗ:».

Общее решение для всех трёх частей: **сессия живёт в базе под `sha256(id)`, всё, что привязано к сессии (черновик, секрет перевыпуска 2FA), хранится в таблицах с `ON DELETE CASCADE` на сессию.** Закрыли сессии пользователя (понижение, отключение, смена пароля) — черновики и временные секреты исчезли сами, отдельной чистки нет.

---

## Черновики 2FA

### Что и когда сохраняем
Только когда действие из формы требует свежего кода (`hasRecentTotp` ложь) и пользователь перенаправляется на `/totp`. Допустимые типы (allowlist, остальное сохранить нельзя):

| type | форма | target_id | version (хэш текущего состояния) | поля тела (allowlist) |
|---|---|---|---|---|
| `key.policy` | `POST /keys/:id/policy` | credential id | политика: mode, approval, max_ttl, max_calls, max_parallel, window_json, expires_at, always_until, label, deleted_at | поля `parsePolicy` |
| `key.filter` | `POST /keys/:id/filter` | credential id | `filter_json`, deleted_at | поля `parseFilter` |
| `agent.create` | `POST /agents` | `''` | `''` (существование ключей проверяется при исполнении) | name, all, ids[] |
| `agent.keys` | `POST /agents/:id/keys` | agent id | all_credentials + отсортированные ids + enabled | all, ids[] |

Не сохраняются никогда: формы с секретом (`/keys/new/*`, `/keys/:id/replace`; после 2FA они просят ключ заново), смена пароля, 2FA, Telegram, приглашения (там нет значений, которые жалко потерять, после кода пользователь жмёт кнопку снова). `_csrf` в тело не попадает. Тело проходит allowlist полей своего типа; поле с именем `key|secret|password|token|code` в теле — ошибка программиста (assert в `save`).

### Общий реестр действий (один путь для прямого вызова и черновика)
`src/web/actions.js`. Маршрут и исполнение черновика вызывают одну и ту же запись реестра, дублирования проверок нет.

```js
/** @typedef {{ userId:string, user:User, sessionHash:string, hasRecentTotp:boolean, repo, catalog, now:()=>number }} ActionCtx */
/** @typedef {{ type:string, perm:string,                                // perm — имя из матрицы прав (can)
 *   fields:string[],                                                    // allowlist полей тела
 *   targetOf(params):string,
 *   version(ctx, targetId):string|null,                                 // null = цели нет (удалена) -> 404/устарело
 *   parse(ctx, targetId, body):{ input:object, errors:string[] },       // та же валидация, что в маршруте
 *   needsFresh(ctx, targetId, input):boolean,                           // weakensPolicy / weakensFilter / widens / agent.create
 *   apply(ctx, targetId, input):ActionResult,                           // СИНХРОННО: repo-вызовы + audit, без await
 *   summary(ctx, targetId, input):{ title:string, before?:object, after?:object } }} ActionDef */
/** @typedef {{ redirect:string, flash?:{type:'ok'|'error', text:string} } | { html:string }} ActionResult */
export const ACTIONS   // Record<type, ActionDef>
export function runAction(ctx, type, targetId, body, { fromDraft=false }) // -> ActionResult | { needFresh:true } | { errors:string[] }
```
Правило: `apply` синхронный (транзакции better-sqlite3), поэтому типы, которым нужен `await` (сейф), в черновики не входят.

### Таблица и repo
```js
// repo (см. схему ниже)
savePending(sessionHash, { id, userId, type, targetId, version, body, expiresAt }) // INSERT OR REPLACE по UNIQUE(session_hash): одна запись на сессию, старая id мертва
getPending(sessionHash, id)     // -> row | null (нет, чужая сессия, просрочена)
consumePending(sessionHash, id) // DELETE ... WHERE id=? AND session_hash=? AND expires_at>unixepoch() RETURNING * -> row|null. Вызывать только внутри db.transaction вместе с apply
deletePending(sessionHash)      // отмена, выход
purgePending()                  // просроченные; вызывается из reapLoop
```

### Модуль `src/web/pending.js`
```js
export const PENDING_TTL = 300
export function createPending({ repo, can, now }) => ({
  save(ctx, type, targetId, body)   // -> id (22 симв. base64url от 16 байт). Проверяет type из allowlist, can(user, perm, target), срезает body до fields,
                                    // version = ACTIONS[type].version(ctx, targetId). Заменяет прежний черновик сессии.
  view(ctx, id)                     // -> { status:'ok', summary, id } | { status:'gone'|'stale'|'forbidden' }. Состояния не меняет.
  apply(ctx, id)                    // -> ActionResult | { status:'gone'|'stale'|'forbidden'|'needFresh'|{errors} }
  cancel(ctx, id)
})
```
`apply` целиком — одна `db.transaction(...).immediate()`:
1. `row = consumePending(sessionHash, id)`; нет → `gone`. (Повтор и двойное нажатие дают `gone`: запись уже удалена тем же коммитом, что и изменение.)
2. `row.user_id === ctx.userId`, пользователь перечитан из базы, `disabled_at IS NULL`, `can(user, def.perm, target)`; иначе `forbidden` (откат не нужен: запись остаётся удалённой, транзакцию завершаем штатно).
3. `def.version(ctx, row.target_id) !== row.version` → `stale` (черновик остаётся удалённым).
4. `ctx.hasRecentTotp` ложь → бросить `NeedFresh` (откат, запись жива до срока, пользователь ещё раз идёт на `/totp`).
5. `def.parse(...)` заново (вдруг каталог/правила изменились); ошибки → откат, запись жива, вернуть errors.
6. `def.apply(...)` + audit. Любое исключение откатывает и consume.

### Маршруты и продолжение после `/totp`
- Маршрут (`/keys/:id/policy`, …) при `needsFresh && !hasRecentTotp`: `id = pending.save(...)`, flash «Сохранено как черновик, введите код», `redirect('/totp?next=/pending/' + id)`. Если действие не требует кода или код свежий — исполняется сразу, черновик не создаётся.
- `GET /pending/:id` (нужна полная сессия и `can`): `view`; нет свежего кода → `redirect('/totp?next=/pending/:id')`; `ok` → страница «Применить сохранённые изменения?» с «было → стало» (`summary`) и двумя кнопками-формами `POST /pending/:id/apply`, `POST /pending/:id/cancel` с CSRF сессии. `gone/stale` → flash и редирект на страницу цели (или `/`).
- `POST /pending/:id/apply`: обычный CSRF-хук, затем `pending.apply`. Успех — результат действия (редирект с flash или html, как `agentCreated` с токеном, показанным один раз). `stale` → «Ключ изменили, пока вы вводили код. Введите значения заново». `needFresh` → снова `/totp`.
- `/totp` уже работает: `safeNext` пропускает `/pending/<id>` (символы `A-Za-z0-9_-`), менять нечего. Неверный код — черновик живёт до срока, `next` сохраняется. Выход, смена пароля, понижение, отключение — сессия удалена, черновик удалён каскадом.
- ТЗ: GET не меняет состояние (Н-5), поэтому после кода показываем страницу подтверждения, а не применяем из `GET /pending/:id`. Применение прямо в `POST /totp` — вариант, см. вопросы.
- П-22: токен CSRF формы берётся из сессии пользователя; черновик не хранит и не принимает токен из тела.

### Аудит
`pending.saved` (type, target, без тела), `pending.applied` (то же, что обычное действие: `credential.policy` / `filter.changed` / `agent.create` / `agent.keys` + `via:'draft'`), `pending.stale`, `pending.cancelled`. Значения в `pending.*` не пишутся.

---

## Пользователи и роли

### Модель
```js
/** @typedef {{ id:string, login:string, name:string, role:'owner'|'viewer', password_hash:string|null,
 *   totp_secret_enc:string|null, totp_enabled:0|1, tg_chat_id:number|null, external_id:string|null,
 *   disabled_at:number|null, created_at:number }} User */   // id: 8 байт base64url; actor в аудите = 'user:'+id
```
ТЗ: добавлены `login` (нужен для входа, когда пользователей больше одного) и `external_id` (слот под Supabase). Общие настройки владельца переезжают в `meta`: `tg_bot_param`, `setup_done`.

Правила:
- «Удалить участника» = `disabled_at` навсегда (строка нужна аудиту): обнуляются `password_hash`, `totp_secret_enc`, `tg_chat_id`, резервные коды удаляются. Включить обратно нельзя, новый человек — новое приглашение (вариант в вопросах). «Отключить» без обнуления не вводим, чтобы не плодить два состояния.
- Пользователь «активен», если `disabled_at IS NULL AND totp_enabled=1`.
- Пока приглашённый не завершил 2FA (`totp_enabled=0`), войти он не может; строки старше 24 ч с `totp_enabled=0` удаляет `repo.purgeUnenrolled()` (из `reapLoop`).

### Матрица прав `src/auth/permissions.js`
Единственное место, где написано, кто что может. Чистая функция, без I/O.
```js
export const ACTIONS    // frozen Set имён
export function can(user /* User|null */, action /* string из ACTIONS */, target /* { userId?:string }|undefined */) // -> bool
// Правила: user=null, disabled_at, totp_enabled=0, неизвестный action или неизвестная роль -> false (fail-closed).
// owner: всё. viewer: только строки ниже. 'self.*': target.userId обязан совпасть с user.id.
```
| action | owner | viewer |
|---|---|---|
| `view.keys` (last4, политика, фильтр), `view.requests`, `view.stats`, `view.audit`, `view.team` | да | да |
| `view.agents` (имена, привязки, без токенов) | да | да (вопрос 1) |
| `key.create`, `key.replace`, `key.policy`, `key.filter`, `key.delete` | да | нет |
| `agent.create`, `agent.enable`, `agent.disable`, `agent.keys`, `agent.delete` | да | нет |
| `request.decide` (сайт, Telegram, tg_code) | да | нет |
| `team.invite`, `team.role`, `team.disable` | да | нет |
| `settings.global` (бот Telegram, каналы уведомлений, язык, часовой пояс, «выйти везде и отозвать всё») | да | нет |
| `self.password`, `self.2fa`, `self.sessions` | только своё | только своё |
| `self.telegram` (привязка своего чата) | да | нет: viewer не получает и не нажимает ничего |

Как пользуются:
- Веб: вместо `requireOwner(req, reply)` — `guard(action)` как `preHandler`; маршрут объявляется `config: { action: 'key.policy' }`. `guard` читает пользователя из `req.user` (перечитывается из базы на каждом запросе, роль и `disabled_at` всегда свежие), `can()` ложь → 403 страница ошибки. Тест обходит `onRoute` и падает, если у непубличного маршрута нет `config.action`.
- Telegram: `bot.js` по `callback.from.id`/`chat.id` ищет `repo.getUserByTgChat(chatId)` (только `disabled_at IS NULL`); нет такого или `!can(user,'request.decide')` → молча игнорировать (как сейчас чужой chat_id), в аудит `tg.ignored` с ограничением частоты. Кнопка несёт id заявки + HMAC; HMAC не привязан к пользователю, поэтому проверка роли обязательна при каждом нажатии.
- `core/requests.js`: `decide({ requestId, approve, via, userId, totp? })`. Внутри: `user = repo.getUser(userId)`, `can(user,'request.decide')` иначе `{ok:false,error:'forbidden'}`; код проверяется секретом **этого** пользователя; решение пишет `decided_by = userId`. Одобрение двумя владельцами сразу: первый коммит `approveRequest` выигрывает, второй получает `not_pending`.
- Черновики и приглашения: `can()` вызывается повторно при исполнении (шаг 2 `pending.apply`; приём приглашения проверяет, что приглашавший всё ещё активный owner).

### Команда: операции repo
```js
getUser(id), getUserByLogin(login), getUserByTgChat(chatId), listUsers(),
countActiveOwners(),
createUserFromInvite(inviteId, { login, name, passwordHash }) // одна транзакция: invite.used_at, INSERT users (totp_enabled=0); -> User | null
setUserPassword(id, hash), setUserTotp(id, secretEnc, enabled), setUserTg(id, chatId|null),
setUserRole(id, role)  /* throws LastOwnerError */, disableUser(id) /* throws LastOwnerError */
```
Защита последнего owner: `setUserRole` и `disableUser` — `db.transaction(...).immediate()`: читают цель; если цель — активный owner и результат убирает у неё владельца, а `countActiveOwners() - 1 < 1` → `LastOwnerError`. Проверка и запись в одной транзакции, два владельца не могут одновременно понизить друг друга. Понизить или отключить себя можно, если останется другой активный owner.

Побочные эффекты `setUserRole` (owner→viewer) и `disableUser`, в той же транзакции: `DELETE FROM sessions WHERE user_id=?` (черновики и временные секреты уходят каскадом), `DELETE FROM one_time_links WHERE user_id=?`, `tg_chat_id=NULL` при отключении и понижении (viewer кнопок не имеет), `DELETE` ожидающих `invites` этого пользователя как приглашающего не нужен, они проверяют приглашавшего при приёме. После коммита: `lockout.reset('u:'+id)`, `bot.dropUser(userId)` (сброс ожидания 6 цифр в памяти). Заявки в `pending` и пропуска агентов не трогаем: они принадлежат шлюзу, а не человеку. Аудит: `team.role {before,after}`, `team.disable`, actor = исполнитель.

### Приглашения
```js
// таблица invites: id, token_hash UNIQUE, name, role, created_by, created_at, expires_at (=+72ч), used_at, user_id
createInvite({ tokenHash, name, role, createdBy, expiresAt }), getInviteByHash(hash), // consume — внутри createUserFromInvite
```
Поток: owner (`can team.invite` + свежий код) вводит имя и роль → ссылка `GET /invite/:token` (показывается один раз, `publicUrl`, 128 бит, в базе sha256, маскируется в логах как `/l/*`). Приглашённый: форма «логин, пароль ≥ 12» → `createUserFromInvite` (атомарно, второй переход по той же ссылке даёт 404) → сессия `purpose='enroll'` (только `/invite/2fa`, 30 мин) → QR → верный код → `totp_enabled=1`, 10 резервных кодов показываются один раз, сессия становится обычной с `totp_ok=1`. Просроченная или использованная ссылка: одинаковая страница 404. Приглашение для роли owner требует `team.invite` и свежего кода приглашающего; роль viewer→owner меняет только owner со свежим кодом (`team.role`).

### Вход, блокировки, сессии
- Логин: если активных пользователей один — поле «логин» не показывается и подставляется он; иначе обязательно. Неизвестный логин проходит ту же argon2-проверку по фиктивному хэшу (одинаковое время) и тот же счётчик по `lockKey(login)`, ответ один: «неверно».
- Блокировки (в памяти, как сейчас): по IP /64 (перед argon2), **по пользователю** `u:<id>` (5 ошибок пароля или кода → пауза 15 мин, уведомление всем владельцам), по сессии. Потолок ошибок кода: 10 в час **на пользователя** (`codeFails` становится Map по id), плюс общий потолок 30 в час на сайт. `APPROVE_KEY` → `2fa:approve:<userId>` (П-9). Оговорка: пользовательская блокировка позволяет постороннему на 15 мин заблокировать вход конкретного человека; смягчение: блок по пользователю действует только на шаг пароля с чужих IP, а с IP, с которого последний раз был успешный вход, не применяется (вопрос 7).
- Лимит сессий: 3 полные на пользователя; вытеснение самой старой не при выдаче половинной сессии, а при `markTotp` (П-32, чтобы пароль без кода не выбивал живую сессию владельца). Половинные: не больше 5 на пользователя, 10 мин, как сейчас.
- Контракт сессии (обновление `auth/session.js`):
```js
export function sessionPlugin(fastify, { repo, provider, secure })
// cookie gw_sid = случайный id (256 бит), в базе только idHash = sha256(id) hex (Н-3). Дамп базы не даёт войти.
// request.session = { idHash, userId, half, purpose:'login'|'enroll', totpAt } | null
// request.user = User | null — перечитывается на каждом запросе; disabled_at или удалён -> сессия удаляется, 401/login
// reply.startSession(req, user) — создаёт half-сессию для user; reply.endSession(req); reply.endUserSessions(userId, exceptIdHash?)
// request.markTotp() — ставит totp_ok/totp_at, вытесняет старые полные сессии этого пользователя (лимит 3)
// request.hasRecentTotp(maxAgeSec=300)
```
- Использованные TOTP-шаги (П-32): `totp_used(user_id, step, used_at, PRIMARY KEY(user_id, step))`. Контракт `verifyTotp(secret, code, usedStore)` меняется: `usedStore = { take(step:number):boolean }`, реализация `repo.takeTotpStep(userId, step)` = `INSERT OR IGNORE ... changes===1`. Совпал код, но шаг уже взят → ложь. Сброс при перезапуске не открывает повтор. `repo.purgeTotpSteps()` удаляет шаги старше 10 минут (reapLoop). Резервные коды: `backup_codes.user_id`.
- Секреты 2FA (П-7): `session_secrets(session_hash, kind, enc, created_at, PRIMARY KEY(session_hash, kind), FK sessions ON DELETE CASCADE)`; `putSessionSecret/peek/take` пишут туда вместо `meta['pending:…']`. TTL 10 мин проверяется при чтении, `purgeSessionSecrets()` в reapLoop.

### Уведомления в команде (решение)
- **Заявки на одобрение и все служебные оповещения (блокировки, истечение ключа, always закончился) — всем активным owner с `tg_chat_id`**, отдельное сообщение каждому, на заявке кнопки у всех. Первое нажатие решает, остальным сообщение редактируется: «Решил <имя>: Разрешено ✓». Viewer'ы Telegram-уведомлений не получают.
- Для хранения сообщений: таблица `request_notices(request_id, user_id, chat_id, message_id, PRIMARY KEY(request_id, user_id))` вместо одного `requests.tg_message_id`; `repo.setRequestTgMessage(requestId, userId, chatId, messageId)`, `listRequestNotices(requestId)`.
- `notify.js`: `requestCreated/requestDecided/grantAuto/info` рассылают по owner'ам; добавляется `toUser(userId, text)` для личных сообщений (например «ваша сессия закрыта»). Slack/Email — один канал на шлюз, не на пользователя.
- Нет ни одного owner с Telegram: заявки только на сайте, как сегодня.
- `bot.js`: `/start <код>` привязывает чат к пользователю из `one_time_links.user_id` (purpose `tg_link`), `UNIQUE(tg_chat_id)`; `/open` создаёт ссылку входа **для найденного по chat_id пользователя**; `/keys` — owner и viewer не нужны, оставить только owner.
- `gateway init [--user <login>]`: сброс пароля/2FA/сессий указанного (по умолчанию самого раннего активного owner) пользователя; консольный доступ = root, поэтому `init` может и снять `disabled_at`.

---

## auth/provider.js

Назначение: веб-слой и Telegram-бот знают только этот интерфейс, как доказать, что человек — этот пользователь. Роли, сессии, права, 2FA-приглашения остаются у шлюза. Подмена на Supabase в облаке не меняет маршруты.

```js
/** @typedef {{ id:string, login:string, name:string, role:'owner'|'viewer', disabled:boolean, totpEnabled:boolean, tgChatId:number|null, externalId:string|null }} AuthUser */
/** @typedef {{ name:'local'|'supabase',
 *   capabilities:{ password:boolean,           // форма логин+пароль на шлюзе
 *                  secondFactor:'local'|'provider'|'none',
 *                  external:boolean,           // вход через редирект на внешнего провайдера
 *                  manageCredentials:boolean } // шлюз сам меняет пароль/2FA (настройки, приглашения)
 * }} ProviderInfo */

export function createAuthProvider({ config, repo, keys, logger }) // -> AuthProvider; config.authProvider = 'local' (по умолчанию) | 'supabase'

/** @typedef {ProviderInfo & {
 *   verifyLogin({ login, password }):Promise<{ ok:true, user:AuthUser } | { ok:false, reason:'bad'|'locked'|'disabled' }>,
 *   verifySecondFactor({ userId, code }):Promise<{ ok:true, kind:'totp'|'backup' } | { ok:false, reason:'bad'|'locked' }>,
 *   getUser(userId):AuthUser|null,
 *   getUserByTelegram(chatId):AuthUser|null,
 *   // только при capabilities.manageCredentials (иначе маршруты настроек и приглашений отвечают 404, страница скрывает блоки):
 *   setPassword(userId, newPassword):Promise<void>,
 *   beginSecondFactorEnrollment(userId):Promise<{ secret:string, otpauthUrl:string }>,
 *   confirmSecondFactorEnrollment(userId, secret, code):Promise<{ ok:boolean, backupCodes?:string[] }>,
 *   // только при capabilities.external (слот под Supabase, не реализован в 1.0):
 *   startExternalLogin?(req):Promise<{ redirect:string }>,
 *   finishExternalLogin?(req):Promise<{ ok:true, user:AuthUser } | { ok:false, reason:string }>
 * }} AuthProvider */
```
Что выполняет `local` (то, что сегодня лежит в `server.js`): `verifyPassword` (argon2, фиктивный хэш для неизвестного логина), `decryptSecret` + `verifyTotp` с `repo.takeTotpStep`, резервные коды, блокировки по пользователю (`u:<id>`, потолок кодов на пользователя). Ошибки, которые провайдер возвращает как `reason:'locked'`, веб-слой показывает одним сообщением.

Остаётся в веб-слое и не зависит от провайдера: rate-limit по IP до argon2, потолок ошибок кода на сайт, `lockKey` по IP /64, cookie и таблица сессий, `request.user`, `can()`, CSRF, черновики, `hasRecentTotp` (свежий код — свойство сессии шлюза; при `secondFactor:'provider'` повторный вызов `verifySecondFactor` ведёт на страницу провайдера и возвращает `ok`).

Слот `supabase` (документируется в `docs/AUTH.md`, кода в 1.0 нет): `users.external_id` = Supabase user id, `capabilities = { password:false, secondFactor:'provider', external:true, manageCredentials:false }`; `startExternalLogin/finishExternalLogin` обмениваются Supabase-токен на `AuthUser` по `external_id`; роль и `disabled_at` берутся из таблицы `users` шлюза, а не из Supabase. Маршруты: `/login` проверяет `provider.capabilities.external` и редиректит, иначе показывает форму. Других ветвлений по имени провайдера в веб-слое быть не должно (тест: `grep "'supabase'"` вне `auth/`).

Использование веб-слоем (единственные вызовы): `POST /login` → `provider.verifyLogin`; `POST /totp` → `provider.verifySecondFactor`; `request.user` → `provider.getUser` (после перехода на облако — кэш по сессии); бот → `provider.getUserByTelegram`; настройки → `setPassword/beginSecondFactorEnrollment/confirmSecondFactorEnrollment` за проверкой `capabilities.manageCredentials`.

---

## Изменения схемы и миграции

`src/db/schema.sql` (новая БД получает сразу версию 2), `db/index.js` — `migrate(db)` по `meta.schema_version`.

```sql
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','viewer')),
  password_hash TEXT, totp_secret_enc TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0,
  tg_chat_id INTEGER, external_id TEXT,
  disabled_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS users_tg ON users(tg_chat_id) WHERE tg_chat_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_ext ON users(external_id) WHERE external_id IS NOT NULL;

CREATE TABLE sessions (                       -- пересоздаётся (id раньше хранился открытым)
  id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL DEFAULT 'login' CHECK (purpose IN ('login','enroll')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL, ua TEXT, totp_ok INTEGER NOT NULL DEFAULT 0, totp_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_user ON sessions(user_id, totp_ok);

CREATE TABLE session_secrets (               -- вместо meta['pending:<вид>:<хэш>'], П-7
  session_hash TEXT NOT NULL REFERENCES sessions(id_hash) ON DELETE CASCADE,
  kind TEXT NOT NULL, enc TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (session_hash, kind)
);
CREATE TABLE pending_actions (               -- П-19
  id TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL UNIQUE REFERENCES sessions(id_hash) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id),
  type TEXT NOT NULL, target_id TEXT NOT NULL, version TEXT NOT NULL, body_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()), expires_at INTEGER NOT NULL
);
CREATE TABLE totp_used (user_id TEXT NOT NULL REFERENCES users(id), step INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (user_id, step));
CREATE TABLE invites (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('owner','viewer')),
  created_by TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL, used_at INTEGER, user_id TEXT REFERENCES users(id)
);
CREATE TABLE request_notices (
  request_id TEXT NOT NULL REFERENCES requests(id), user_id TEXT NOT NULL REFERENCES users(id),
  chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL, PRIMARY KEY (request_id, user_id)
);
ALTER TABLE backup_codes ADD COLUMN user_id TEXT REFERENCES users(id);        -- NOT NULL обеспечивает repo
ALTER TABLE one_time_links ADD COLUMN user_id TEXT REFERENCES users(id);      -- open / tg_link несут пользователя
ALTER TABLE requests ADD COLUMN decided_by TEXT REFERENCES users(id);
```

Миграция v1 → v2 (одна транзакция, идемпотентна по `schema_version`):
1. Если есть таблица `owner` со строкой `password_hash IS NOT NULL`: `INSERT INTO users` с новым id, `login='owner'`, `name='Owner'`, `role='owner'`, пароль/TOTP/`tg_chat_id`/`created_at` копируются; `meta.tg_bot_param` и `meta.setup_done` берутся из строки `owner`. Если `owner` пуст (мастер не пройден) — пользователей нет, `setup_done` не ставится, мастер создаёт первого owner.
2. `UPDATE backup_codes SET user_id = <id>`; `one_time_links` без `user_id` (старые `open`/`tg_link`) удаляются.
3. `DROP TABLE sessions` и создание новой: **все текущие сессии закрываются, владелец входит заново один раз** (cookie хранит открытый id, пересчёт хэшей невозможен, а смысл Н-3 в том, чтобы открытых id в базе больше не было). Старые `meta['pending:*']` удаляются.
4. `ALTER TABLE owner RENAME TO owner_v1_backup` (читать только вручную, удаляется в следующем релизе). `schema.sql` для новых БД таблицу `owner` не создаёт.
5. `audit`: старые строки с actor `owner` остаются как есть (append-only); в интерфейсе actor `owner` показывается как «owner (до 1.0)», новые — `user:<id>` с именем из `users`.
6. `meta.schema_version = 2`. Репозиторий: `getOwner/setPasswordHash/setTotp/setTg/setSetupDone` заменяются методами `*User*`; `setup_done` — `getMeta('setup_done')`.
Откат: восстановление из бэкапа до миграции (перед миграцией `db/index.js` делает копию файла `gateway.db.pre-v2`).

Обновить в `docs/ARCHITECTURE.md`: раздел `db/repo.js` (owner → users, sessions, pending, invites, totp_used, session_secrets, request_notices), `auth/totp.js` (`usedStore`), `auth/session.js`, `core/requests.js` (`decide` принимает `userId`, `forbidden`), `notify.js` (рассылка по owner'ам, `toUser`), `tg/bot.js` (`getUserByTgChat`, `dropUser`, `/open` и `/start` по пользователю), `web/server.js` (маршруты `/pending/:id*`, `/invite/*`, `/settings/team*`, `guard(action)`), новые модули `auth/permissions.js`, `auth/provider.js`, `web/actions.js`, `web/pending.js`.

---

## Тесты (node:test, concrete cases)

`test/pending.test.js`
1. policy: weaken без свежего кода → 302 на `/totp?next=/pending/<id>`, в `pending_actions` одна строка, тело содержит только поля allowlist, нет `_csrf`; credential не изменён.
2. После верного кода `GET /pending/:id` показывает «было → стало», состояние базы не меняется; `POST /pending/:id/apply` применяет, строка удалена, audit `credential.policy` с `via:'draft'`.
3. filter: галочки типов, сохранённые до кода, совпадают после применения (регрессия «галочки теряются»).
4. Replay: второй `POST apply` с тем же id → `gone`, второго audit нет. Два параллельных `apply` (`Promise.all` на синхронной транзакции) → ровно один успех; для `agent.create` создан ровно один агент.
5. Одна запись на сессию: второй `save` в той же сессии заменяет первую, старый id → `gone`.
6. TTL: через 301 с (подмена `now`) `apply` и `view` → `gone`; `purgePending` удаляет.
7. Чужая сессия: `apply` чужого id с другой сессией → `gone`; тот же пользователь, другая сессия → `gone`.
8. Устаревшая версия: между `save` и `apply` политика ключа изменена другим вызовом → `stale`, запись удалена, ключ не перезаписан старыми значениями; то же для удалённого ключа и для `agent.keys` при смене привязки.
9. Неверный код: `/totp` ошибка, черновик жив; `apply` без свежего кода → `needFresh`, запись не потеряна (откат consume).
10. Повторная проверка роли: после `save` пользователь понижен до viewer → `apply` = `forbidden` (и сессии его удалены, черновик исчез каскадом); `disabled_at` — то же.
11. CSRF: `POST /pending/:id/apply` без токена → 403; токен из другой сессии → 403.
12. Секреты: `save` на `/keys/new/*` и `/keys/:id/replace` отклоняется (тип не в allowlist); тело с полем `key`/`password` → assert; в `body_json` нет значения ключа.
13. Валидация повторяется: черновик с невалидным фильтром (метод из deny, добавленный в каталог между save и apply) → errors, а не запись.
14. Выход (`/logout`) и смена пароля удаляют черновик.
15. Исключение внутри `apply` (мок repo бросает) → consume откатан, запись жива.

`test/team.test.js`
16. `can()`: таблица действие × роль (owner/viewer/null/disabled/totp_enabled=0/неизвестное действие/неизвестная роль), `self.*` только со своим `userId`.
17. Все непубличные маршруты имеют `config.action` (обход через `onRoute`); viewer на каждый POST-маршрут получает 403 и состояние базы не меняется (параметризованный прогон по списку маршрутов).
18. viewer видит ключи, заявки, Activity, аудит; не видит токены агентов и не видит кнопок записи; прямой POST `key.policy` — 403.
19. Telegram: нажатие `approve:` из чата viewer'а, из чата отключённого owner'а и из неизвестного чата — заявка остаётся pending, бот не отвечает, аудит `tg.ignored`. Нажатие owner'а проходит. Два owner'а жмут одновременно → один grant (`UNIQUE(grants.request_id)`), второму «уже решено».
20. `requestCreated` шлёт по сообщению каждому owner с chat_id и ни одному viewer; `requestDecided` редактирует все сообщения; `info` — всем owner.
21. Последний owner: понизить, отключить, самого себя — `LastOwnerError`; два owner понижают друг друга параллельно → один успех, второй `LastOwnerError`; при трёх активных owner понижение допустимо; отключённый owner не считается.
22. Понижение и отключение: сессии пользователя удалены, его черновик и `session_secrets` исчезли, ссылки `open`/`tg_link` удалены, `tg_chat_id` обнулён, ожидающее «6 цифр» в боте сброшено; сессии других пользователей целы; audit actor `user:<id>` исполнителя.
23. Приглашение: нужна роль owner + свежий код; ссылка 72 ч (73 ч → 404); одноразовость (две параллельные регистрации → один пользователь, второй 404); в базе только sha256; приглашавший отключён до приёма → 404; без 2FA войти нельзя; незавершённый `totp_enabled=0` старше 24 ч удаляется.
24. Лимиты: 5 ошибок пароля одного пользователя блокируют его (`u:<id>`), другой пользователь входит; неизвестный логин считается и отвечает так же (то же сообщение, сопоставимое время с фиктивным хэшем); потолок 10 ошибок кода в час на пользователя, не на сайт.
25. Лимит сессий: 3 полные на пользователя, четвёртая при `markTotp` вытесняет самую старую; половинная сессия (только пароль) живую не вытесняет (П-32).
26. Сессии: в `sessions.id_hash` лежит sha256(cookie), открытого id в файле базы нет (поиск строки в дампе); смена роли в базе действует на следующем же запросе без перелогина.
27. TOTP-шаги: код, принятый один раз, не принимается повторно, в том числе после «перезапуска» (новый `createRepo` на том же файле); шаги разных пользователей независимы.
28. Миграция v1→v2 на копии прод-схемы с данными: одна строка `users` (owner, login `owner`), пароль/TOTP/tg_chat_id/резервные коды сохранены, `meta.tg_bot_param`/`setup_done` перенесены, сессии пусты, `owner_v1_backup` существует, повторный запуск ничего не меняет; пустая `owner` → пользователей нет, мастер доступен; audit со старым actor читается.
29. `gateway init --user`: сбрасывает пароль/2FA/сессии указанного пользователя, не трогает остальных.

`test/auth-provider.test.js`
30. `local.verifyLogin`: верный/неверный пароль, неизвестный логин, `disabled_at`, `reason:'locked'` после 5 ошибок; без поля «логин» при одном пользователе.
31. `local.verifySecondFactor`: TOTP, резервный код (одноразовый), `locked`; не принимает код пользователя А для пользователя Б.
32. Веб-слой с поддельным провайдером (`capabilities.external=true`, `manageCredentials=false`): `/login` редиректит, `/settings/password` и `/invite/*` дают 404; роутинг не импортирует `local`. Грепом: упоминания `'supabase'`/`'local'` вне `auth/` отсутствуют.
33. Кириллица: в `src/auth`, `src/web/pending.js`, `src/web/actions.js` нет строк пользователю вне i18n (ключи `flash.draft_*`, `team.*`, `invite.*`).

---

## Решения (03.11, проверка контракта)

1. Viewer видит агентов и привязки, только чтение.
2. После кода — страница подтверждения «было → стало» (GET не меняет состояние), применение `POST /pending/:id/apply`.
3. Поле «логин» скрыто, пока активный пользователь один.
4. Viewer без Telegram — достаточно.
5. «Вернуть» участника не делаем: новое приглашение.
6. Таблица остаётся `sessions` (поправить ТЗ §3).
7. Блокировка по пользователю принимается как есть + уведомление всем owner; одобрение через Telegram при этом работает.
8. Миграция с одним повторным входом и `owner_v1_backup` на один релиз — да.
9. `gateway init --user <login>` — да.
Порядок реализации: сессии по хэшу (Н-3), `totp_used` (П-32), `session_secrets`, черновики (П-19) и `auth/provider.js` — в этап 4 (безопасность) и хвост этапа 0б; таблица `users`, приглашения и роли — этап 8 (команда), если владелец оставит команду в 1.0 (ТЗ §22 п. 1).

## Исходные вопросы

1. Viewer видит список агентов и привязки (без токенов)? ТЗ §13 перечисляет ключи, заявки, Activity, аудит, про агентов молчит. В черновике: да, только чтение.
2. После верного кода сразу применять черновик в `POST /totp` (на один клик меньше, CSRF формы кода уже проверен) или показывать страницу подтверждения с «было → стало» (как в черновике, строже и безопаснее при устаревших данных)?
3. Поле «логин» в форме входа: скрывать, пока пользователь один (ломает минимально для прода), или показывать всегда? Для будущего Supabase логином станет email.
4. Viewer без Telegram-уведомлений и без привязки чата. Достаточно, или viewer'у нужны оповещения «только читать»?
5. «Удалить участника» = необратимое отключение (строка остаётся для аудита). Нужна ли кнопка «вернуть» (с принудительной сменой пароля и 2FA)?
6. ТЗ §3 называет таблицу `user_sessions`; в черновике оставлена `sessions` с `user_id` (меньше переименований). Согласны?
7. Блокировка пользователя за 5 ошибок позволяет постороннему на 15 мин закрыть вход конкретному человеку. Принять риск (с уведомлением всем owner) или смягчать «блок по пользователю не действует с IP последнего успешного входа»?
8. Миграция закрывает все сессии (владелец входит заново один раз) и оставляет `owner_v1_backup` на один релиз. Принимается?
9. Что делает `gateway init` в команде: сброс одного пользователя (`--user`, по умолчанию самый ранний активный owner), без сброса остальных. Подходит?
