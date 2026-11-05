# Вход: сменный модуль `auth/provider.js`

Веб-слой (`web/server.js`) и Telegram-бот (`tg/bot.js`) знают только интерфейс провайдера: как доказать, что человек — этот пользователь. Роли, сессии, cookie, CSRF, права, черновики 2FA и свежесть кода (`hasRecentTotp`) остаются у шлюза и от провайдера не зависят.

В 1.0 есть одна реализация, `local`. Облачных реализаций нет; раздел «Слот supabase» только описывает, как он встанет.

## Выбор провайдера

`GW_AUTH_PROVIDER` (`config.authProvider`). Пусто = `local` (значение по умолчанию лежит в `src/auth/provider.js`, строк с именами провайдеров вне `src/auth/` быть не должно: проверяет `test/auth-provider.test.js`). Неизвестное имя или не реализованный слот — ошибка при старте (`Unknown auth provider "x"`, `Auth provider "supabase" is not implemented in this release`).

Тесты подставляют готовый провайдер: `buildApp({ auth: provider })` (только тесты, обходит `GW_AUTH_PROVIDER`).

## Интерфейс

```js
/** AuthUser: { id, login, name, role:'owner'|'viewer', disabled, totpEnabled, tgChatId:number|null, externalId:string|null } */
/** ProviderInfo: { name, capabilities:{ password:boolean, secondFactor:'local'|'provider'|'none', external:boolean, manageCredentials:boolean } } */
createAuthProvider({ config, repo, keys, logger })  // -> AuthProvider

verifyLogin({ login?, password, ip? })   // -> { ok:true, user } | { ok:false, reason:'bad'|'locked'|'disabled', alert?:'distributed' }
verifySecondFactor({ userId, code, ip? }) // -> { ok:true, kind:'totp'|'backup' } | { ok:false, reason:'bad'|'locked' }
getUser(userId)                          // -> AuthUser | null
getUserByTelegram(chatId)                // -> AuthUser | null
// только при capabilities.manageCredentials:
setPassword(userId, newPassword)
beginSecondFactorEnrollment(userId)      // -> { secret, otpauthUrl }
confirmSecondFactorEnrollment(userId, secret, code) // -> { ok, backupCodes? }
regenerateBackupCodes(userId)            // -> string[]  (дополнение к контракту: кнопка «новые резервные коды»)
// только при capabilities.external:
startExternalLogin(req)                  // -> { redirect }
finishExternalLogin(req)                 // -> { ok:true, user } | { ok:false, reason }
```

Единственные места вызова:

| Где | Вызов |
|---|---|
| `POST /login` | `verifyLogin` (поле логина не обязательно, пока пользователь один) |
| `GET /login` | при `capabilities.external` редирект на `startExternalLogin(req).redirect`, формы нет; `POST /login` без `capabilities.password` отвечает 404 |
| `POST /totp`, код одобрения заявки (`ctx.verifyTotp`) | `verifySecondFactor` |
| `/settings`, страница мастера | `getUser`, `setPassword`, `begin/confirmSecondFactorEnrollment`, `regenerateBackupCodes` |
| `/settings/password`, `/settings/2fa/*` | только при `capabilities.manageCredentials`, иначе 404, на странице настроек блоки скрыты |
| `tg/bot.js` | `getUserByTelegram` (кто из чатов считается владельцем; правило «только личный чат с самим собой», П-8, остаётся в боте), `getUser` для chat_id получателя |

Остаётся в веб-слое: rate-limit по IP до argon2, `lockKey` по IP /64, блокировки по IP и по сессии, общий потолок ошибок кода на сайт (30 в час), cookie и таблица сессий, CSRF, `can()`, `hasRecentTotp`. Провайдер возвращает `reason:'locked'`, веб-слой показывает одно сообщение.

## Что делает `local`

- Пока нет таблицы `users` (этап 6.4), единственный пользователь — владелец из строки `owner`: `id = OWNER_USER_ID`, `login 'owner'`, `name 'Owner'`, `role 'owner'`, `disabled false`. Пока пароль не задан (мастер не пройден), `getUser` возвращает `null`.
- `verifyLogin`: argon2 (семафор на 1 в `auth/password.js`); неизвестный логин проверяется против фиктивного хэша, чтобы время не выдавало отсутствие пользователя. Блокировка `u:<id>|<ip>` (IPv6 по /64): 5 ошибок пароля с одного адреса, 15 минут; чужой перебор с другого адреса владельца не запирает. Глобальный счётчик `ug:<id>` с любых адресов (50 ошибок за 15 минут) вход НЕ блокирует: иначе распределённый перебор запирал бы владельца. При пороге `verifyLogin` возвращает `alert:'distributed'`, сайт шлёт владельцу уведомление (не чаще раза в 15 минут); вход всё равно требует второй фактор. Неизвестные логины считаются отдельно (`u:?<логин>`) и владельца не блокируют.
- `verifySecondFactor`: TOTP (`decryptSecret` + `verifyTotp` с `repo.takeTotpStep(userId, шаг)`, повтор шага отвергается, переживает перезапуск) или резервный код (одноразовый, `repo.useBackupCode`). Блокировка `uc:<id>|<ip>`: 5 ошибок кода подряд с одного адреса, 15 минут; потолок 30 ошибок кода в час на пользователя с любых адресов (он защищает 6-значный TOTP от перебора и остаётся блокирующим; при достижении на сайте владельцу уходит `notify.totp_locked_hour`). Верный код обнуляет счётчики пароля и кода пользователя.
- Счётчики блокировок живут в памяти экземпляра провайдера (как раньше у IP), не в базе.
- `capabilities = { password:true, secondFactor:'local', external:false, manageCredentials:true }`.

## Слот `supabase` (кода в 1.0 нет)

- `users.external_id` = id пользователя в Supabase (таблица `users` появится на этапе 6.4).
- `capabilities = { password:false, secondFactor:'provider', external:true, manageCredentials:false }`.
- `startExternalLogin/finishExternalLogin` обменивают токен Supabase на `AuthUser` по `external_id`. Маршрут возврата с провайдера (`/login/callback`) добавится вместе с реализацией: в 1.0 вызывается только `startExternalLogin`.
- Роль и `disabled_at` берутся из таблицы `users` шлюза, а не из Supabase. Сессии шлюза выдаются тем же `reply.startSession`.
- `secondFactor:'provider'`: повторная проверка кода (`verifySecondFactor`) ведёт на страницу провайдера и возвращает `ok`; свежесть кода хранит сессия шлюза.
- `getUser` в облаке — с кэшем по сессии; маршруты веб-слоя не меняются, ветвлений по имени провайдера в нём нет.
