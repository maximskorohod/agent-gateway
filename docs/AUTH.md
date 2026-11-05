# Login: the pluggable module `auth/provider.js`

The web layer (`web/server.js`) and the Telegram bot (`tg/bot.js`) know only the provider interface: how to prove that a person is this user. Roles, sessions, cookies, CSRF, permissions, 2FA drafts and code freshness (`hasRecentTotp`) stay with the gateway and do not depend on the provider.

Release 1.0 has one implementation, `local`. There are no cloud implementations; the "`supabase` slot" section only describes how that slot will work.

## Choosing a provider

`GW_AUTH_PROVIDER` (`config.authProvider`). Empty = `local` (the default value lives in `src/auth/provider.js`; strings with provider names must not appear outside `src/auth/`, which `test/auth-provider.test.js` checks). An unknown name or an unimplemented slot is a startup error (`Unknown auth provider "x"`, `Auth provider "supabase" is not implemented in this release`).

Tests inject a ready provider: `buildApp({ auth: provider })` (tests only, bypasses `GW_AUTH_PROVIDER`).

## Interface

```js
/** AuthUser: { id, login, name, role:'owner'|'viewer', disabled, totpEnabled, tgChatId:number|null, externalId:string|null } */
/** ProviderInfo: { name, capabilities:{ password:boolean, secondFactor:'local'|'provider'|'none', external:boolean, manageCredentials:boolean } } */
createAuthProvider({ config, repo, keys, logger })  // -> AuthProvider

verifyLogin({ login?, password, ip? })   // -> { ok:true, user } | { ok:false, reason:'bad'|'locked'|'disabled', alert?:'distributed' }
verifySecondFactor({ userId, code, ip? }) // -> { ok:true, kind:'totp'|'backup' } | { ok:false, reason:'bad'|'locked' }
getUser(userId)                          // -> AuthUser | null
getUserByTelegram(chatId)                // -> AuthUser | null
// only with capabilities.manageCredentials:
setPassword(userId, newPassword)
beginSecondFactorEnrollment(userId)      // -> { secret, otpauthUrl }
confirmSecondFactorEnrollment(userId, secret, code) // -> { ok, backupCodes? }
regenerateBackupCodes(userId)            // -> string[]  (an addition to the contract: the "new backup codes" button)
// only with capabilities.external:
startExternalLogin(req)                  // -> { redirect }
finishExternalLogin(req)                 // -> { ok:true, user } | { ok:false, reason }
```

The only call sites:

| Where | Call |
|---|---|
| `POST /login` | `verifyLogin` (the login field is optional while there is a single user) |
| `GET /login` | with `capabilities.external`, a redirect to `startExternalLogin(req).redirect` and no form; `POST /login` without `capabilities.password` answers 404 |
| `POST /totp`, the request approval code (`ctx.verifyTotp`) | `verifySecondFactor` |
| `/settings`, the wizard page | `getUser`, `setPassword`, `begin/confirmSecondFactorEnrollment`, `regenerateBackupCodes` |
| `/settings/password`, `/settings/2fa/*` | only with `capabilities.manageCredentials`, otherwise 404 and the blocks are hidden on the settings page |
| `tg/bot.js` | `getUserByTelegram` (which chats count as the owner; the rule "only a private chat with yourself" stays in the bot), `getUser` for the recipient chat_id |

The web layer keeps: the per-IP rate limit before argon2, `lockKey` by IP /64, lockouts by IP and by session, the site-wide cap on code errors (30 per hour), cookies and the session table, CSRF, `can()`, `hasRecentTotp`. The provider returns `reason:'locked'` and the web layer shows one message.

## What `local` does

- Until a `users` table exists, the only user is the owner from the `owner` row: `id = OWNER_USER_ID`, `login 'owner'`, `name 'Owner'`, `role 'owner'`, `disabled false`. Until a password is set (the wizard is not finished), `getUser` returns `null`.
- `verifyLogin`: argon2 (a semaphore of 1 in `auth/password.js`); an unknown login is checked against a dummy hash so that timing does not reveal whether the user exists. Lockout `u:<id>|<ip>` (IPv6 by /64): 5 password errors from one address, 15 minutes; someone else's guessing from another address does not lock the owner out. The global counter `ug:<id>` across all addresses (50 errors in 15 minutes) does NOT block login: otherwise distributed guessing would lock the owner out. At the threshold `verifyLogin` returns `alert:'distributed'` and the site sends the owner a notification (at most once per 15 minutes); login still requires the second factor. Unknown logins are counted separately (`u:?<login>`) and do not block the owner.
- `verifySecondFactor`: TOTP (`decryptSecret` + `verifyTotp` with `repo.takeTotpStep(userId, step)`; a repeated step is rejected, and this survives a restart) or a backup code (one-time, `repo.useBackupCode`). Lockout `uc:<id>|<ip>`: 5 code errors in a row from one address, 15 minutes; a cap of 30 code errors per hour per user across all addresses (it protects the 6-digit TOTP from guessing and stays blocking; when it is reached the site sends the owner `notify.totp_locked_hour`). A correct code resets the user's password and code counters.
- Lockout counters live in the memory of the provider instance (as the per-IP ones did before), not in the database.
- `capabilities = { password:true, secondFactor:'local', external:false, manageCredentials:true }`.

## The `supabase` slot (no code in 1.0)

- `users.external_id` = the user id in Supabase (the `users` table does not exist yet).
- `capabilities = { password:false, secondFactor:'provider', external:true, manageCredentials:false }`.
- `startExternalLogin/finishExternalLogin` exchange a Supabase token for an `AuthUser` by `external_id`. The return route from the provider (`/login/callback`) will be added together with the implementation: in 1.0 only `startExternalLogin` is called.
- The role and `disabled_at` come from the gateway's `users` table, not from Supabase. Gateway sessions are issued by the same `reply.startSession`.
- `secondFactor:'provider'`: a repeated code check (`verifySecondFactor`) leads to the provider's page and returns `ok`; the freshness of the code is kept by the gateway session.
- `getUser` in the cloud case uses a per-session cache; the web layer routes do not change, and there is no branching on the provider name in it.
