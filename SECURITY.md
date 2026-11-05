# Security policy

## Reporting a vulnerability

Report privately through GitHub: the repository's **Security** tab → **Report a vulnerability** (https://github.com/maximskorohod/agentkeygate/security/advisories/new). Please do not open a public issue.

Please include a description of the problem, steps to reproduce, the affected version or commit, and the impact as you understand it.

- Please do not publish details (issues, posts, talks) until a fix is available. We will agree on a timeline with you.
- Test only against your own installation. Do not access other people's data or services.
- Do not send real API keys in a report.

Supported versions: the latest 1.x release.

## Threat model

Short version: the gateway sits between an AI agent and a third-party API. The agent is not trusted. The owner is. The upstream service is trusted with the key by design.

### Assets

- API keys of third-party services.
- The owner's account: password, TOTP secret, Telegram connection, sessions.
- Passes (grant tokens) issued to agents.
- The data that comes back from the services the keys open (CRM contacts, tickets, and so on).

### Actors

- **Owner.** The only human with administrative rights. Approves requests and manages keys.
- **Agent.** A program with an agent token. It may be buggy or manipulated (for example, by prompt injection), and it may try to read or send data it should not.
- **Upstream service.** Receives the key by design.
- **Network attacker.** Can send any request to the public address of the gateway.
- **Server administrator.** Root on the host or an administrator of the cloud account. Out of scope (see below).

## What is protected

- **Keys stay in the vault.** Agents never receive keys. They receive passes: signed tokens with an expiry (TTL), a call limit, and a parallelism limit. Quotas are checked in the database on every call. Revoking a pass takes effect immediately.
- **Owner approval.** Each key has a policy: `always`, `ask`, or `deny`, optional approval channels, and an optional time window.
- **2FA on weakening.** Changing a key to `always`, turning off `readOnly`, turning off `mask`, or widening a field filter requires a fresh 2FA code. Tightening needs no code.
- **CSRF and web headers.** CSRF tokens, strict Content-Security-Policy without `unsafe-inline`, HSTS, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` (no referrer leaves the site; `no-referrer` would make browsers send `Origin: null` on forms), `Cache-Control: no-store`. No external scripts, fonts, or CDNs on the pages.
- **SSRF.** Catalog hosts are fixed. Custom hosts must be HTTPS on port 443 with a domain name. The name is resolved on every call, the connection goes to the verified address, redirects are not followed, and private, loopback, and link-local ranges are refused. The reference server setup adds an nftables rule set for the gateway user as a second barrier.
- **Logs without secrets.** Key values never appear in logs, URLs, responses, or error messages. Path-based keys are masked in paths and in response bodies. Request logs drop query strings and headers. Account identifiers that the service API puts in its own paths (for example a Twilio Account SID in `/Accounts/<SID>/…`) are not secrets and are logged as part of the path; the secret half (Auth Token) is not.
- **`readOnly`.** On by default for new CRM and support keys (Bitrix24, amoCRM, HubSpot, Pipedrive, Zendesk, Atlassian Jira and Confluence, Airtable). Only read methods pass; a write returns `403 write_not_allowed` and spends no quota. Available for other REST services too.
- **`mask`.** Replaces e-mail addresses, phone numbers written with a `+`, card numbers (Luhn check), and IBANs in string values of JSON responses with `****`, for any service where it is offered.
- **Field filter.** For supported services the owner picks which data types and fields the agent can see. Everything else is removed from the response before it reaches the agent. The owner sees an "Agent will see" line in each request.
- **One-time links.** 128-bit tokens, stored as hashes, compared in constant time.
- **Login.** Argon2id password hashing, TOTP 2FA (RFC 6238) with single-use codes, lockout after repeated failures, and notifications on lockouts. A lockout applies only to the address (an IPv6 network counts as one address) that failed: five wrong passwords or five wrong codes block that address for 15 minutes. Wrong passwords from many addresses never lock the owner out; past 50 in 15 minutes the owner gets a notification, and sign-in still needs the second factor. Wrong codes are also capped at 30 per hour across all addresses, because a 6-digit code can be guessed by a distributed attack; that cap also notifies the owner.
- **Fail closed.** If the database or the vault is unavailable, agents receive `503`.
- **Audit log.** Append-only, kept for 90 days.
- **Backups are encrypted.** `scripts/backup.sh` refuses to write a plain copy. See below.

## Known limitations

These are known and accepted in 1.0. Read them before you rely on the filter.

- **Searching by a hidden field (P-18).** An agent that is allowed to call a search or list route can pass a filter on a field it cannot see (for example a HubSpot search on `email`, a Pipedrive `filter_id`, a Bitrix24 `filter[PHONE]`). The service applies the filter, and the agent learns from the number and order of results whether a record matches. The value itself is not returned, but the fact of a match is, and range filters such as Bitrix24 `filter[>OPPORTUNITY]` can narrow a value down step by step. The hook for this check exists in code and does nothing in 1.0. If this matters, turn on `readOnly` and do not give the agent search routes.
- **A service that knows the key can return it encoded.** The gateway removes the key from responses in its raw, URL, base64, and JSON-escaped forms. A malicious or compromised service already holds the key and can send it in any other encoding, for example `sk-...` or reversed, and an agent can decode it. Only give keys to services you trust, and do not treat the removal as protection against a hostile service.
- **`mask` does not catch everything.**
  - A bare run of digits without a `+` or separators (an ID, a phone written as `79991234567`) is not masked. A card number is masked only when the string passes the Luhn check and starts with 2 to 6.
  - Names and addresses are not found. There is no ML.
  - An address like `192.168.100.200` looks like a phone number and is masked.
  - Non-JSON and streaming responses are refused (`502`) when `mask` is on.
- **Field lists are not verified against live accounts.** The HubSpot, Pipedrive, and Zendesk types, fields, and denied query parameters were taken from the vendors' documentation and are marked "not verified live" in the catalog. A field may be missing from the list or named differently. Check the "Agent will see" preview with a test account before trusting a filter.
- **`readOnly` trusts the HTTP method.** It treats `GET` as safe. For an API that writes on `GET` (for example the Slack Web API) it guarantees nothing. Check what the key can do before you rely on it.
- **Zendesk API tokens.** Zendesk stops issuing new API tokens on 27 October 2026; existing tokens work until 30 April 2027. OAuth (client_credentials) support comes after the launch.
- **Demo network guard.** In demo mode (`GW_DEMO=1`) the in-process guard blocks outgoing TCP and DNS. It does not intercept UDP (`dgram`) and does not cover child processes. A demo instance must also run behind the systemd and nftables rules described in `docs/DEPLOY.md`.
- **Backups are encrypted only.** No unencrypted backup is ever written. If neither `age` with a public key nor `gpg` with a passphrase is configured, the backup fails. With the file vault the archive contains the master key next to the vault, so the encryption key must be kept off the server.
- **Proxies and client IP.** The gateway reads the client address from `X-Forwarded-For` only from peers listed in `trustProxy` (loopback by default, or `GW_TRUST_PROXY`). Behind Cloudflare, the reference setup trusts `CF-Connecting-IP` only from Cloudflare ranges and requires Authenticated Origin Pulls. If you widen `GW_TRUST_PROXY` to a network that untrusted hosts can reach, they can forge their address and defeat login lockout and rate limits.

## Not protected

- **Server and cloud administrators.** Anyone with root on the host or administrator access to the AWS account can read the vault and the database, and therefore all keys.
- **The file vault.** The master key is stored next to the encrypted vault file. Anyone with access to the data volume can decrypt the keys. Use AWS SSM for production on AWS. The Docker setup uses the file vault.
- **The upstream service.** It sees the key and the request data. Anything you send to a service leaves your control.
- **Cloudflare in proxy mode.** When the domain is proxied through Cloudflare, Cloudflare sees the traffic, including API keys you type into the site.
- **Agent misuse within the pass.** An agent with a valid pass can send anything within the limits, including data from its own context. Without `readOnly` or a method filter, a pass allows any call the key allows. The reason text is written by the agent, so the owner sees it as quoted, untrusted text. Use keys with the narrowest scope the provider offers.
- **Your accounts.** A compromised Telegram account, email account, or logged-in browser session.
- **Availability.** Denial-of-service attacks beyond the built-in rate limits.
- **Dependencies and platform.** Vulnerabilities in Node.js, Fastify, Caddy, and other dependencies are fixed upstream. We update dependencies, but a zero-day can affect you before a fix.
