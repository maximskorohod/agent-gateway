---
name: agentkeygate
description: Request temporary, owner-approved access to third-party APIs through an AgentKeyGate instance and call them without ever seeing the keys. Use when a task needs an external API (CRM, email, payments, LLM providers) and the user runs AgentKeyGate.
---

# AgentKeyGate

Use this skill to get short-lived access to a third-party API that the owner approves. You never receive the API key. You receive a pass that works for a limited time and a limited number of calls. The owner approves each request, or a standing policy approves it.

## Setup

Two environment variables must be set:

- `AGENTKEYGATE_URL`: base URL of the gateway, for example `https://gw.example.com`. No trailing slash.
- `AGENTKEYGATE_TOKEN`: your agent token, which starts with `gwa_`. The owner creates it in the web UI under Agents. It is shown once.

If a token is missing, ask the user for it. Do not search the filesystem or the environment for API keys.

The helper script `scripts/gw.sh` in this skill directory needs `curl` and `jq`.

## Step 1: request access

Send a `POST` to `/v1/grants`. The body has `provider` (the service name, such as `gemini`), `ttl` (seconds, 300 to 86400), `calls` (a number), and `reason` (why you need it, up to 200 characters).

```bash
curl -sS -X POST "$AGENTKEYGATE_URL/v1/grants" \
  -H "Authorization: Bearer $AGENTKEYGATE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"gemini","ttl":600,"calls":20,"reason":"Summarize 14 support tickets from today"}'
```

Handle the response:

- `200` with `status: "approved"` and a `token` (`gwt_...`): use the token now.
- `202` with `status: "pending"` and a `request_id`: the owner must approve. Go to step 2.
- `400` with `error: "credential_id_required"` and a list of keys: several keys exist for this service. Pick one `id` and send it as `credential_id`.
- `403`: the owner's policy denied the request, or the service has no key. Read the `reason` in the body. Do not retry. Report it to the user.
- `401`: the agent token is invalid or disabled. Stop and tell the user.
- `429`: rate limited. Wait at least 60 seconds before the next request.

## Step 2: poll while pending

Poll only when the response was `202`. Poll no more often than every 5 seconds, which is the `poll_after` value. Stop after 10 minutes.

```bash
curl -sS "$AGENTKEYGATE_URL/v1/grants/$REQUEST_ID" \
  -H "Authorization: Bearer $AGENTKEYGATE_TOKEN"
```

- `202`: still pending. Keep polling.
- `200` with a `token`: approved. The token is returned only once, so save it immediately.
- `403` with `status: "denied"` or `"expired"`: stop. Report it to the user.
- `410`: the pass was already issued or revoked. Stop.
- `429`: you polled too often. Slow down.

## Step 3: call the service through the proxy

Send the request to `/v1/proxy/<service>/<path>` with the pass as the bearer token. The path is forwarded to the service as is.

```bash
curl -sS -X POST "$AGENTKEYGATE_URL/v1/proxy/gemini/v1beta/models/gemini-2.0-flash:generateContent" \
  -H "Authorization: Bearer $GRANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

Notes:

- The gateway replaces your `Authorization` header and adds the key. Never send an API key yourself.
- Every call counts toward `calls`, and the pass expires at `expires_at`. Plan the calls needed to finish the task.
- Paths with `..`, `@`, or `://` are rejected.

Handle the response:

- The service's own status and body are returned as they are.
- `401` with `invalid_grant`: the pass is invalid, expired, revoked, or outside the owner's allowed time window. Request a new pass only if the task still needs it.
- `429` with `quota_exceeded`: the call limit or the parallelism limit was reached. Do not retry in a loop. If you were running requests in parallel, wait a few seconds once. Otherwise request a new pass only if needed.
- `502` with `upstream_unreachable`: the service did not respond. Retry once after 10 seconds, then report it.
- `403` with `method_not_allowed` or `write_not_allowed`: the owner's filter closed this method (or writes). Do not retry, do not look for another route to the same data, do not ask the owner to bypass the filter. The body lists the methods that are open (`allowed`). Use one of them or report that the task cannot be done.
- `400` with `query_not_allowed`: the query has a parameter the filter closes. Remove it.

An approved answer (`200` from step 1 or step 2) can carry a `filter` object that says what you will see: `types` (data types with the field paths), `methods` (open methods), `read_only` (writes are closed) and `mask` (personal data is replaced with `****`). Plan the calls around it.

## Rules

- Ask for the smallest `ttl` and `calls` that finish the task. The owner sets a maximum per key, and anything above it is capped.
- Write a specific `reason`, for example "Create invoice for order 1042", not "need access". The owner reads it before approving.
- Keep the `reason` under 200 characters, in plain text, without markup or links.
- Reuse a pass while it is valid instead of requesting a new one.
- Never print tokens, put them in URLs, or write them to files other than the helper's token file.

## Helper script

`scripts/gw.sh` wraps the steps above and keeps the pass in `${XDG_RUNTIME_DIR:-$HOME/.cache}/agentkeygate/<service>.token` (directory mode 700, file mode 600). The token is sent to curl through a config file, not on the command line.

```bash
scripts/gw.sh request gemini 600 20 "Summarize 14 support tickets from today"
scripts/gw.sh call gemini POST v1beta/models/gemini-2.0-flash:generateContent '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

Set `GW_CREDENTIAL_ID` before `request` when the service has several keys. After an approval the script prints the `filter` object to stderr when the owner set one.

Exit codes of `gw.sh`:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Any other error, including an error status returned by the service. |
| 2 | Wrong usage. |
| 3 | `method_not_allowed`: the owner's filter closed this method. Do not ask to bypass it. |
| 4 | `write_not_allowed`: the owner's filter is read-only or has not opened writes. Do not ask to bypass it. |

On code 3 or 4 the script prints the gateway's answer (with the open methods) to stdout and the reason to stderr. Do not retry the same call.
