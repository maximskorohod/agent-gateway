# Contributing

agent-gateway is small on purpose: one owner, one SQLite file, one process. Please keep changes in that spirit.

## Setup and tests

Requires Node.js 22. The stack is plain ESM JavaScript: no TypeScript and no bundler.

```bash
npm ci
npm test
```

Tests run offline and without AWS. They use the file vault (`GW_VAULT=file`) and a mock upstream service on localhost.

### Windows

Use PowerShell or Git Bash. `npm ci` can fail on Windows while it builds native modules with node-gyp. The prebuilt binaries work, so skip the build scripts:

```powershell
npm.cmd ci --ignore-scripts
npm.cmd test
```

This also works with Node 24. For machine-readable output and a short summary:

```bash
node --test --test-reporter=tap test/*.test.js 2>&1 | grep -E "^# (tests|pass|fail)"
```

Use `npm.cmd`, `npx.cmd` instead of `npm`, `npx` if PowerShell blocks the `.ps1` wrappers.

## Rules

- **No external resources on the site.** No CDN scripts, fonts, or stylesheets. Page scripts are files under `src/web/public/`. Inline scripts are not allowed, because the Content-Security-Policy has no `unsafe-inline`.
- **Interface strings.** Every user-visible string goes through `t()` and exists in both `src/i18n/en.js` and `src/i18n/ru.js` with the same keys. English is the default. Do not hard-code product name or text in code. Labels from `providers.yaml` are English, Russian ones are keys like `catalog.name.*` and `catalog.hint.*`.
- **Errors for agents.** API and MCP errors are English codes and do not depend on the interface language. Logs and internal errors are English. Cyrillic outside the dictionaries is caught by `test/no-cyrillic.test.js`.
- **Secrets stay out of logs.** Key values, passwords, and tokens never appear in logs, URLs, error messages, or tests in plain text. Test tokens must be obviously fake and built at run time.
- **Time.** Stored times use SQLite `unixepoch()`. JavaScript time is used only for timeouts.
- **Synchronous transactions.** better-sqlite3 transactions are synchronous. There is no `await` inside `db.transaction(...)`.
- **Database access.** All queries go through `db/repo.js`.
- **Short errors for users.** User-facing errors are short and have no stack traces. Internal errors go to `logger.error`.
- **Module contracts.** Each module exports only what `docs/ARCHITECTURE.md` describes. If you change a signature there, update the document in the same pull request. Contracts for the 1.0 release are in `docs/contracts/`.
- **No network in tests.** Tests do not call external services or AWS.
- **Line endings.** LF only. CRLF breaks shell scripts and configuration files. Set `git config core.autocrlf false` on Windows.
- **Dependencies.** Add a new dependency only with an exact version at least two weeks old (`npm install --save-exact --ignore-scripts`), and explain why in the pull request.

The design documents in `docs/` are in Russian. The contracts in `docs/ARCHITECTURE.md` are binding.

## Pull requests

- Include a test for every behavior change and every bug fix. A fix for a security finding comes with a regression test.
- Run `npm test` before you push.
- Keep a pull request focused. Describe what changed and why.
- For security-relevant changes, describe the threat and how the change is tested.
- Do not commit server addresses, domains, key IDs, or personal data. Before a commit, check the staged diff: `git diff --cached | grep -iE 'sk_|pg_live|AIza|token|password'`.
- Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
