> Russian version: [docs/ru/DEPLOY.md](ru/DEPLOY.md)

# Deploying AgentKeyGate

Target server: Debian 12 or Ubuntu 24.04, Amazon EC2 t3.micro (1 GB RAM, `setup.sh` creates 1 GB of swap).

Two ways to deploy: a VPS with `scripts/setup.sh` (sections 1 and 2) and Docker (section 7). A demo instance with a third line of defense is described in section 10.

Verification status (2026-11-04, staging: Ubuntu 24.04, 2 vCPU / 4 GB, not AWS, `--vault file`, domain DNS only without Cloudflare proxying): `setup.sh` from scratch and on re-run, native module build as `gateway`, the unit under `SystemCallFilter` (restart without SIGSYS, `systemd-analyze security` 1.4 OK), Caddy 2.11 (`caddy validate`, Let's Encrypt), nftables (outbound only 53/443/465/587), IP spoofing through headers, the setup wizard, login with 2FA, HubSpot/Pipedrive/Stripe/Twilio keys, request → approval → call over REST and MCP, the filter and readOnly on live responses, Slack "Send test", `backup.sh` (age) and `gateway restore`, Docker (`docker compose build/up`, healthcheck). Scenario: `tools/staging-e2e.mjs`. The `--behind-cloudflare` mode with AOP was verified on Nov 5 (without a Rate Limiting rule). Not verified on a live server: the `ssm` vault and the IAM role on EC2, Telegram, SMTP, the demo instance, `MemoryMax` with large Deepgram files. These places are marked "not verified on a live server".

## 1. Before you install

**Not AWS** (any VPS with Ubuntu 24.04 or Debian 12): the Elastic IP, Security Group, and IAM role below are not needed, install with `--vault file`. Inbound traffic is closed by nftables from `setup.sh` (22, 80, 443); if your provider has its own firewall, open the same ports there. With `--vault file` the nftables rule for the metadata address 169.254.169.254 is not installed: OpenStack clouds serve their own instance metadata on that address. The domain is an A record pointing at the server IP without proxying (DNS only); for a trial run without your own domain, `<ip-with-dashes>.sslip.io` works.

**Elastic IP.** Attach it to the instance, otherwise the address changes after a restart.

**Security Group** (inbound):
- TCP 22: only your IP (`/32`);
- TCP 80 and 443: `0.0.0.0/0` (80 is needed to issue the Let's Encrypt certificate);
- do not open port 8080 (the gateway listens on 127.0.0.1 only).

**Instance IAM role.** Create a role that trusts `ec2.amazonaws.com`, add the policy below, and attach the role to the instance. Gateway keys are stored in SSM Parameter Store (SecureString) under the `/gateway/` prefix.

Policy (minimal; the `aws:SourceVpc` condition is optional, see below):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GatewayVault",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
      "Resource": "arn:aws:ssm:*:*:parameter/gateway/*"
    },
    {
      "Sid": "GatewayKmsViaSsm",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "ssm.eu-central-1.amazonaws.com"
        }
      }
    }
  ]
}
```

Important:
- **The `aws:SourceVpc` condition works only for requests through VPC endpoints** (interface endpoints `com.amazonaws.<region>.ssm` and `...kms`). If the instance uses the public SSM addresses (the default), the request has no `aws:SourceVpc` key, and all key operations will be denied. Then either create SSM and KMS endpoints in this VPC, or remove both `Condition` blocks from the policy.
- The KMS resource is `*` because `alias/aws/ssm` cannot be used as a resource in IAM. The restriction comes from `kms:ViaService`. If the parameters are encrypted with your own KMS key, give its ARN and remove `kms:ViaService`.
- Replace the region in `kms:ViaService` with yours (`--region`).

**How to find the VPC ID.** In the console: EC2, Instances, select the instance, Networking tab, the VPC ID field. Or from the server itself (IMDSv2):

```bash
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
MAC=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/mac)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/vpc-id"; echo
```

**DNS in Cloudflare.** Create an A record `gw.example.com` pointing at the Elastic IP and turn proxying off (grey cloud, DNS only). Otherwise Let's Encrypt will not issue a certificate over HTTP-01, and the gateway will receive requests that do not come from the real client IP.

## 2. Installation

On the server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/maximskorohod/agentkeygate/v1.0.2/scripts/setup.sh -o /root/setup.sh
echo "e0ddced59b9c360681161e300232726c32b49fb5f39ee8686765b2971faec2fc  /root/setup.sh" | sha256sum -c -
sudo bash /root/setup.sh --domain gw.example.com --vault ssm --region eu-central-1
```

What the script does, step by step:
1. installs system packages, creates 1 GB of swap, installs Node.js 22 (NodeSource) and Caddy;
2. creates a system user `gateway` without a shell;
3. clones the repository to `/opt/agentkeygate/app` (the code is owned by root, `gateway` cannot write to it) and builds dependencies as an unprivileged user (`npm ci --ignore-scripts`, then `npm rebuild argon2 better-sqlite3`);
4. creates `/var/lib/agentkeygate` (data) and `/etc/agentkeygate/env` (`GW_*` variables, mode 0600);
5. installs the hardened systemd unit `gateway.service`, a Caddy config with your domain, nftables rules, and a backup cron job;
6. starts the services, waits for `/healthz`, and calls `gateway init`.

Verified on staging on Nov 4: native module build as `gateway`, start and restart of the unit under `SystemCallFilter` without `Bad system call`, `caddy validate` on Caddy 2.11. Not verified on a live server: whether `MemoryMax=512M` is enough for large Deepgram files. Commands to check: `systemd-analyze security gateway`, `journalctl -u gateway -n 50`, `caddy validate --config /etc/caddy/Caddyfile`.

At the end the script prints a one-time setup link:

```
==> Setup wizard: gateway init
...a link like https://gw.example.com/setup/<code>...
```

The link is valid for 15 minutes and opens once. Open it in a browser and go through the wizard: password (at least 12 characters), 2FA (required, save the backup codes), Telegram (optional).

Running `setup.sh` again is safe: it updates the code and configs and restarts the services. If the link expired before you finished the wizard, just run it again. After the wizard is completed, `setup.sh` does not call `gateway init` (it would reset the password and 2FA); you can open the wizard again with the `--init` flag or as described in section 4.

**Domain behind Cloudflare with proxying** (orange cloud): SSL/TLS mode **Full (strict)** and the `--behind-cloudflare` flag. Caddy takes the client IP from `CF-Connecting-IP` only from Cloudflare addresses, nftables lets 80/443 in only from them; in the Security Group also open 80/443 only for the ranges at www.cloudflare.com/ips. In this mode Cloudflare sees the traffic, including keys.

**Authenticated Origin Pulls (AOP).** In `--behind-cloudflare` mode Caddy requires a Cloudflare client certificate, so a direct connection to the server IP fails the TLS handshake. To enable it:

1. In the Cloudflare dashboard: SSL/TLS → Origin Server → Authenticated Origin Pulls tab → **Global** section → On. Global AOP uses a shared Cloudflare certificate and applies to all proxied records of the zone; it does not interfere with origins that do not ask for a client certificate. The certificate is the same for all Cloudflare customers: it proves that the request came through the Cloudflare network, not through your zone. If you need a binding to your own zone, set up zone-level AOP with your own certificate.
2. Download the global AOP CA (`https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem`, the link is on the Authenticated Origin Pulls → Global page) and put it on the server as `/etc/caddy/cloudflare-origin-pull-ca.pem`. The script does not download this file itself.
3. Compare `sha256sum /etc/caddy/cloudflare-origin-pull-ca.pem` with the `CF_CA_SHA256` constant at the top of `setup.sh` (`c14fed0c…b843`, CA valid until 2029-11-01; checked on 2026-11-04 with two downloads from different machines).
4. Run `setup.sh --behind-cloudflare ...`. The script refuses to continue if the fingerprint does not match. If Cloudflare issued a new CA, pass its fingerprint with the `--cf-ca-sha256 <fingerprint>` flag after the same check.

**Without Cloudflare** (DNS only, the default) IP spoofing is checked like this: send a request with forged `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP` headers and a wrong password, then the login log (`sqlite3 -readonly /var/lib/agentkeygate/gw.db "SELECT target FROM audit WHERE action='login.fail' ORDER BY rowid DESC LIMIT 1"`) must show the real client address. Caddy without `trusted_proxies` replaces the header with its own client address, and the gateway trusts only loopback. Verified on staging on Nov 4; HTTPS to the bare server IP does not answer there (the certificate is issued for the domain only).

Order matters: first Global AOP in the dashboard and the proxy on the record, then `setup.sh --behind-cloudflare`. If Global AOP is off, Caddy drops the connection after the handshake, and Cloudflare shows error **520** (verified on staging on Nov 5). After switching, check the state of the toggle by reloading the page.

**Rate Limiting on `/login`.** On the Free plan the rule has only the Path field, no Host field. If the zone has other proxied services with a `/login` path, the rule will apply to them too. The period and block time on Free are fixed: 10 s, counted per IP.

Three manual checks for `--behind-cloudflare` mode, to confirm that IP spoofing does not work (replace `<your-host>` with your domain and `<server-ip>` with the server IP). Verified on staging on Nov 5: a direct connection does not answer, through Cloudflare it returns 200, a forged `X-Forwarded-For` does not appear in the logs, Cloudflare rejects a forged `CF-Connecting-IP` itself (403), and `login.fail` shows the real client address. Renewal of the Let's Encrypt certificate behind the proxy is not verified:

```bash
# 1. A direct connection bypassing Cloudflare must not succeed (handshake error or nftables timeout):
curl -sk --resolve <your-host>:443:<server-ip> https://<your-host>/healthz -o /dev/null -w '%{http_code}\n'

# 2. Forged headers on a direct connection must not reach the gateway and must not change the IP in the login log:
curl -sk --resolve <your-host>:443:<server-ip> https://<your-host>/healthz \
  -H 'X-Forwarded-For: 203.0.113.7' -H 'CF-Connecting-IP: 203.0.113.7' -o /dev/null -w '%{http_code}\n'

# 3. Through Cloudflare the request succeeds, and the forged X-Forwarded-For does not appear in the log:
curl -s https://<your-host>/healthz -H 'X-Forwarded-For: 203.0.113.7'
sudo journalctl -u gateway -n 20 --no-pager | grep 203.0.113.7 || echo "forged address not found in the log"
```

Expected: checks 1 and 2 end with a connection error (code 000) or a refusal, check 3 answers, and the forged address is not in the log. If checks 1 and 2 returned 200, AOP is not working: make sure the `#cf` lines in `/etc/caddy/Caddyfile` are uncommented (`grep client_auth /etc/caddy/Caddyfile`).

**Private repository**: create a bare repository on the server (`git init --bare /srv/agentkeygate.git`), push the branch with `git push <ssh-host>:/srv/agentkeygate.git main`, and pass `--repo /srv/agentkeygate.git`. A GitHub token is not needed on the server. You can get `setup.sh` itself from the same repository: `git --git-dir=/srv/agentkeygate.git show main:scripts/setup.sh > /root/setup.sh` (verified on staging). If you clone the bare repository by hand, specify the branch (`git clone --branch main …`): `HEAD` of a new bare repository points to a branch that does not exist, and the clone comes out empty.

## 3. Updating

Run `setup.sh` again with the same arguments: it updates the code, builds dependencies as an unprivileged user (`npm ci --ignore-scripts`, then `npm rebuild argon2 better-sqlite3`), and restarts the services. Do not run `npm ci` as root by hand: package install scripts would run with root rights.

## 4. Reopen the wizard (`gateway init`)

`init` resets the password, 2FA, sessions, and passes. Keys and agents stay. The command (as root, variables are taken from `/etc/agentkeygate/env`):

```bash
sudo bash -c 'set -a; . /etc/agentkeygate/env; set +a; runuser -u gateway -- env -C /opt/agentkeygate/app -i PATH=/usr/bin:/bin $(env | grep "^GW_") /usr/bin/node bin/gateway.js init'
```

## 5. Backups and restore

A backup runs every night at 03:17 (`/etc/cron.d/agentkeygate`, script `scripts/backup.sh`). Copies are stored in `/var/backups/agentkeygate/`, and those older than 30 days are deleted.

Encryption:
- **age** (preferred): `sudo apt install age`, put the recipient's public key in `/etc/agentkeygate/backup.age.pub`. Keep the private key off the server.
- **gpg** (if age is not available): put the passphrase in `/etc/agentkeygate/backup.pass` (0600, root). The passphrase is stored on the same server, so the copy only protects against a leak of the backup files themselves.
- Encryption is mandatory. If there is neither age with a key nor gpg with a passphrase, the script prints an error, exits with code 1, and saves nothing (no plaintext copies are ever left on disk).
- File vault (`GW_VAULT=file`): the copy includes `vault.json` and `master.key`, and the file is named `gw-DATE.tar.age|gpg` (inside: `gw.db`, `vault.json`, `master.key`). The master key is in the same encrypted archive, so only the encryption protects it: keep the age private key off the server. For the ssm vault the copy contains only the database.
- Audit rotation (older than 90 days, as an archive, gateway stopped): `gateway audit rotate --days 90 --out /var/backups/agentkeygate/audit`. The audit log is append-only, so there is no scheduled cleanup with DELETE.

Upload to S3 (optional): in `/etc/agentkeygate/backup.env` set `S3_BUCKET=...` and, if you want, `S3_PREFIX=...`. This needs the `aws` CLI and the IAM permission `s3:PutObject` for the instance role. The retention period in S3 is set by the bucket lifecycle rule (30 days).

Restore:

```bash
# 1. Decrypt the copy (on your machine or on the server):
age -d -i ~/backup.key -o gw.db gw-2026-11-01.db.age
#    or for gpg:
gpg --batch --pinentry-mode loopback --passphrase-file /etc/agentkeygate/backup.pass -d -o gw.db gw-2026-11-01.db.gpg

#    for the file vault, the archive gw-DATE.tar.age|gpg: decrypt it the same way, then unpack:
#    tar -xf gw.tar  # gw.db, vault.json, master.key
# 2. Stop the gateway. For the file vault, first put the vault back in the data directory:
sudo systemctl stop gateway
#    sudo install -o gateway -g gateway -m 0600 vault.json master.key /var/lib/agentkeygate/   (one file at a time, not in a batch, if the names differ)
#    and put gw.db where gateway can read it:
sudo install -o gateway -g gateway -m 0600 gw.db /var/lib/agentkeygate/restore.db
rm -f gw.db

# 3. Restore (the pass signing key is rotated, all passes are revoked, sessions, one-time links, pending requests
#    and temporary 2FA secrets are reset):
sudo bash -c 'set -a; . /etc/agentkeygate/env; set +a; runuser -u gateway -- env -C /opt/agentkeygate/app -i PATH=/usr/bin:/bin $(env | grep "^GW_") /usr/bin/node bin/gateway.js restore /var/lib/agentkeygate/restore.db'

# 4. Start and delete the temporary file:
sudo rm -f /var/lib/agentkeygate/restore.db
sudo systemctl start gateway
```

After the restore, log in again. If the password or 2FA does not work, run the wizard again (section 4).

Verified on staging on Nov 4 (age, file vault): the archive `gw-DATE.tar.age` with no plaintext copies next to it, restore following the steps above revoked all passes and sessions, keys and agents stayed, and after re-approval calls to the services work (the vault is decrypted by the restored `master.key`). The age key for the trial was created with `age-keygen` on the server; in a real installation, create it on your own machine and put only the public part on the server.

## 6. Checks and logs

```bash
systemctl status gateway caddy nftables chrony
curl -s https://gw.example.com/healthz          # public check through Caddy
journalctl -u gateway -f                        # gateway logs
journalctl -u caddy -f                          # Caddy logs (TLS and proxy errors)
tail -f /var/log/caddy/access.log               # access log without query strings and headers
sudo nft list ruleset | less                    # current firewall
sudo tail -n 50 /var/log/agentkeygate-backup.log
```

Firewall block logs (`agw-ssrf-…`, `agw-out-drop`, `agw-in-drop`) go to the kernel log: `journalctl -k | grep agw-`.

## 7. Docker

Files: `Dockerfile`, `docker-compose.yml`, `Caddyfile.docker`, `.env.example`. Two containers run: the gateway (no published port, read-only filesystem, no capabilities, not root) and Caddy (ports 80 and 443, Let's Encrypt certificate).

```bash
cp .env.example .env        # fill in DOMAIN and GW_PUBLIC_URL (https://gw.example.com)
docker compose up -d
docker compose exec gateway node bin/gateway.js init   # prints a one-time setup link (15 minutes)
```

Things to keep in mind:
- In Docker the vault is file-only (`GW_VAULT=file`), and data lives in the `gateway-data` volume (`/data`). The master key sits next to the vault, so access to the volume equals access to all keys.
- Caddy runs in a different container, and by default the gateway trusts the `X-Forwarded-For` header only from loopback. So that blocks, limits, and the login log see the client address and not the container address, `docker-compose.yml` already sets `GW_TRUST_PROXY=172.16.0.0/12` (Docker subnets). If your compose network is outside this range, override the value. Do not widen it to networks that contain other people's hosts.
- `scripts/backup.sh` does not back up Docker (it is made for a VPS). Copy the `gateway-data` volume yourself and encrypt the copy (age or gpg); restore with `docker compose exec gateway node bin/gateway.js restore <file>` after stopping writes.
- The nftables rules and systemd hardening from section 2 do not apply in Docker.
- Do not install Docker on a server where `setup.sh` has already installed `deploy/nftables.conf`: the file starts with `flush ruleset`, and every `systemctl restart nftables` (including a repeated `setup.sh`) wipes the Docker rules. After that the containers are left without outbound network (the build fails on `apk add`, the gateway cannot reach the services) until you run `systemctl restart docker`. Verified on staging on Nov 4.

Verified on staging on Nov 4 (Docker 29, Compose 2.40): `docker compose build` and `up`, healthcheck `healthy`, `/healthz`, the process runs as `gateway` (not root), the `/app` filesystem is read-only, `/data` is writable, `gateway init` in the container prints the setup link, `caddy validate` for `Caddyfile.docker`. The Caddy container was not started with certificate issuance (ports 80/443 on that server were taken by the systemd variant).

## 8. Environment variables

On a VPS `setup.sh` writes them to `/etc/agentkeygate/env`; in Docker they come from `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `GW_PUBLIC_URL` | `http://127.0.0.1:8080` | External address used in links and notifications |
| `GW_HOST`, `GW_PORT` | `127.0.0.1`, `8080` | Where the gateway listens (do not expose it, Caddy connects) |
| `GW_DATA_DIR` | `./data` | Directory for the database `gw.db`, `vault.json`, `master.key` |
| `GW_VAULT` | `file` | `file` or `ssm` |
| `GW_VAULT_PREFIX`, `GW_SSM_REGION` | `/gateway`, `eu-central-1` | `ssm` only |
| `GW_TRUST_PROXY` | `loopback` | Proxy addresses or subnets whose `X-Forwarded-For` is accepted |
| `GW_LANG` | `en` | Interface language: `en` or `ru` |
| `GW_TZ` | `UTC` | Gateway time zone |
| `GW_LOG_LEVEL` | `info` | Log level |
| `GW_PROXY_RATE_PER_MIN` | `300` | Limit of proxy calls per agent per minute |
| `GW_MCP_ENABLED` | on | `0`, `false`, or `off` turns MCP off at `/mcp` |
| `GW_MCP_ORIGINS` | empty | Allowed Origins for browser MCP clients, comma separated |
| `GW_MCP_MAX_SESSIONS`, `GW_MCP_MAX_SESSIONS_PER_AGENT`, `GW_MCP_IDLE_SEC`, `GW_MCP_MAX_LIFETIME_SEC` | `200`, `5`, `900`, `86400` | MCP session limits |
| `GW_MCP_MAX_RESPONSE`, `GW_MCP_BODY_LIMIT`, `GW_MCP_CALL_PARALLEL` | `65536`, `262144`, `4` | Bytes of a service response passed to the model, size of an MCP request body, concurrent `call`s per session |
| `GW_AUTH_PROVIDER` | local | Login module |
| `GW_WAITLIST_URL` | empty | Link for "Cloud: join the waitlist" (https only) |
| `GW_DEMO`, `GW_DEMO_RESET_SEC`, `GW_PROD_HOSTS` | off, `3600`, empty | Demo mode, see section 10 |

## 9. Caddy

VPS config: `deploy/Caddyfile` (`setup.sh` fills in the domain and installs it as `/etc/caddy/Caddyfile`). For Docker: `Caddyfile.docker`. What both do: TLS from Let's Encrypt, security headers (HSTS, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`: with `no-referrer` the browser sends forms with `Origin: null`, and the CSRF check rejects them), a 210 MB body limit (for Deepgram; the app itself limits other requests to 2 MB), an access log without query strings and without request headers, proxying to the gateway without buffering and with a response header timeout of 620 s.

Specifics of the VPS variant: the log also masks the IP to /16 (IPv4) and /32 (IPv6); lines marked `#cf` are enabled only by the `--behind-cloudflare` flag (trust in `CF-Connecting-IP` only from Cloudflare addresses, and Authenticated Origin Pulls). The log filter and `trust_pool` syntax was verified on Caddy 2.11; on another version, run `caddy validate`.

## 10. Demo instance

Demo mode (`GW_DEMO=1`) is for a public showcase instance: it has no real keys and no outgoing connections, and the data resets every hour. Protection has three lines:

1. **Startup.** The gateway refuses to start (exit code 1, before opening the port) if it finds real data: the vault is not `file`, `AWS_*`, `GW_SSM_*`, or `GW_VAULT_PREFIX` are set, `GW_DATA_DIR` is not set explicitly, the data directory is not empty and has no demo marker, the vault or database holds someone else's keys, the owner has a password, `GW_PUBLIC_URL` matches a host from `GW_PROD_HOSTS`.
2. **Process.** A network guard inside Node blocks outgoing TCP connections and DNS, and calls go to a built-in mock. The guard does not intercept UDP (`dgram`) and child processes.
3. **Server.** An OS-level restriction that works even if the code has a bug: systemd and nftables, as below.

Demo variables (in `/etc/agentkeygate/env` of a separate instance):

```
GW_DEMO=1
GW_DATA_DIR=/var/lib/agentkeygate-demo
GW_VAULT=file
GW_PUBLIC_URL=https://demo.example.com
GW_PROD_HOSTS=gw.example.com
```

- `GW_DATA_DIR` is set explicitly and the directory must be empty on first start (the gateway creates the `.demo-data` marker itself). A directory where the `gateway init` wizard has already been run will not work.
- `GW_VAULT=file`, and none of the variables `AWS_*`, `GW_SSM_*`, `GW_VAULT_PREFIX`. With the `--demo` installation below the script writes the env file without those lines; for a manual installation delete them from `/etc/agentkeygate/env` yourself.
- `GW_PROD_HOSTS` lists the hosts of the production gateway, comma separated. This is insurance against starting the demo with a production address.
- Install the demo on a separate machine, or a separate directory and user; not on a server with the production gateway.

**Installation with `setup.sh --demo`.** Download and verify `scripts/setup.sh` as in section 2, then run:

```bash
sudo bash setup.sh --domain demo.example.com --demo --prod-hosts gw.example.com
```

On top of the usual installation (section 2) the demo run does the following:

- writes the env file above: `GW_DEMO=1`, `GW_DATA_DIR=/var/lib/agentkeygate-demo`, `GW_VAULT=file`, no `GW_VAULT_PREFIX` and `GW_SSM_REGION`; creates `/var/lib/agentkeygate-demo` (mode 0700, owner `gateway`);
- installs `deploy/gateway-demo.conf` as the drop-in `/etc/systemd/system/gateway.service.d/demo.conf` (line 3a below);
- installs `/etc/nftables-demo.conf` (the `agw_demo` table, line 3b below), checks it with `nft -c`, and adds the line `include "/etc/nftables-demo.conf"` to `/etc/nftables.conf` at every run, so the table survives the config being rewritten from the repository;
- does not install the backup cron and removes a leftover one, and does not run `gateway init`.

A repeated run keeps demo mode even without `--demo`: the mode and `GW_PROD_HOSTS` are taken from the previous env file, and `GW_*` variables the script does not manage (`GW_LANG`, `GW_TZ`, `GW_TRUST_PROXY`, `GW_WAITLIST_URL`) are carried over unchanged. An installation whose previous env has no `GW_DEMO=1` removes a leftover `demo.conf` drop-in and behaves as before. `--print-env` prints the resulting `GW_*` environment to stdout and exits with code 0 before the root check and before any change. Refusals before any change: `--demo --vault ssm`, `--demo --init`, an invalid `--prod-hosts`, a demo without a production host list.

**Line 3a: systemd.** The drop-in for the demo unit is installed by `setup.sh --demo` from `deploy/gateway-demo.conf` as `/etc/systemd/system/gateway.service.d/demo.conf`; for a manual installation use `systemctl edit gateway`:

```ini
[Service]
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=
ReadWritePaths=/var/lib/agentkeygate-demo
```

`IPAddressDeny=any` forbids the unit any IP traffic, `IPAddressAllow=localhost` keeps loopback, over which Caddy reaches the gateway at 127.0.0.1:8080. The empty `ReadWritePaths=` clears the production path from `gateway.service` (the demo does not create that directory, and a missing path stops the unit from starting), the next line leaves the demo data directory as the one writable path. Check: `systemctl show gateway -p IPAddressDeny -p IPAddressAllow -p ReadWritePaths`.

**Line 3b: nftables.** A separate table with a priority earlier than the rules from `deploy/nftables.conf`: outbound traffic from the user `gateway` is allowed only over loopback and as replies to established inbound connections, everything else is dropped. The table lives in `deploy/nftables-demo.conf`, installed as `/etc/nftables-demo.conf`:

```
table inet agw_demo {
  chain output {
    type filter hook output priority filter - 10; policy accept;

    meta skuid gateway oif "lo" accept
    meta skuid gateway ct state established,related accept
    meta skuid gateway limit rate 6/minute log prefix "agw-demo-out: "
    meta skuid gateway drop
  }
}
```

`setup.sh --demo` checks the file with `nft -c -f /etc/nftables-demo.conf` and adds the line `include "/etc/nftables-demo.conf"` to `/etc/nftables.conf` at every run (`deploy/nftables.conf` starts with `flush ruleset`, and a repeated `setup.sh` rewrites the config: the script restores the `include` line itself). For a manual installation: check with `nft -c -f /etc/nftables-demo.conf`, apply with `nft -f /etc/nftables-demo.conf`, and add the `include` line to `/etc/nftables.conf` yourself.

Check as that user: `sudo -u gateway curl -m 5 -sS https://example.com` must fail, and `curl -s https://demo.example.com/healthz` from outside must answer.

Checked on a VPS with a separate unit bound to loopback: the gateway starts and restarts in demo mode, and a process with `IPAddressDeny=any` and `IPAddressAllow=localhost` cannot reach outside. Not verified on a live server: the `--demo` installation path with the `agw_demo` nftables table and the include line, a demo at a public address behind Caddy, and a unit with `SystemCallFilter` and `IPAddressDeny` together.
