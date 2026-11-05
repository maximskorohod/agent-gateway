#!/usr/bin/env bash
# Install or update AgentKeyGate on a VPS: Debian 12 / Ubuntu 24.04, Amazon EC2 t3.micro (1 GB RAM).
#
# Run as root:
#   sudo ./setup.sh --domain gw.example.com [--repo URL] [--branch main] [--vault ssm|file] [--region eu-central-1]
#
# The script is idempotent: a repeated run pulls the code from git, rebuilds dependencies,
# rewrites the configs from the repository and restarts the services. At the end it runs
# `gateway init`, which prints a one-time setup wizard link (valid for 15 minutes).
set -euo pipefail

# ---------- constants ----------
readonly APP_USER="gateway"
readonly APP_HOME="/opt/agentkeygate"
readonly APP_DIR="${APP_HOME}/app"
readonly DATA_DIR="/var/lib/agentkeygate"
readonly BACKUP_DIR="/var/backups/agentkeygate"
readonly ETC_DIR="/etc/agentkeygate"
readonly ENV_FILE="${ETC_DIR}/env"
readonly GW_PORT="8080"
# Authenticated Origin Pulls (Cloudflare mode): the operator places the CA file, the script does not download it.
readonly CF_CA_FILE="/etc/caddy/cloudflare-origin-pull-ca.pem"
# SHA-256 of the global AOP CA (developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem,
# CN=origin-pull.cloudflare.net, valid until 2029-11-01). Checked on 2026-11-04: two downloads, from the server and from another machine.
# If Cloudflare issues a new CA, pass the new fingerprint with --cf-ca-sha256.
CF_CA_SHA256="c14fed0ce5210db0719fea11d1f10b33750dc17d609aeaf47c75e9eff0d7b843"

# ---------- helper functions ----------
step() { echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage:
  sudo ./setup.sh --domain gw.example.com [--repo URL] [--branch BRANCH] [--vault ssm|file] [--region REGION]

  --domain   required; the domain whose A record points to the Elastic IP (Cloudflare: grey cloud)
  --repo     git repository (default: https://github.com/maximskorohod/agentkeygate.git)
             or an absolute path to a bare repository on the server (for a private repository)
  --branch   branch (default: main)
  --vault    ssm (default, production: keys in AWS SSM via the IAM role) or file (tests only)
  --region   AWS region for SSM (default: eu-central-1)
  --behind-cloudflare  the domain is proxied by Cloudflare (orange cloud, SSL Full strict):
             Caddy takes the client IP from CF-Connecting-IP, nftables lets 80/443 in only from Cloudflare addresses.
             Cloudflare then sees the traffic, including keys in requests. Enables Authenticated Origin Pulls:
             put the Cloudflare CA at /etc/caddy/cloudflare-origin-pull-ca.pem before running (the script does not download it);
             its SHA-256 is checked against the CF_CA_SHA256 constant or the --cf-ca-sha256 flag.
  --cf-ca-sha256 HEX  expected SHA-256 of the Cloudflare CA file (64 hex characters, checked against the official page)
  --init     open the setup wizard again (gateway init) after it was completed:
             resets the password, 2FA, sessions and passes; keys and agents are kept
USAGE
}

# Runs a command as the gateway user with the GW_* variables from the env file.
# The gateway user cannot read the env file itself (0600, root), so root reads the variables.
run_as_gw() {
  (
    # The file is not sourced with `.`: GW_PORT is readonly here, and assigning it again would stop the script.
    # Values in the env file are plain (KEY=VALUE without quotes), so they can be passed as they are.
    local -a gwenv
    mapfile -t gwenv < <(grep -E '^GW_[A-Z0-9_]+=' "$ENV_FILE" || true)
    exec runuser -u "$APP_USER" -- env -C "$APP_DIR" -i PATH=/usr/bin:/bin "${gwenv[@]}" \
      /usr/bin/node "$APP_DIR/bin/gateway.js" "$@"
  )
}

# ---------- argument parsing ----------
DOMAIN=""
REPO="https://github.com/maximskorohod/agentkeygate.git"
BRANCH="main"
VAULT="ssm"
REGION="eu-central-1"
BEHIND_CF=0
FORCE_INIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) [[ $# -ge 2 ]] || die "--domain requires a value"; DOMAIN="$2"; shift 2 ;;
    --repo)   [[ $# -ge 2 ]] || die "--repo requires a value";   REPO="$2";   shift 2 ;;
    --branch) [[ $# -ge 2 ]] || die "--branch requires a value"; BRANCH="$2"; shift 2 ;;
    --vault)  [[ $# -ge 2 ]] || die "--vault requires a value";  VAULT="$2";  shift 2 ;;
    --region) [[ $# -ge 2 ]] || die "--region requires a value"; REGION="$2"; shift 2 ;;
    --behind-cloudflare) BEHIND_CF=1; shift ;;
    --cf-ca-sha256) [[ $# -ge 2 ]] || die "--cf-ca-sha256 requires a value"; CF_CA_SHA256="$2"; shift 2 ;;
    --init) FORCE_INIT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

# ---------- checks ----------
[[ $EUID -eq 0 ]] || die "run the script as root: sudo ./setup.sh --domain ..."
[[ -n "$DOMAIN" ]] || { usage; die "--domain is not set"; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
  || die "invalid domain: $DOMAIN"
# A local path is for a private repository: the code is pushed to the server over ssh
# into a bare repository, so the server does not store GitHub tokens.
[[ "$REPO" =~ ^https://[^[:space:]]+$ || "$REPO" =~ ^/[^[:space:]]+$ ]] \
  || die "--repo must be an https URL or an absolute path to a git repository on the server"
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid branch name: $BRANCH"
case "$VAULT" in
  ssm|file) ;;
  *) die "--vault must be ssm or file" ;;
esac
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "invalid region: $REGION"
if [[ "$BEHIND_CF" -eq 1 ]]; then
  [[ "$CF_CA_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
    || die "Cloudflare CA fingerprint is not set: check the file against the official Cloudflare page and pass --cf-ca-sha256 <sha256>"
fi

# shellcheck disable=SC1091
. /etc/os-release
case "${ID}:${VERSION_ID:-}" in
  debian:12|ubuntu:24.04|ubuntu:26.04) ;;
  *) die "supported systems: Debian 12 and Ubuntu 24.04/26.04, this one is: ${PRETTY_NAME:-unknown}" ;;
esac

# Configs from deploy/ with the "#cf " marker (enable behind Cloudflare) and "#nocf" (only without Cloudflare).
render_cf() {
  if [[ "$BEHIND_CF" -eq 1 ]]; then
    sed -e 's/^\([[:space:]]*\)#cf /\1/' -e '/#nocf$/d' "$1"
  else
    sed -e '/^[[:space:]]*#cf /d' -e 's/[[:space:]]*#nocf$//' "$1"
  fi
}

export DEBIAN_FRONTEND=noninteractive

# ---------- 1. system packages ----------
step "Updating the package list and installing base packages"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  curl ca-certificates gnupg git build-essential python3 sqlite3 \
  unattended-upgrades nftables chrony

step "Automatic security updates (unattended-upgrades)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
# ---------- 2. 1 GB swap (needed on 1 GB RAM: npm ci and native module builds) ----------
step "1 GB swap and vm.swappiness=10"
if [[ -z "$(swapon --noheadings --show=NAME)" ]]; then
  if [[ ! -f /swapfile ]]; then
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
else
  echo "    swap is already active, skipping"
fi
grep -qE '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
echo 'vm.swappiness = 10' > /etc/sysctl.d/99-agentkeygate.conf
sysctl -q -p /etc/sysctl.d/99-agentkeygate.conf

# ---------- 3. Node.js 22 (NodeSource) ----------
step "Node.js 22"
node_major="$(node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || true)"
if [[ "${node_major:-0}" -ge 22 ]]; then
  echo "    already installed: $(node -v), skipping"
else
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq nodejs
  echo "    installed: $(node -v)"
fi

# ---------- 4. Caddy (official repository, caddyserver.com/docs/install) ----------
step "Caddy from the official repository"
caddy_key=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
caddy_list=/etc/apt/sources.list.d/caddy-stable.list
if [[ ! -s "$caddy_key" ]]; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor --yes -o "${caddy_key}.tmp"
  mv -f "${caddy_key}.tmp" "$caddy_key"
fi
if [[ ! -s "$caddy_list" ]]; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > "${caddy_list}.tmp"
  mv -f "${caddy_list}.tmp" "$caddy_list"
fi
apt-get update -qq
apt-get install -y -qq caddy

# ---------- 5. system user ----------
step "User ${APP_USER} (no shell, home ${APP_HOME})"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_HOME" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
  echo "    created"
else
  echo "    already exists"
fi
install -d -m 0755 -o root -g root "$APP_HOME"

# ---------- 6. application code ----------
step "Application code: ${REPO} (${BRANCH}) -> ${APP_DIR}"
# A bare repository on the server usually belongs to the user who pushes to it (not root).
# The global git config is not touched: safe.directory for a local repository is passed
# with the -c key only in the commands that access it (N-10).
GIT_SAFE=()
if [[ "$REPO" == /* ]]; then
  GIT_SAFE=(-c "safe.directory=${REPO}")
fi
if [[ -d "$APP_DIR/.git" ]]; then
  git "${GIT_SAFE[@]}" -C "$APP_DIR" remote set-url origin "$REPO"
  git "${GIT_SAFE[@]}" -C "$APP_DIR" fetch --quiet origin "$BRANCH"
  # Below, the script runs chmod 0755 on backup.sh; in old commits the file was 0644, and git saw this as a local
  # change: pull refused to update the code (staging 04.11). Restore the file to the git version before pull.
  git "${GIT_SAFE[@]}" -C "$APP_DIR" checkout --quiet -- scripts/backup.sh
  git "${GIT_SAFE[@]}" -C "$APP_DIR" checkout --quiet "$BRANCH"
  git "${GIT_SAFE[@]}" -C "$APP_DIR" pull --quiet --ff-only origin "$BRANCH"
elif [[ -e "$APP_DIR" ]]; then
  die "${APP_DIR} exists but is not a git repository; remove it and run again"
else
  git "${GIT_SAFE[@]}" clone --quiet --branch "$BRANCH" "$REPO" "$APP_DIR"
fi
echo "    commit: $(git -C "$APP_DIR" rev-parse --short HEAD)"

# The code belongs to root and is not writable by the gateway user.
chmod 0755 "$APP_DIR"
chmod 0755 "$APP_DIR/scripts/backup.sh"

step "Dependencies (npm, production only, no install scripts, as user ${APP_USER})"
# N-10: install scripts of third-party packages must not run as root. The build runs in a separate directory
# as an unprivileged user with a temporary HOME and cache; the finished node_modules then
# goes to root and is not writable by gateway.
(
  umask 022
  build_dir="$(mktemp -d "${APP_HOME}/build.XXXXXX")"
  trap 'rm -rf "$build_dir"' EXIT
  # mktemp -d creates the directory as 0700 root: without chmod the gateway user cannot enter work (staging 04.11)
  chmod 0755 "$build_dir"
  install -d -m 0755 -o "$APP_USER" -g "$APP_USER" "$build_dir/home" "$build_dir/work"
  cp "$APP_DIR/package.json" "$build_dir/work/"
  [[ -f "$APP_DIR/package-lock.json" ]] && cp "$APP_DIR/package-lock.json" "$build_dir/work/"
  chown -R "$APP_USER:$APP_USER" "$build_dir/work"

  # All npm commands: clean environment, HOME and cache inside build_dir.
  as_builder() {
    runuser -u "$APP_USER" -- env -C "$build_dir/work" -i \
      PATH=/usr/bin:/bin HOME="$build_dir/home" TMPDIR="$build_dir/home" \
      npm_config_cache="$build_dir/home/.npm" "$@"
  }

  if [[ -f "$build_dir/work/package-lock.json" ]]; then
    as_builder npm ci --omit=dev --ignore-scripts --no-audit --no-fund
  else
    as_builder npm install --omit=dev --ignore-scripts --no-audit --no-fund
  fi
  # Explicit build of native modules (install scripts of other packages do not run).
  as_builder npm rebuild argon2 better-sqlite3 --no-audit --no-fund

  rm -rf "$APP_DIR/node_modules"
  mv "$build_dir/work/node_modules" "$APP_DIR/node_modules"
  chown -R root:root "$APP_DIR/node_modules"
  chmod -R go-w,a+rX "$APP_DIR/node_modules"
)

# ---------- 7. data directories ----------
step "Data directories"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0700 -o root -g root "$BACKUP_DIR"

# ---------- 8. gateway env file ----------
step "Configuration ${ENV_FILE} (0600)"
install -d -m 0755 -o root -g root "$ETC_DIR"
env_tmp="$(mktemp "${ETC_DIR}/env.XXXXXX")"
cat > "$env_tmp" <<ENV
# Gateway environment variables (read by systemd via EnvironmentFile). Created by setup.sh.
GW_DATA_DIR=${DATA_DIR}
GW_PORT=${GW_PORT}
GW_HOST=127.0.0.1
GW_PUBLIC_URL=https://${DOMAIN}
GW_VAULT=${VAULT}
GW_VAULT_PREFIX=/gateway
GW_SSM_REGION=${REGION}
GW_LOG_LEVEL=info
ENV
chmod 0600 "$env_tmp"
chown root:root "$env_tmp"
mv -f "$env_tmp" "$ENV_FILE"
if [[ "$VAULT" == "file" ]]; then
  echo "    WARNING: --vault file stores keys in a file on disk. Use it for tests only."
fi

# ---------- 9. gateway systemd unit ----------
step "systemd: gateway.service"
install -m 0644 -o root -g root "$APP_DIR/deploy/gateway.service" /etc/systemd/system/gateway.service
systemctl daemon-reload

# ---------- 10. Caddy: config with the domain ----------
step "Caddy: /etc/caddy/Caddyfile for ${DOMAIN}"
install -d -m 0755 -o caddy -g caddy /var/log/caddy
if [[ "$BEHIND_CF" -eq 1 ]]; then
  # Authenticated Origin Pulls (N-11): the operator places the CA file, the script does not download it.
  [[ -s "$CF_CA_FILE" ]] \
    || die "${CF_CA_FILE} not found: download the Authenticated Origin Pulls CA from the official Cloudflare page and put it there"
  cf_ca_actual="$(sha256sum "$CF_CA_FILE" | cut -d' ' -f1)"
  [[ "${cf_ca_actual,,}" == "${CF_CA_SHA256,,}" ]] \
    || die "SHA-256 of ${CF_CA_FILE} (${cf_ca_actual}) does not match the expected value; file rejected"
  chmod 0644 "$CF_CA_FILE"
  echo "    Cloudflare Origin Pull CA: fingerprint matches"
fi
render_cf "$APP_DIR/deploy/Caddyfile" | sed "s/{\$DOMAIN}/${DOMAIN}/g" > /etc/caddy/Caddyfile.new
caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile
chmod 0644 /etc/caddy/Caddyfile.new
mv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
# When run as root, caddy validate creates access.log owned by root, and the caddy service then cannot open it.
chown -R caddy:caddy /var/log/caddy

# ---------- 11. nftables ----------
step "nftables: checking and installing /etc/nftables.conf"
# The "#ssm" line (IMDS for the IAM role) is needed only for the ssm vault; with the file vault the metadata address stays closed.
if [[ "$VAULT" == "ssm" ]]; then
  render_cf "$APP_DIR/deploy/nftables.conf" | sed -e 's/[[:space:]]*#ssm$//' > /etc/nftables.conf.new
else
  render_cf "$APP_DIR/deploy/nftables.conf" | sed -e '/#ssm$/d' > /etc/nftables.conf.new
fi
nft -c -f /etc/nftables.conf.new
chmod 0644 /etc/nftables.conf.new
mv -f /etc/nftables.conf.new /etc/nftables.conf

# ---------- 12. backups ----------
step "Backups: cron and script"
install -m 0644 -o root -g root "$APP_DIR/deploy/backup.cron" /etc/cron.d/agentkeygate
bash -n "$APP_DIR/scripts/backup.sh"

# ---------- 13. starting services ----------
step "Enabling and restarting nftables, chrony, caddy, gateway"
systemctl enable nftables
systemctl restart nftables
systemctl enable chrony
systemctl restart chrony
systemctl enable caddy
systemctl restart caddy
systemctl enable gateway
systemctl restart gateway

# ---------- 14. waiting for readiness ----------
step "Waiting for http://127.0.0.1:${GW_PORT}/healthz (up to 15 s)"
ready=0
for _ in $(seq 1 15); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${GW_PORT}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "--- last lines of the gateway journal ---" >&2
  journalctl -u gateway -n 30 --no-pager >&2 || true
  die "the gateway did not respond within 15 s; see: journalctl -u gateway"
fi
echo "    gateway is responding"

# ---------- 15. setup wizard ----------
# gateway init resets the password, 2FA and sessions, so after the wizard is completed
# a repeated setup.sh run does not call it (only with --init).
setup_done="$(sqlite3 -readonly "${DATA_DIR}/gw.db" 'SELECT setup_done FROM owner WHERE id = 1' 2>/dev/null || true)"
if [[ "$setup_done" == "1" && "$FORCE_INIT" -ne 1 ]]; then
  step "Setup wizard already completed: gateway init skipped (to reset the password and 2FA: --init)"
  echo
  echo "Done. Code and configs are updated, services are restarted."
  exit 0
fi
step "Setup wizard: gateway init"
run_as_gw init

echo
echo "Done. Open the link above within 15 minutes and go through the wizard:"
echo "password, 2FA, Telegram. If the link has expired, run setup.sh again."
