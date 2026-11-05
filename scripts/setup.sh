#!/usr/bin/env bash
# Установка и обновление agent-gateway на VPS: Debian 12 / Ubuntu 24.04, Amazon EC2 t3.micro (1 ГБ RAM).
#
# Запуск от root:
#   sudo ./setup.sh --domain gw.example.com [--repo URL] [--branch main] [--vault ssm|file] [--region eu-central-1]
#
# Скрипт идемпотентен: повторный запуск обновляет код из git, пересобирает зависимости,
# перезаписывает конфиги из репозитория и перезапускает сервисы. В конце запускает
# `gateway init`, который печатает одноразовую ссылку мастера настройки (живёт 15 минут).
set -euo pipefail

# ---------- константы ----------
readonly APP_USER="gateway"
readonly APP_HOME="/opt/agent-gateway"
readonly APP_DIR="${APP_HOME}/app"
readonly DATA_DIR="/var/lib/agent-gateway"
readonly BACKUP_DIR="/var/backups/agent-gateway"
readonly ETC_DIR="/etc/agent-gateway"
readonly ENV_FILE="${ETC_DIR}/env"
readonly GW_PORT="8080"
# Authenticated Origin Pulls (режим Cloudflare): CA кладёт оператор, скрипт его не скачивает.
readonly CF_CA_FILE="/etc/caddy/cloudflare-origin-pull-ca.pem"
# SHA-256 CA global AOP (developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem,
# CN=origin-pull.cloudflare.net, до 01.11.2029). Сверено 04.11.2026: две загрузки, с сервера и с другой машины.
# Если Cloudflare выпустит новый CA, передайте новый отпечаток флагом --cf-ca-sha256.
CF_CA_SHA256="c14fed0ce5210db0719fea11d1f10b33750dc17d609aeaf47c75e9eff0d7b843"

# ---------- вспомогательные функции ----------
step() { echo "==> $*"; }
die()  { echo "ОШИБКА: $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Использование:
  sudo ./setup.sh --domain gw.example.com [--repo URL] [--branch BRANCH] [--vault ssm|file] [--region REGION]

  --domain   обязательный; домен, A-запись которого указывает на Elastic IP (Cloudflare, серая тучка)
  --repo     git-репозиторий (по умолчанию https://github.com/maximskorohod/agent-gateway.git)
             или абсолютный путь к голому репозиторию на сервере (для закрытого репозитория)
  --branch   ветка (по умолчанию main)
  --vault    ssm (по умолчанию, прод: ключи в AWS SSM по IAM-роли) или file (только для тестов)
  --region   регион AWS для SSM (по умолчанию eu-central-1)
  --behind-cloudflare  домен проксируется Cloudflare (оранжевая тучка, SSL Full strict):
             Caddy берёт IP клиента из CF-Connecting-IP, nftables пускает 80/443 только с адресов Cloudflare.
             Cloudflare при этом видит трафик, включая ключи в запросах. Включает Authenticated Origin Pulls:
             положите CA Cloudflare в /etc/caddy/cloudflare-origin-pull-ca.pem до запуска (скрипт не скачивает его),
             отпечаток SHA-256 сверяется с константой CF_CA_SHA256 или флагом --cf-ca-sha256.
  --cf-ca-sha256 HEX  ожидаемый SHA-256 файла CA Cloudflare (64 hex-символа, сверен с официальной страницей)
  --init     заново открыть мастер (gateway init) после того, как он уже пройден:
             сбрасывает пароль, 2FA, сессии и пропуска; ключи и агенты остаются
USAGE
}

# Запускает команду от пользователя gateway с переменными GW_* из env-файла.
# Сам env-файл (0600, root) пользователь gateway не читает, поэтому переменные берёт root.
run_as_gw() {
  (
    # Файл не подключается через `.`: GW_PORT здесь readonly, и повторное присваивание роняет скрипт.
    # Значения в env-файле простые (KEY=VALUE без кавычек), их можно передать как есть.
    local -a gwenv
    mapfile -t gwenv < <(grep -E '^GW_[A-Z0-9_]+=' "$ENV_FILE" || true)
    exec runuser -u "$APP_USER" -- env -C "$APP_DIR" -i PATH=/usr/bin:/bin "${gwenv[@]}" \
      /usr/bin/node "$APP_DIR/bin/gateway.js" "$@"
  )
}

# ---------- разбор аргументов ----------
DOMAIN=""
REPO="https://github.com/maximskorohod/agent-gateway.git"
BRANCH="main"
VAULT="ssm"
REGION="eu-central-1"
BEHIND_CF=0
FORCE_INIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) [[ $# -ge 2 ]] || die "--domain требует значение"; DOMAIN="$2"; shift 2 ;;
    --repo)   [[ $# -ge 2 ]] || die "--repo требует значение";   REPO="$2";   shift 2 ;;
    --branch) [[ $# -ge 2 ]] || die "--branch требует значение"; BRANCH="$2"; shift 2 ;;
    --vault)  [[ $# -ge 2 ]] || die "--vault требует значение";  VAULT="$2";  shift 2 ;;
    --region) [[ $# -ge 2 ]] || die "--region требует значение"; REGION="$2"; shift 2 ;;
    --behind-cloudflare) BEHIND_CF=1; shift ;;
    --cf-ca-sha256) [[ $# -ge 2 ]] || die "--cf-ca-sha256 требует значение"; CF_CA_SHA256="$2"; shift 2 ;;
    --init) FORCE_INIT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "неизвестный аргумент: $1" ;;
  esac
done

# ---------- проверки ----------
[[ $EUID -eq 0 ]] || die "запустите скрипт от root: sudo ./setup.sh --domain ..."
[[ -n "$DOMAIN" ]] || { usage; die "не задан --domain"; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
  || die "некорректный домен: $DOMAIN"
# Локальный путь — для закрытого репозитория: код заливается на сервер через `git push` по ssh
# в голый репозиторий, и сервер не хранит токенов GitHub.
[[ "$REPO" =~ ^https://[^[:space:]]+$ || "$REPO" =~ ^/[^[:space:]]+$ ]] \
  || die "--repo должен быть https-адресом или абсолютным путём к git-репозиторию на сервере"
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "некорректное имя ветки: $BRANCH"
case "$VAULT" in
  ssm|file) ;;
  *) die "--vault должен быть ssm или file" ;;
esac
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "некорректный регион: $REGION"
if [[ "$BEHIND_CF" -eq 1 ]]; then
  [[ "$CF_CA_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
    || die "не задан отпечаток CA Cloudflare: сверьте файл с официальной страницей Cloudflare и передайте --cf-ca-sha256 <sha256>"
fi

# shellcheck disable=SC1091
. /etc/os-release
case "${ID}:${VERSION_ID:-}" in
  debian:12|ubuntu:24.04|ubuntu:26.04) ;;
  *) die "поддерживаются Debian 12 и Ubuntu 24.04/26.04, а это: ${PRETTY_NAME:-неизвестно}" ;;
esac

# Конфиги из deploy/ с пометками "#cf " (включить за Cloudflare) и "#nocf" (только без Cloudflare).
render_cf() {
  if [[ "$BEHIND_CF" -eq 1 ]]; then
    sed -e 's/^\([[:space:]]*\)#cf /\1/' -e '/#nocf$/d' "$1"
  else
    sed -e '/^[[:space:]]*#cf /d' -e 's/[[:space:]]*#nocf$//' "$1"
  fi
}

export DEBIAN_FRONTEND=noninteractive

# ---------- 1. системные пакеты ----------
step "Обновляю список пакетов и ставлю базовые пакеты"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  curl ca-certificates gnupg git build-essential python3 sqlite3 \
  unattended-upgrades nftables chrony

step "Автообновления безопасности (unattended-upgrades)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
# ---------- 2. swap 1 ГБ (нужен на 1 ГБ RAM: npm ci и сборка нативных модулей) ----------
step "Swap 1 ГБ и vm.swappiness=10"
if [[ -z "$(swapon --noheadings --show=NAME)" ]]; then
  if [[ ! -f /swapfile ]]; then
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
else
  echo "    swap уже активен, пропускаю"
fi
grep -qE '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
echo 'vm.swappiness = 10' > /etc/sysctl.d/99-agent-gateway.conf
sysctl -q -p /etc/sysctl.d/99-agent-gateway.conf

# ---------- 3. Node.js 22 (NodeSource) ----------
step "Node.js 22"
node_major="$(node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || true)"
if [[ "${node_major:-0}" -ge 22 ]]; then
  echo "    уже установлен: $(node -v), пропускаю"
else
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq nodejs
  echo "    установлен: $(node -v)"
fi

# ---------- 4. Caddy (официальный репозиторий caddyserver.com/docs/install) ----------
step "Caddy из официального репозитория"
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

# ---------- 5. системный пользователь ----------
step "Пользователь ${APP_USER} (без shell, дом ${APP_HOME})"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_HOME" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
  echo "    создан"
else
  echo "    уже есть"
fi
install -d -m 0755 -o root -g root "$APP_HOME"

# ---------- 6. код приложения ----------
step "Код приложения: ${REPO} (${BRANCH}) → ${APP_DIR}"
# Голый репозиторий на сервере обычно принадлежит пользователю, который в него пушит (не root).
# Глобальный git config не трогаем: safe.directory для локального репозитория передаётся
# ключом -c только в тех командах, которые к нему обращаются (Н-10).
GIT_SAFE=()
if [[ "$REPO" == /* ]]; then
  GIT_SAFE=(-c "safe.directory=${REPO}")
fi
if [[ -d "$APP_DIR/.git" ]]; then
  git "${GIT_SAFE[@]}" -C "$APP_DIR" remote set-url origin "$REPO"
  git "${GIT_SAFE[@]}" -C "$APP_DIR" fetch --quiet origin "$BRANCH"
  # Ниже скрипт сам делает chmod 0755 backup.sh; в старых коммитах файл был 0644, и git считал это локальной
  # правкой: pull отказывался обновлять код (staging 04.11). Возвращаем файл к версии из git перед pull.
  git "${GIT_SAFE[@]}" -C "$APP_DIR" checkout --quiet -- scripts/backup.sh
  git "${GIT_SAFE[@]}" -C "$APP_DIR" checkout --quiet "$BRANCH"
  git "${GIT_SAFE[@]}" -C "$APP_DIR" pull --quiet --ff-only origin "$BRANCH"
elif [[ -e "$APP_DIR" ]]; then
  die "${APP_DIR} существует, но это не git-репозиторий; уберите его и запустите снова"
else
  git "${GIT_SAFE[@]}" clone --quiet --branch "$BRANCH" "$REPO" "$APP_DIR"
fi
echo "    коммит: $(git -C "$APP_DIR" rev-parse --short HEAD)"

# Код принадлежит root и не доступен на запись пользователю gateway.
chmod 0755 "$APP_DIR"
chmod 0755 "$APP_DIR/scripts/backup.sh"

step "Зависимости (npm, только production, без скриптов установки, от пользователя ${APP_USER})"
# Н-10: скрипты установки чужих пакетов не должны выполняться от root. Сборка идёт в отдельном каталоге
# от непривилегированного пользователя с временным HOME и кэшем; готовый node_modules затем
# переходит к root и недоступен gateway на запись.
(
  umask 022
  build_dir="$(mktemp -d "${APP_HOME}/build.XXXXXX")"
  trap 'rm -rf "$build_dir"' EXIT
  # mktemp -d создаёт каталог 0700 от root: без chmod пользователь gateway не войдёт в work (staging 04.11)
  chmod 0755 "$build_dir"
  install -d -m 0755 -o "$APP_USER" -g "$APP_USER" "$build_dir/home" "$build_dir/work"
  cp "$APP_DIR/package.json" "$build_dir/work/"
  [[ -f "$APP_DIR/package-lock.json" ]] && cp "$APP_DIR/package-lock.json" "$build_dir/work/"
  chown -R "$APP_USER:$APP_USER" "$build_dir/work"

  # Все npm-команды: чистое окружение, HOME и кэш внутри build_dir.
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
  # Явная сборка нативных модулей (скрипты остальных пакетов не запускаются).
  as_builder npm rebuild argon2 better-sqlite3 --no-audit --no-fund

  rm -rf "$APP_DIR/node_modules"
  mv "$build_dir/work/node_modules" "$APP_DIR/node_modules"
  chown -R root:root "$APP_DIR/node_modules"
  chmod -R go-w,a+rX "$APP_DIR/node_modules"
)

# ---------- 7. каталоги данных ----------
step "Каталоги данных"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0700 -o root -g root "$BACKUP_DIR"

# ---------- 8. env-файл шлюза ----------
step "Конфигурация ${ENV_FILE} (0600)"
install -d -m 0755 -o root -g root "$ETC_DIR"
env_tmp="$(mktemp "${ETC_DIR}/env.XXXXXX")"
cat > "$env_tmp" <<ENV
# Переменные окружения шлюза (читает systemd через EnvironmentFile). Создано setup.sh.
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
  echo "    ВНИМАНИЕ: --vault file хранит ключи в файле на диске. Это только для тестов."
fi

# ---------- 9. systemd-юнит шлюза ----------
step "systemd: gateway.service"
install -m 0644 -o root -g root "$APP_DIR/deploy/gateway.service" /etc/systemd/system/gateway.service
systemctl daemon-reload

# ---------- 10. Caddy: конфиг с доменом ----------
step "Caddy: /etc/caddy/Caddyfile для ${DOMAIN}"
install -d -m 0755 -o caddy -g caddy /var/log/caddy
if [[ "$BEHIND_CF" -eq 1 ]]; then
  # Authenticated Origin Pulls (Н-11): файл CA кладёт оператор, скрипт его не скачивает.
  [[ -s "$CF_CA_FILE" ]] \
    || die "нет ${CF_CA_FILE}: скачайте CA Authenticated Origin Pulls с официальной страницы Cloudflare и положите сюда"
  cf_ca_actual="$(sha256sum "$CF_CA_FILE" | cut -d' ' -f1)"
  [[ "${cf_ca_actual,,}" == "${CF_CA_SHA256,,}" ]] \
    || die "SHA-256 ${CF_CA_FILE} (${cf_ca_actual}) не совпадает с ожидаемым; файл не принят"
  chmod 0644 "$CF_CA_FILE"
  echo "    CA Cloudflare Origin Pull: отпечаток совпал"
fi
render_cf "$APP_DIR/deploy/Caddyfile" | sed "s/{\$DOMAIN}/${DOMAIN}/g" > /etc/caddy/Caddyfile.new
caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile
chmod 0644 /etc/caddy/Caddyfile.new
mv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
# caddy validate от root сам создаёт access.log с владельцем root, и служба caddy потом не может его открыть.
chown -R caddy:caddy /var/log/caddy

# ---------- 11. nftables ----------
step "nftables: проверка и установка /etc/nftables.conf"
# Строка "#ssm" (IMDS для IAM-роли) нужна только сейфу ssm; с файловым сейфом адрес метаданных закрыт.
if [[ "$VAULT" == "ssm" ]]; then
  render_cf "$APP_DIR/deploy/nftables.conf" | sed -e 's/[[:space:]]*#ssm$//' > /etc/nftables.conf.new
else
  render_cf "$APP_DIR/deploy/nftables.conf" | sed -e '/#ssm$/d' > /etc/nftables.conf.new
fi
nft -c -f /etc/nftables.conf.new
chmod 0644 /etc/nftables.conf.new
mv -f /etc/nftables.conf.new /etc/nftables.conf

# ---------- 12. резервные копии ----------
step "Резервные копии: cron и скрипт"
install -m 0644 -o root -g root "$APP_DIR/deploy/backup.cron" /etc/cron.d/agent-gateway
bash -n "$APP_DIR/scripts/backup.sh"

# ---------- 13. запуск сервисов ----------
step "Включаю и перезапускаю nftables, chrony, caddy, gateway"
systemctl enable nftables
systemctl restart nftables
systemctl enable chrony
systemctl restart chrony
systemctl enable caddy
systemctl restart caddy
systemctl enable gateway
systemctl restart gateway

# ---------- 14. ожидание готовности ----------
step "Жду ответа http://127.0.0.1:${GW_PORT}/healthz (до 15 с)"
ready=0
for _ in $(seq 1 15); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${GW_PORT}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "--- последние строки журнала gateway ---" >&2
  journalctl -u gateway -n 30 --no-pager >&2 || true
  die "шлюз не ответил за 15 с; смотрите: journalctl -u gateway"
fi
echo "    шлюз отвечает"

# ---------- 15. мастер настройки ----------
# gateway init сбрасывает пароль, 2FA и сессии, поэтому после пройденного мастера повторный
# запуск setup.sh его не вызывает (только с --init).
setup_done="$(sqlite3 -readonly "${DATA_DIR}/gw.db" 'SELECT setup_done FROM owner WHERE id = 1' 2>/dev/null || true)"
if [[ "$setup_done" == "1" && "$FORCE_INIT" -ne 1 ]]; then
  step "Мастер уже пройден: gateway init пропущен (сбросить пароль и 2FA: --init)"
  echo
  echo "Готово. Код и конфиги обновлены, сервисы перезапущены."
  exit 0
fi
step "Мастер настройки: gateway init"
run_as_gw init

echo
echo "Готово. Откройте ссылку выше в течение 15 минут и пройдите мастер:"
echo "пароль, 2FA, Telegram. Если ссылка истекла, запустите setup.sh ещё раз."
