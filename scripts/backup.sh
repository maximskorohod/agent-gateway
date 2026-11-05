#!/usr/bin/env bash
# Ежесуточная резервная копия базы agent-gateway (П-35: только шифрованная).
# Запускается cron от root (deploy/backup.cron, 03:17). Шаги:
#   1) проверка, что есть чем шифровать: age с /etc/agent-gateway/backup.age.pub или gpg с
#      /etc/agent-gateway/backup.pass. Если нет ни того ни другого, бэкап не делается: ошибка и код 1.
#      Открытой копии на диске не бывает ни при каком исходе (trap удаляет всё промежуточное);
#   2) снимок SQLite командой .backup (согласован даже при работающем шлюзе, WAL);
#   3) если шлюз использует файловый сейф (GW_VAULT=file в /etc/agent-gateway/env), в копию
#      добавляются vault.json и master.key из каталога данных. Решение: мастер-ключ лежит
#      В ТОМ ЖЕ шифруемом архиве, что и сейф. Без ключа vault.json не расшифровать, то есть
#      сейф без ключа бесполезен для восстановления, а хранить ключ отдельно значит
#      потерять его при первой же аварии. Защита всего содержимого целиком держится на
#      шифровании архива (age: приватный ключ только у владельца, вне сервера; gpg: пароль
#      лежит на сервере, тогда копия защищает только от утечки самих файлов бэкапа).
#      Для сейфа ssm (прод) в копию идёт только база: gw-ДАТА.db.age|gpg;
#      для сейфа file архив: gw-ДАТА.tar.age|gpg с файлами gw.db, vault.json, master.key;
#   4) загрузка в S3 (только шифрованного файла), если в /etc/agent-gateway/backup.env задан S3_BUCKET;
#   5) удаление локальных копий старше 30 дней.
# Восстановление описано в docs/DEPLOY.md, раздел 5. Пароли и ключи в вывод не печатаются.
set -euo pipefail
# Снимок и шифровка доступны только root.
umask 077

readonly DATA_DIR="${GW_BACKUP_DATA_DIR:-/var/lib/agent-gateway}"
readonly DB="${DATA_DIR}/gw.db"
readonly BACKUP_DIR="/var/backups/agent-gateway"
readonly AGE_PUB="/etc/agent-gateway/backup.age.pub"
readonly GPG_PASS="/etc/agent-gateway/backup.pass"
readonly BACKUP_ENV="/etc/agent-gateway/backup.env"
readonly GW_ENV="/etc/agent-gateway/env"
readonly KEEP_DAYS=30

log() { echo "[$(date '+%F %T')] $*"; }

# Не запускать два бэкапа одновременно (например, если прошлый завис).
exec 9>/run/agent-gateway-backup.lock
flock -n 9 || { log "предыдущий бэкап ещё идёт, пропускаю"; exit 0; }

# Настройки S3 (S3_BUCKET, S3_PREFIX) необязательны.
if [[ -f "$BACKUP_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$BACKUP_ENV"
  set +a
fi

command -v sqlite3 >/dev/null 2>&1 || { log "ОШИБКА: sqlite3 не установлен"; exit 1; }
[[ -f "$DB" ]] || { log "ОШИБКА: база не найдена: $DB"; exit 1; }

install -d -m 0700 -o root -g root "$BACKUP_DIR"

STAMP="$(date +%F)"
PLAIN="${BACKUP_DIR}/gw-${STAMP}.db"
STAGE="${BACKUP_DIR}/stage-${STAMP}"
TARBALL="${BACKUP_DIR}/gw-${STAMP}.tar"
# Снимок в WAL-режиме оставляет рядом -wal и -shm; убираем их вместе с ним.
rm_plain() { rm -rf "$PLAIN" "${PLAIN}-wal" "${PLAIN}-shm" "$STAGE" "$TARBALL"; }
rm_plain
# Любой выход (ошибка, set -e, нет шифрования) не оставляет открытых данных на диске.
trap rm_plain EXIT

# Способ шифрования выбираем до снимка: нет способа, нет и открытой копии.
if command -v age >/dev/null 2>&1 && [[ -f "$AGE_PUB" ]]; then
  ENC=age
elif command -v gpg >/dev/null 2>&1 && [[ -f "$GPG_PASS" ]]; then
  ENC=gpg
else
  log "ОШИБКА: шифровать нечем (нужен age с ${AGE_PUB} или gpg с ${GPG_PASS}); бэкап не создан, открытая копия не хранится"
  rm_plain
  exit 1
fi

# Тип сейфа читаем из env-файла шлюза как текст (файл не исполняем).
VAULT_MODE=""
if [[ -f "$GW_ENV" ]]; then
  VAULT_MODE="$(grep -E '^GW_VAULT=' "$GW_ENV" | tail -n 1 | cut -d= -f2- | tr -d "\"' " || true)"
fi

sqlite3 "$DB" ".backup '${PLAIN}'"
[[ -s "$PLAIN" ]] || { log "ОШИБКА: снимок не создан"; rm_plain; exit 1; }

SRC="$PLAIN"
NAME_BASE="gw-${STAMP}.db"
if [[ "$VAULT_MODE" == "file" ]]; then
  command -v tar >/dev/null 2>&1 || { log "ОШИБКА: tar не установлен"; exit 1; }
  [[ -f "${DATA_DIR}/vault.json" && -f "${DATA_DIR}/master.key" ]] || { log "ОШИБКА: GW_VAULT=file, но vault.json или master.key не найдены в ${DATA_DIR}"; exit 1; }
  install -d -m 0700 "$STAGE"
  mv "$PLAIN" "${STAGE}/gw.db"
  cp "${DATA_DIR}/vault.json" "${STAGE}/vault.json"
  cp "${DATA_DIR}/master.key" "${STAGE}/master.key"
  tar -C "$STAGE" -cf "$TARBALL" gw.db vault.json master.key
  rm -rf "$STAGE"
  SRC="$TARBALL"
  NAME_BASE="gw-${STAMP}.tar"
  log "в копию включены vault.json и master.key (файловый сейф)"
fi

FINAL="${BACKUP_DIR}/${NAME_BASE}.${ENC}"
rm -f "$FINAL"
if [[ "$ENC" == "age" ]]; then
  age -R "$AGE_PUB" -o "$FINAL" "$SRC"
else
  gpg --batch --yes --quiet --pinentry-mode loopback --symmetric --cipher-algo AES256 \
    --passphrase-file "$GPG_PASS" -o "$FINAL" "$SRC"
fi
[[ -s "$FINAL" ]] || { log "ОШИБКА: шифрованный файл не создан"; rm -f "$FINAL"; exit 1; }
rm_plain
log "зашифровано ${ENC}: $(basename "$FINAL")"

# В S3 уходит только шифрованный файл (других на этом этапе уже нет).
if [[ -n "${S3_BUCKET:-}" ]]; then
  if command -v aws >/dev/null 2>&1; then
    KEY_PREFIX="${S3_PREFIX:-agent-gateway}"
    aws s3 cp "$FINAL" "s3://${S3_BUCKET}/${KEY_PREFIX}/$(basename "$FINAL")" --sse AES256 --only-show-errors
    log "загружено в s3://${S3_BUCKET}/${KEY_PREFIX}/ (срок хранения задаётся lifecycle-правилом бакета)"
  else
    log "ВНИМАНИЕ: S3_BUCKET задан, но aws CLI не установлен; загрузка пропущена"
  fi
fi

find "$BACKUP_DIR" -maxdepth 1 -type f -name 'gw-*' -mtime +"$KEEP_DAYS" -delete
log "готово: $(basename "$FINAL"), размер $(du -h "$FINAL" | cut -f1); локальные копии старше ${KEEP_DAYS} дней удалены"
