#!/usr/bin/env bash
# Daily backup of the AgentKeyGate database (P-35: encrypted only).
# Run by cron as root (deploy/backup.cron, 03:17). Steps:
#   1) check that there is a way to encrypt: age with /etc/agentkeygate/backup.age.pub or gpg with
#      /etc/agentkeygate/backup.pass. If neither is available, no backup is made: error and exit code 1.
#      A plaintext copy never stays on disk, whatever the outcome (the trap removes all intermediate files);
#   2) SQLite snapshot with the .backup command (consistent even while the gateway runs, WAL);
#   3) if the gateway uses the file vault (GW_VAULT=file in /etc/agentkeygate/env), vault.json and
#      master.key from the data directory are added to the backup. Decision: the master key is stored
#      IN THE SAME encrypted archive as the vault. Without the key vault.json cannot be decrypted, so
#      a vault without its key is useless for recovery, and keeping the key separately means
#      losing it in the first failure. The protection of the whole content rests entirely on
#      the archive encryption (age: the private key is held only by the owner, off the server; gpg: the passphrase
#      is stored on the server, so the copy only protects against a leak of the backup files themselves).
#      For the ssm vault (production) only the database goes into the backup: gw-DATE.db.age|gpg;
#      for the file vault it is an archive: gw-DATE.tar.age|gpg with the files gw.db, vault.json, master.key;
#   4) upload to S3 (the encrypted file only) if S3_BUCKET is set in /etc/agentkeygate/backup.env;
#   5) delete local copies older than 30 days.
# Restore steps are in docs/DEPLOY.md, section 5. Passwords and keys are never printed.
set -euo pipefail
# The snapshot and the encryption are accessible to root only.
umask 077

readonly DATA_DIR="${GW_BACKUP_DATA_DIR:-/var/lib/agentkeygate}"
readonly DB="${DATA_DIR}/gw.db"
readonly BACKUP_DIR="${GW_BACKUP_DIR:-/var/backups/agentkeygate}"
readonly AGE_PUB="${GW_BACKUP_AGE_PUB:-/etc/agentkeygate/backup.age.pub}"
readonly GPG_PASS="/etc/agentkeygate/backup.pass"
readonly BACKUP_ENV="/etc/agentkeygate/backup.env"
readonly GW_ENV="/etc/agentkeygate/env"
readonly KEEP_DAYS=30

log() { echo "[$(date '+%F %T')] $*"; }

# Do not run two backups at the same time (for example, if the previous one hung).
exec 9>/run/agentkeygate-backup.lock
flock -n 9 || { log "the previous backup is still running, skipping"; exit 0; }

# S3 settings (S3_BUCKET, S3_PREFIX) are optional.
if [[ -f "$BACKUP_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$BACKUP_ENV"
  set +a
fi

command -v sqlite3 >/dev/null 2>&1 || { log "ERROR: sqlite3 is not installed"; exit 1; }
[[ -f "$DB" ]] || { log "ERROR: database not found: $DB"; exit 1; }
# The data directory belongs to the gateway user and this script runs as root: a link there must not make root read other files.
for f in "$DB" "${DB}-wal" "${DB}-shm"; do
  [[ ! -L "$f" ]] || { log "ERROR: symbolic link in the data directory: $f"; exit 1; }
done

install -d -m 0700 -o root -g root "$BACKUP_DIR"

STAMP="$(date +%F)"
PLAIN="${BACKUP_DIR}/gw-${STAMP}.db"
STAGE="${BACKUP_DIR}/stage-${STAMP}"
TARBALL="${BACKUP_DIR}/gw-${STAMP}.tar"
# In WAL mode the snapshot leaves -wal and -shm files next to it; remove them together with it.
rm_plain() { rm -rf "$PLAIN" "${PLAIN}-wal" "${PLAIN}-shm" "$STAGE" "$TARBALL"; }
rm_plain
# Any exit (error, set -e, no encryption) leaves no plaintext data on disk.
trap rm_plain EXIT

# Pick the encryption method before the snapshot: no method, no plaintext copy.
if command -v age >/dev/null 2>&1 && [[ -f "$AGE_PUB" ]]; then
  ENC=age
elif command -v gpg >/dev/null 2>&1 && [[ -f "$GPG_PASS" ]]; then
  ENC=gpg
else
  log "ERROR: nothing to encrypt with (need age with ${AGE_PUB} or gpg with ${GPG_PASS}); no backup created, no plaintext copy kept"
  rm_plain
  exit 1
fi

# Read the vault type from the gateway env file as text (the file is not executed).
VAULT_MODE=""
if [[ -f "$GW_ENV" ]]; then
  VAULT_MODE="$(grep -E '^GW_VAULT=' "$GW_ENV" | tail -n 1 | cut -d= -f2- | tr -d "\"' " || true)"
fi

sqlite3 "$DB" ".backup '${PLAIN}'"
[[ -s "$PLAIN" ]] || { log "ERROR: snapshot was not created"; rm_plain; exit 1; }
# If the gateway was stopped, sqlite3 created -wal and -shm as root, and the gateway would not start with them.
for f in "${DB}-wal" "${DB}-shm"; do
  if [[ -e "$f" && ! -L "$f" ]]; then chown --reference="$DB" "$f"; fi
done

SRC="$PLAIN"
NAME_BASE="gw-${STAMP}.db"
if [[ "$VAULT_MODE" == "file" ]]; then
  command -v tar >/dev/null 2>&1 || { log "ERROR: tar is not installed"; exit 1; }
  [[ -f "${DATA_DIR}/vault.json" && -f "${DATA_DIR}/master.key" ]] || { log "ERROR: GW_VAULT=file, but vault.json or master.key not found in ${DATA_DIR}"; exit 1; }
  [[ ! -L "${DATA_DIR}/vault.json" && ! -L "${DATA_DIR}/master.key" ]] || { log "ERROR: symbolic link instead of the vault file"; exit 1; }
  install -d -m 0700 "$STAGE"
  mv "$PLAIN" "${STAGE}/gw.db"
  cp -P "${DATA_DIR}/vault.json" "${STAGE}/vault.json"
  cp -P "${DATA_DIR}/master.key" "${STAGE}/master.key"
  tar -C "$STAGE" -cf "$TARBALL" gw.db vault.json master.key
  rm -rf "$STAGE"
  SRC="$TARBALL"
  NAME_BASE="gw-${STAMP}.tar"
  log "vault.json and master.key included in the backup (file vault)"
fi

FINAL="${BACKUP_DIR}/${NAME_BASE}.${ENC}"
rm -f "$FINAL"
if [[ "$ENC" == "age" ]]; then
  age -R "$AGE_PUB" -o "$FINAL" "$SRC"
else
  gpg --batch --yes --quiet --pinentry-mode loopback --symmetric --cipher-algo AES256 \
    --passphrase-file "$GPG_PASS" -o "$FINAL" "$SRC"
fi
[[ -s "$FINAL" ]] || { log "ERROR: encrypted file was not created"; rm -f "$FINAL"; exit 1; }
rm_plain
log "encrypted with ${ENC}: $(basename "$FINAL")"

# Only the encrypted file goes to S3 (no other files are left at this point).
if [[ -n "${S3_BUCKET:-}" ]]; then
  if command -v aws >/dev/null 2>&1; then
    KEY_PREFIX="${S3_PREFIX:-agentkeygate}"
    aws s3 cp "$FINAL" "s3://${S3_BUCKET}/${KEY_PREFIX}/$(basename "$FINAL")" --sse AES256 --only-show-errors
    log "uploaded to s3://${S3_BUCKET}/${KEY_PREFIX}/ (retention is set by the bucket lifecycle rule)"
  else
    log "WARNING: S3_BUCKET is set but the aws CLI is not installed; upload skipped"
  fi
fi

find "$BACKUP_DIR" -maxdepth 1 -type f -name 'gw-*' -mtime +"$KEEP_DAYS" -delete
log "done: $(basename "$FINAL"), size $(du -h "$FINAL" | cut -f1); local copies older than ${KEEP_DAYS} days removed"
