#!/usr/bin/env bash
# gw.sh: get owner-approved access through agent-gateway and call APIs with the pass.
# The API key never reaches this script or the agent.
#
#   gw.sh request <service> <ttl_seconds> <calls> "<reason>"
#   gw.sh call <service> <METHOD> <path> [json-body]
#
# Environment: AGENT_GATEWAY_URL, AGENT_GATEWAY_TOKEN (agent token, gwa_...).
# Optional: GW_CREDENTIAL_ID (when the service has several keys).
# The pass is saved to ${XDG_RUNTIME_DIR:-$HOME/.cache}/agent-gateway/<service>.token (directory mode 700, file mode 600).
#
# Exit codes:
#   0  success
#   1  any other error (also an error status returned by the service itself)
#   2  wrong usage
#   3  method_not_allowed: the owner's filter closed this method. Do not ask to bypass it.
#   4  write_not_allowed: the owner's filter is read-only or has not opened writes. Do not ask to bypass it.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  gw.sh request <service> <ttl_seconds> <calls> "<reason>"
  gw.sh call <service> <METHOD> <path> [json-body]
USAGE
  exit 2
}

die() { echo "gw: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

: "${AGENT_GATEWAY_URL:?set AGENT_GATEWAY_URL to the gateway base URL}"
: "${AGENT_GATEWAY_TOKEN:?set AGENT_GATEWAY_TOKEN to your agent token}"
BASE="${AGENT_GATEWAY_URL%/}"

HTTP_CODE=""
BODY=""

check_service() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "invalid service name: $1"
}

pass_dir() {
  echo "${XDG_RUNTIME_DIR:-${HOME:?HOME is not set}/.cache}/agent-gateway"
}

token_file() {
  echo "$(pass_dir)/$1.token"
}

save_pass() {
  local service="$1" token="$2" dir
  [[ "$token" == gwt_* ]] || die "gateway returned no pass"
  dir=$(pass_dir)
  # private directory (0700): other local users can neither list nor guess the pass file
  ( umask 077; mkdir -p -m 700 "$dir" ) || die "cannot create $dir"
  chmod 700 "$dir" 2>/dev/null || true
  ( umask 077; printf '%s\n' "$token" > "$(token_file "$service")" )
}

# Calls the gateway. Sets HTTP_CODE and BODY.
# The bearer token goes through a curl config read from a file descriptor, so it never appears in argv.
api() {
  local method="$1" path="$2" data="${3:-}" auth="${4:-$AGENT_GATEWAY_TOKEN}"
  local -a extra=()
  if [[ -n "$data" ]]; then extra=(--data-binary "$data"); fi
  local out rc=0
  # -g: curl не разбирает [] и {} в URL как диапазоны (фильтры вида filter[ID]=1)
  out=$(curl -sS -g --max-time 60 -X "$method" "$BASE$path" \
        -K <(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$auth") \
        ${extra[@]+"${extra[@]}"} -w '\n%{http_code}') || rc=$?
  case "$rc" in
    0) ;;
    3) die "malformed URL: check the path and query (curl exit 3)" ;;
    7) die "cannot reach $BASE (connection refused or no route, curl exit 7)" ;;
    *) die "request failed (curl exit $rc): $BASE" ;;
  esac
  HTTP_CODE="${out##*$'\n'}"
  BODY="${out%$'\n'*}"
}

# Prints what the owner's filter lets you see (from the "filter" field of an approved answer), if there is one.
show_filter() {
  local f
  f=$(jq -c '.filter // empty' <<<"$BODY" 2>/dev/null) || return 0
  [[ -z "$f" ]] || echo "filter: $f" >&2
}

poll() {
  local service="$1" rid="$2" start now
  start=$(date +%s)
  while :; do
    sleep 5
    now=$(date +%s)
    if (( now - start > 600 )); then
      die "no answer after 10 minutes: the request expired. Ask the owner or try later."
    fi
    api GET "/v1/grants/$rid"
    case "$HTTP_CODE" in
      202) ;;
      200)
        save_pass "$service" "$(jq -r '.token // empty' <<<"$BODY")"
        echo "approved: pass saved for $service"
        show_filter
        return 0 ;;
      403) die "not approved: $(jq -r '.status // "denied"' <<<"$BODY")" ;;
      410) die "the pass was already issued or revoked" ;;
      429) ;;
      *) die "unexpected HTTP $HTTP_CODE while polling" ;;
    esac
  done
}

cmd_request() {
  local service="$1" ttl="$2" calls="$3" reason="$4" body
  check_service "$service"
  [[ "$ttl" =~ ^[0-9]+$ && "$calls" =~ ^[0-9]+$ ]] || die "ttl and calls must be whole numbers"
  [[ -n "$reason" ]] || die "reason is required: say why the access is needed"
  if (( ${#reason} > 200 )); then die "reason is longer than 200 characters"; fi

  body=$(jq -cn --arg p "$service" --argjson t "$ttl" --argjson c "$calls" --arg r "$reason" \
         --arg k "${GW_CREDENTIAL_ID:-}" \
         '{provider:$p, ttl:$t, calls:$c, reason:$r} + (if $k == "" then {} else {credential_id:$k} end)')

  api POST /v1/grants "$body"
  case "$HTTP_CODE" in
    200)
      save_pass "$service" "$(jq -r '.token // empty' <<<"$BODY")"
      echo "approved: pass saved for $service (max $(jq -r '.max_calls' <<<"$BODY") calls)"
      show_filter ;;
    202)
      local rid
      rid=$(jq -r '.request_id' <<<"$BODY")
      echo "waiting for the owner to approve (request $rid)" >&2
      poll "$service" "$rid" ;;
    400)
      echo "$BODY" >&2
      die "several keys exist for $service: set GW_CREDENTIAL_ID to one of the ids above" ;;
    401) die "agent token rejected: check AGENT_GATEWAY_TOKEN" ;;
    403) die "denied: $(jq -r '.reason // .error // "no details"' <<<"$BODY")" ;;
    429) die "rate limited: wait at least 60 seconds" ;;
    *) die "unexpected HTTP $HTTP_CODE from the gateway" ;;
  esac
}

cmd_call() {
  local service="$1" method="${2^^}" path="${3#/}" data="${4:-}" file pass
  check_service "$service"
  case "$method" in
    GET|POST|PUT|PATCH|DELETE) ;;
    *) die "unsupported method: $method" ;;
  esac
  # Проверки касаются только пути (до "?"): в запросе допустимы @ (email), .. и ://
  case "${path%%\?*}" in
    *..*|*@*|*://*) die "invalid path" ;;
  esac

  file=$(token_file "$service")
  [[ -r "$file" ]] || die "no pass for $service: run 'gw.sh request $service ...' first"
  pass=$(<"$file")

  api "$method" "/v1/proxy/$service/$path" "$data" "$pass"
  case "$HTTP_CODE" in
    401)
      rm -f "$file"
      die "the pass is invalid, expired, or revoked. Request a new one only if the task still needs it." ;;
    429) die "pass limit reached (calls or parallel requests). Do not retry in a loop." ;;
    502) die "the service did not respond. Retry once later." ;;
  esac
  printf '%s\n' "$BODY"
  # The owner's filter closed the method: separate exit codes (3, 4), no retries and no workarounds.
  if [[ "$HTTP_CODE" == 403 ]]; then
    local code=""
    [[ "$BODY" =~ \"error\"[[:space:]]*:[[:space:]]*\"([a-z_]+)\" ]] && code="${BASH_REMATCH[1]}"
    case "$code" in
      method_not_allowed)
        echo "gw: method closed by the owner's filter, do not ask to bypass it" >&2
        exit 3 ;;
      write_not_allowed)
        echo "gw: writes closed by the owner's filter, do not ask to bypass it" >&2
        exit 4 ;;
    esac
  fi
  if [[ "$HTTP_CODE" != 2* ]]; then
    echo "gw: service returned HTTP $HTTP_CODE" >&2
    exit 1
  fi
}

main() {
  [[ $# -ge 1 ]] || usage
  case "$1" in
    request)
      [[ $# -eq 5 ]] || usage
      cmd_request "$2" "$3" "$4" "$5" ;;
    call)
      [[ $# -ge 4 && $# -le 5 ]] || usage
      cmd_call "$2" "$3" "$4" "${5:-}" ;;
    *) usage ;;
  esac
}

main "$@"
