#!/usr/bin/env bash
# Push HACKERONE_API_KEY to GCP Secret Manager.
#
# Sources the value from .env (or whatever path you pass as $1), pipes it
# via stdin into `gcloud secrets ... --data-file=-` so it never appears
# in shell history, argv, or any log line.
#
# USAGE
#   bash scripts/gcp-secret-push.sh                       # use ./.env
#   bash scripts/gcp-secret-push.sh /path/to/.env         # use a specific .env
#   GCP_PROJECT=other-project bash scripts/gcp-secret-push.sh
#
# SAFETY
#   - The value is sourced + piped, NEVER echoed.
#   - We unset the variable on exit so subsequent shells don't inherit it.
#   - gcloud writes to Secret Manager only; nothing local persists.
set -euo pipefail

ENV_FILE="${1:-.env}"
GCP_PROJECT="${GCP_PROJECT:-ruv-dev}"
SECRET_NAME="HACKERONE_API_KEY"

if [ ! -f "$ENV_FILE" ]; then
  echo "gcp-secret-push: env file not found: $ENV_FILE" >&2
  exit 2
fi

# Robust dotenv read — `source` chokes on unquoted base64 / `/` chars.
# Extract only the literal value AFTER `HACKERONE_API_KEY=`, strip optional
# surrounding quotes, and assign without shell expansion.
RAW_LINE="$(grep -E '^[[:space:]]*HACKERONE_API_KEY[[:space:]]*=' "$ENV_FILE" | head -1 || true)"
if [ -z "$RAW_LINE" ]; then
  echo "gcp-secret-push: HACKERONE_API_KEY line not found in $ENV_FILE" >&2
  exit 2
fi
# Strip everything up to and including the first `=`
RAW_VAL="${RAW_LINE#*=}"
# Trim leading + trailing whitespace (handles `KEY = value` style)
RAW_VAL="$(printf '%s' "$RAW_VAL" | awk '{$1=$1; print}')"
# Strip surrounding " or ' if present (after whitespace trim)
case "$RAW_VAL" in
  \"*\")  RAW_VAL="${RAW_VAL#\"}"; RAW_VAL="${RAW_VAL%\"}" ;;
  \'*\')  RAW_VAL="${RAW_VAL#\'}"; RAW_VAL="${RAW_VAL%\'}" ;;
esac
HACKERONE_API_KEY="$RAW_VAL"

if [ -z "${HACKERONE_API_KEY:-}" ]; then
  echo "gcp-secret-push: HACKERONE_API_KEY value is empty in $ENV_FILE" >&2
  exit 2
fi

# Refuse to push the placeholder
if [ "$HACKERONE_API_KEY" = "username:token-goes-here" ]; then
  echo "gcp-secret-push: refusing to push the placeholder value" >&2
  exit 3
fi

# Diagnostics — length + first 4 chars only. NEVER the full value.
LEN=$(printf '%s' "$HACKERONE_API_KEY" | wc -c | tr -d ' ')
PREFIX=$(printf '%s' "$HACKERONE_API_KEY" | head -c 4)
echo "gcp-secret-push: project=$GCP_PROJECT secret=$SECRET_NAME len=$LEN prefix=${PREFIX}…"

# Check if the secret already exists; create or add-version accordingly.
if gcloud secrets describe "$SECRET_NAME" --project="$GCP_PROJECT" >/dev/null 2>&1; then
  echo "gcp-secret-push: secret exists — adding new version"
  printf '%s' "$HACKERONE_API_KEY" \
    | gcloud secrets versions add "$SECRET_NAME" \
        --data-file=- \
        --project="$GCP_PROJECT"
else
  echo "gcp-secret-push: creating secret"
  printf '%s' "$HACKERONE_API_KEY" \
    | gcloud secrets create "$SECRET_NAME" \
        --replication-policy=automatic \
        --data-file=- \
        --project="$GCP_PROJECT"
fi

# Wipe from this shell's env. Subsequent commands in the same shell
# session won't see the variable.
unset HACKERONE_API_KEY

echo "gcp-secret-push: done."
echo "Verify with: gcloud secrets versions access latest --secret=$SECRET_NAME --project=$GCP_PROJECT | head -c 4; echo"
