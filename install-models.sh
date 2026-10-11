#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Spidy local-model installer (Linux / macOS)
#
# Pulls the open, uncensored LLMs Spidy's Autopilot uses, into your local
# Ollama. Nothing leaves your machine: Ollama runs locally and Spidy only ever
# talks to http://127.0.0.1:11434. Safe to re-run — it skips models you already
# have. These models are large; see the sizes below before pulling.
#
# Roles:
#   executor — proposes the next command/tool (smaller, fast)
#   guide    — the bigger, smarter supervisor that steers the executor
#
# Usage:
#   bash install-models.sh                # pull the default (reasonably sized) set
#   bash install-models.sh --with-large   # also pull the big mixtral guide (~26GB)
#   bash install-models.sh dolphin-mistral llama3.1:8b   # pull only what you name
# ---------------------------------------------------------------------------
set -uo pipefail

# name | role | approx size | note
DEFAULT_MODELS=(
  "dolphin-mistral|executor/guide|4.1GB|uncensored, 7B, 32K context, strong at commands"
  "dolphin3:8b|executor/guide|4.9GB|uncensored, newer (Llama 3.1 base)"
  "llama3.1:8b|guide|4.9GB|strong general guide"
)
LARGE_MODELS=(
  "dolphin-mixtral:8x7b|guide|26GB|uncensored, much stronger reasoning — needs ~32GB RAM"
)

WITH_LARGE=0
NAMED=()
for arg in "$@"; do
  case "$arg" in
    --with-large) WITH_LARGE=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) NAMED+=("$arg") ;;
  esac
done

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is not installed. Get it from https://ollama.com/download , then re-run this script." >&2
  exit 1
fi

# Make sure the local Ollama server is reachable (ollama pull needs it running).
if ! ollama list >/dev/null 2>&1; then
  echo "Starting a local Ollama server (ollama serve) in the background…"
  (ollama serve >/dev/null 2>&1 &) ; sleep 2
  if ! ollama list >/dev/null 2>&1; then
    echo "Could not reach Ollama. Start it in another terminal with:  ollama serve" >&2
    exit 1
  fi
fi

installed(){ ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$1"; }

# Build the list to pull.
TO_PULL=()
if [ "${#NAMED[@]}" -gt 0 ]; then
  for n in "${NAMED[@]}"; do TO_PULL+=("$n||| (requested)"); done
else
  TO_PULL=("${DEFAULT_MODELS[@]}")
  [ "$WITH_LARGE" = "1" ] && TO_PULL+=("${LARGE_MODELS[@]}")
fi

echo "Spidy local models — pulling into your Ollama:"
PULLED=(); SKIPPED=(); FAILED=()
for entry in "${TO_PULL[@]}"; do
  IFS='|' read -r name role size note <<< "$entry"
  name="${name// /}"
  [ -z "$name" ] && continue
  if installed "$name"; then
    echo "   skip: $name (already installed)"; SKIPPED+=("$name"); continue
  fi
  echo
  echo ">> $name  [${role:-model}${size:+, ~$size}]${note:+  — $note}"
  if ollama pull "$name"; then PULLED+=("$name"); else echo "   failed: $name"; FAILED+=("$name"); fi
done

echo
echo "Done. Pulled: ${#PULLED[@]}  Already had: ${#SKIPPED[@]}  Failed: ${#FAILED[@]}"
[ "${#FAILED[@]}" -gt 0 ] && printf '   could not pull: %s\n' "${FAILED[*]}"
if [ "$WITH_LARGE" != "1" ] && [ "${#NAMED[@]}" -eq 0 ]; then
  echo "Tip: add --with-large to also pull dolphin-mixtral:8x7b (a much stronger guide, ~26GB)."
fi
echo "In Spidy, click '↻ refresh' next to the model pickers, then choose your Executor and Guide."
