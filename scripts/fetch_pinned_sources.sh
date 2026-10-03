#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/.github/source_pins.env"

fetch_pinned() {
  local repo="$1" rev="$2" dest="$3"
  if [[ ! "$rev" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::$repo pin is not a full commit hash: $rev"
    exit 1
  fi
  rm -rf "$dest"
  git init -q "$dest"
  git -C "$dest" fetch -q --depth=1 "https://github.com/Aster-Privacy/$repo.git" "$rev"
  git -C "$dest" checkout -q --detach FETCH_HEAD
  local actual
  actual="$(git -C "$dest" rev-parse HEAD)"
  if [[ "$actual" != "$rev" ]]; then
    echo "::error::$repo checked out $actual, expected $rev"
    exit 1
  fi
  echo "$repo pinned at $rev"
}

for name in "$@"; do
  case "$name" in
    ui) fetch_pinned aster-ui "$ASTER_UI_REV" "$root/../aster-ui" ;;
    mail) fetch_pinned Aster-Mail "$ASTER_MAIL_REV" "$root/../Aster-Mail" ;;
    *) echo "::error::unknown source: $name"; exit 1 ;;
  esac
done
