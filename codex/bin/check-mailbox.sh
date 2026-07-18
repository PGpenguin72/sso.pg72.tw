#!/bin/sh

set -eu

role=${1:-}
case "$role" in
  A|C|D|E) ;;
  *)
    echo "usage: $0 <A|C|D|E>" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mailbox="$repo_root/codex/mailboxes/$role"
acknowledgements="$repo_root/codex/acks/$role"
found=0

for message in "$mailbox"/*.md; do
  [ -f "$message" ] || continue
  filename=${message##*/}
  [ "$filename" = "README.md" ] && continue
  message_id=${filename%.md}
  if [ ! -f "$acknowledgements/$message_id.ack.md" ]; then
    printf '%s\n' "$message"
    found=1
  fi
done

if [ "$found" -eq 0 ]; then
  printf '%s\n' "NO_UNACKNOWLEDGED_MESSAGES"
fi
