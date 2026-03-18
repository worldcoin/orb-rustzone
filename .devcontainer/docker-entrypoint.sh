#!/usr/bin/env bash
set -euo pipefail

mkdir -p /nix/var/nix/daemon-socket

nix-daemon &
daemon_pid=$!

for _ in $(seq 1 100); do
  if [ -S /nix/var/nix/daemon-socket/socket ]; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "nix-daemon exited before creating its socket" >&2
    exit 1
  fi
  sleep 0.1
done

if [ ! -S /nix/var/nix/daemon-socket/socket ]; then
  echo "Timed out waiting for nix-daemon socket" >&2
  exit 1
fi

export NIX_REMOTE=daemon
export USER=vscode
export HOME=/home/vscode

exec gosu vscode "$@"
