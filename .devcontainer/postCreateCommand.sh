#!/usr/bin/env bash

set -Eeuxo pipefail

sudo chown ubuntu target
sudo chown ubuntu optee/target
# This path is a magic string. See https://stackoverflow.com/a/60713369
# sudo chown vscode /run/host-services/ssh-auth.sock

git config --global --add safe.directory /workspaces/orb-rustzone

nix profile install \
    nixpkgs#direnv \
    nixpkgs#nix-direnv \
    nixpkgs#starship

# Get direnv to work in the bash scripts
if [ ! -e .envrc ]; then
    cp .envrc.example .envrc # Bootstrap for the user
fi

if [ -e .devcontainer/postCreateCommand.user.sh ]; then
    .devcontainer/postCreateCommand.user.sh
fi
