FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash zsh git ca-certificates curl sudo xz-utils gosu \
 && rm -rf /var/lib/apt/lists/*


# Create non-root devcontainer user
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

# Install Nix files, but no init integration.
RUN curl -sSfL https://artifacts.nixos.org/nix-installer | \
    sh -s -- install linux \
      --init none \
      --extra-conf "sandbox = false" \
      --extra-conf "experimental-features = nix-command flakes" \
      --extra-conf "max-jobs = auto" \
      --no-confirm

# Make Nix and direnv available in both bash and zsh shells
RUN cat >> /etc/bash.bashrc <<'EOF'
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
eval "$(direnv hook bash)"
EOF
RUN cat >> /etc/zsh/zshrc <<'EOF'
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
eval "$(direnv hook zsh)"
EOF

USER ubuntu
WORKDIR /home/ubuntu

CMD ["/bin/bash"]
