FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash zsh git ca-certificates curl sudo xz-utils gosu \
 && rm -rf /var/lib/apt/lists/*

# Install Nix files, but no init integration.
RUN curl -sSfL https://artifacts.nixos.org/nix-installer | \
    sh -s -- install linux \
      --init none \
      --extra-conf "sandbox = false" \
      --extra-conf "experimental-features = nix-command flakes" \
      --extra-conf "allowed-users = *" \
      --extra-conf "trusted-users = root vscode" \
      --no-confirm

RUN groupadd -r nix-users
RUN useradd -m -s /bin/bash vscode \
 && usermod -aG nix-users vscode \
 && echo 'vscode ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-vscode \
 && echo 'Defaults secure_path="/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' >> /etc/sudoers.d/90-vscode \
 && chmod 0440 /etc/sudoers.d/90-vscode

ENV PATH=/nix/var/nix/profiles/default/bin:$PATH

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/docker-entrypoint.sh" ]
CMD [ "sleep", "infinity" ]
