#!/usr/bin/env bash
# Run as root only inside the dedicated Lima VM, never on a shared server.
set -euo pipefail

if [[ $(id -u) != 0 || $(hostname) != lima-transeuroogs-tfs ]]; then
    echo 'This script requires root inside lima-transeuroogs-tfs.' >&2
    exit 1
fi
if [[ ! -r /proc/sys/fs/binfmt_misc/rosetta ]]; then
    echo 'Rosetta binfmt must be available before provisioning this lab.' >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl docker.io docker-buildx git jq \
    openssl python3-yaml rsync snapd
install -d -m 0755 /etc/docker
python3 - <<'PY'
import json
from pathlib import Path
path = Path('/etc/docker/daemon.json')
config = json.loads(path.read_text()) if path.exists() else {}
config['insecure-registries'] = sorted(set(config.get('insecure-registries', []) + ['localhost:32000']))
config['log-driver'] = 'local'
config['log-opts'] = {'max-size': '10m', 'max-file': '3'}
config['builder'] = {'gc': {'enabled': True, 'defaultKeepStorage': '3GB'}}
config['ip-forward-no-drop'] = True
path.write_text(json.dumps(config, indent=2) + '\n')
PY
systemctl enable --now docker
systemctl restart docker
# Docker may otherwise block routed pod traffic inside this isolated VM.
iptables -P FORWARD ACCEPT
if ! snap list microk8s >/dev/null 2>&1; then
    snap install microk8s --classic --channel=1.29/stable
fi
usermod -aG docker,microk8s lima
timeout 600 microk8s status --wait-ready
for addon in dns hostpath-storage registry rbac; do
    microk8s enable "$addon"
done
microk8s kubectl wait --for=condition=Ready node --all --timeout=300s
docker run --rm --platform=linux/amd64 alpine:3.22 uname -m
microk8s kubectl get nodes -o wide
