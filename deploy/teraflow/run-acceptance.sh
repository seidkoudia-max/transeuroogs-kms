#!/usr/bin/env bash
# Disruptive to this dedicated lab only; preserves all durable volumes.
set -euo pipefail
[[ $(hostname) == lima-transeuroogs-tfs ]] || exit 1
root=/opt/transeuroogs
kube() { sudo microk8s kubectl "$@"; }
check() { kube -n tfs exec -i deployment/lab-client -- python - "$@" < "$root/check-cluster.py"; }
services=(contextservice deviceservice pathcompservice qkd-appservice serviceservice nbiservice webuiservice)
stopped=false
restore() {
    kube -n tfs scale deployment "${services[@]}" --replicas=1
    stopped=false
    for service in "${services[@]}"; do
        kube -n tfs rollout status "deployment/$service" --timeout=120s
    done
    sudo systemctl restart transeuroogs-webui
}
cleanup() {
    result=$?
    trap - EXIT
    if $stopped; then restore || result=1; fi
    exit "$result"
}
trap cleanup EXIT

# Do not replace an unresolved operation or modify another lab's state.
python3 "$root/deploy-lab.py" probe
kube -n tfs exec deployment/lab-client -- test ! -e /state/private/pending-policy.json
check onboard --nbi
check isolation
check resume --nbi
check lost-start
kube -n transeuroogs-kms rollout restart deployment/kms
kube -n tfs rollout restart deployment/contextservice deployment/deviceservice deployment/lab-client
kube -n transeuroogs-kms rollout status deployment/kms --timeout=120s
for service in contextservice deviceservice lab-client; do
    kube -n tfs rollout status "deployment/$service" --timeout=120s
done
check paused
check discovery
check lost-recover
check resume --nbi
check delivery
stopped=true
kube -n tfs scale deployment "${services[@]}" --replicas=0
kube -n tfs wait --for=delete pod -l 'app in (contextservice,deviceservice,pathcompservice,qkd-appservice,serviceservice,nbiservice,webuiservice)' --timeout=120s
check delivery
restore
check discovery
check history
printf '%s\n' 'PASS: controller restart, durable outbox replay, KMS restart and delivery during complete controller outage'
