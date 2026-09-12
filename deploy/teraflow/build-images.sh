#!/usr/bin/env bash
# Build only inside the isolated lab; retain upstream Dockerfiles and provenance.
set -euo pipefail
[[ $(hostname) == lima-transeuroogs-tfs ]] || exit 1
cd /opt/transeuroogs/controller
revision=fb8707871eba26806cac7ac373c70b2bb5bd26fc
[[ $(git rev-parse HEAD) == "$revision" ]] || exit 1
mkdir -p /opt/transeuroogs/logs
if [[ $# == 0 ]]; then
    set -- context device pathcomp-frontend pathcomp-backend qkd_app service nbi webui
fi
for component in "$@"; do
    case "$component" in
        context|device|qkd_app|service|nbi|webui) dockerfile="src/$component/Dockerfile" ;;
        pathcomp-frontend) dockerfile=src/pathcomp/frontend/Dockerfile ;;
        pathcomp-backend) dockerfile=src/pathcomp/backend/Dockerfile ;;
        *) echo "Unknown component: $component" >&2; exit 1 ;;
    esac
    # Keep this constrained VM below 22 GiB used; also monitor host space.
    used_kib=$(df -Pk / | awk 'NR == 2 {print $3}')
    if (( used_kib > 22 * 1024 * 1024 )); then
        echo 'Lab disk budget reached; inspect build cache before proceeding.' >&2
        exit 1
    fi
    image="localhost:32000/tfs/$component:transeuroogs-v7"
    log="/opt/transeuroogs/logs/build-$component.log"
    echo "Building $component"
    if ! sudo docker buildx build --platform=linux/amd64 --load --progress=plain \
        --label "org.opencontainers.image.revision=$revision" \
        -t "$image" -f "$dockerfile" . > "$log" 2>&1; then
        tail -n 40 "$log"
        exit 1
    fi
    sudo docker push "$image" > "/opt/transeuroogs/logs/push-$component.log" 2>&1
    sudo docker image inspect "$image" --format '{{json .RepoDigests}}'
done
