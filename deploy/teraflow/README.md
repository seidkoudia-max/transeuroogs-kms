# TeraFlow v7 local laboratory

A real TeraFlow controller is deployed locally on the Apple Silicon development
Mac, using an isolated Ubuntu VM and MicroK8s. The controller manages the
synthetic LU KMS through the opt-in TransEuroOGS driver. The WebUI is available at
[http://127.0.0.1:8080/](http://127.0.0.1:8080/); choose
**Context(admin):Topology(admin)**, then **Device** to see `LU-KMS`.
The HTTP NBI remains inside the cluster.

This is a bounded allocation lab. It does not provision physical QKD links or
establish ETSI 015/021/023 conformance. See [SDN allocation](../../docs/SDN_ALLOCATION.md)
and [the acceptance record](ACCEPTANCE.md) for the tested boundary.

## Start, inspect and stop the existing lab

Run on the Mac:

```sh
limactl start transeuroogs-tfs
limactl shell --workdir=/tmp transeuroogs-tfs sudo microk8s kubectl get pods -A
```

Allow the database, DNS and controller services to become ready after boot.
The WebUI forwarder starts automatically inside the VM. If its connection is
stale after replacing the WebUI pod:

```sh
limactl shell --workdir=/tmp transeuroogs-tfs sudo systemctl restart transeuroogs-webui
```

Stop the VM to release its RAM and CPU allocation; this preserves its disk,
controller database, KMS state and policy outbox:

```sh
limactl stop transeuroogs-tfs
```

No host Docker context or kubeconfig is changed. The VM shares no host home or
repository mounts. Only the WebUI is automatically forwarded, on loopback;
Lima also maintains its own loopback SSH transport. KMS ingress permits only the
Device service and lab-client pods in `tfs`, and still requires mTLS. The
lab-client holds separate synthetic application, controller and investigator
credentials solely to run acceptance checks.

## Runtime and storage

| Component | Local profile |
| --- | --- |
| Lima | 2.2.0, Apple VZ and Rosetta binfmt |
| Ubuntu | 24.04.4 LTS, arm64 |
| VM allocation | 6 CPUs, 10 GiB RAM, 60 GiB sparse disk |
| MicroK8s | 1.29/stable; observed 1.29.15; DNS, storage, registry, RBAC |
| TeraFlow | v7.0.0, commit `fb8707871eba26806cac7ac373c70b2bb5bd26fc` |
| Controller containers | linux/amd64 via Rosetta; original upstream Dockerfiles |
| KMS | Native linux/arm64 Go binary, synthetic keys only |
| Controller dependencies | CockroachDB 22.2.19, NATS 2.10, Apache Kafka 3.9.1 |

Context, Device, Service, PathComp frontend/backend, QKD App, NBI and WebUI run
with one replica. Kafka is required even for this small deployment because NBI
creates topics during startup. Grafana, full monitoring, autoscaling, ingress,
HA and physical device adapters are outside this lab. Some upstream UI links
therefore lead to features without a deployed backend.

The upstream [deployment guide](https://tfs.etsi.org/documentation/latest/deployment_guide/)
uses Ubuntu/MicroK8s. Rosetta is a local adaptation, not a native arm64 port or an
upstream-supported production claim. Kafka's single-broker KRaft configuration
uses the [official Apache image example](https://github.com/apache/kafka/blob/3.9.1/docker/examples/docker-compose-files/cluster/combined/plaintext/docker-compose.yml).

Controller images are built into the VM registry and deployments select the
verified amd64 child digest explicitly. KMS/NATS/Kafka use arm64 manifests.
Actual digests are recorded in `/opt/transeuroogs/lab-state/*-images.json` and
`kms-image.json` inside the VM. Source pinning does not freeze upstream pip/apt
or mutable base-image dependencies; record each build's resolved image digests.

The VM used approximately 24 GiB after deployment. The Mac must also accommodate
build cache and growing sparse-disk blocks; check **both** host and guest space:

```sh
df -h /
limactl shell --workdir=/tmp transeuroogs-tfs df -h /
limactl shell --workdir=/tmp transeuroogs-tfs sudo docker system df
```

Start a fresh build with at least 35–40 GiB available on the host. The build
helper stops before an image if guest usage exceeds 22 GiB; it cannot enforce
host free space. If necessary, prune only this lab's unused build cache, then
trim the guest. Do not prune volumes or the registry:

```sh
limactl shell --workdir=/tmp transeuroogs-tfs sudo docker builder prune --all --force --keep-storage=1GB
limactl shell --workdir=/tmp transeuroogs-tfs sudo fstrim -av
```

PVC sizes under MicroK8s hostpath storage are requests, not hard disk quotas.
Kafka retention is bounded for the lab, but controller state and the image
registry still require monitoring. The database uses encrypted transport and a
random local password; its lab `sslmode=require` does not validate a pinned DB
CA. This is not the operational KMS/PostgreSQL deployment profile.

## Reproduce in a fresh dedicated VM

These instructions are for a new lab. For the existing VM, use start/stop above;
do not rerun initialization against replacement state or delete PVCs to fix an
error. Host prerequisites are Lima 2.2+, Rosetta and Go 1.27.1. The provided
scripts reject a different VM hostname and unowned namespaces.

From this repository on the Mac:

```sh
limactl create --name=transeuroogs-tfs deploy/teraflow/lima.yaml
limactl start transeuroogs-tfs
limactl copy deploy/teraflow/bootstrap-ubuntu.sh transeuroogs-tfs:/tmp/bootstrap-ubuntu.sh
limactl shell --workdir=/tmp transeuroogs-tfs sudo bash /tmp/bootstrap-ubuntu.sh
limactl shell --workdir=/tmp transeuroogs-tfs sudo install -d -o lima -m 0755 /opt/transeuroogs
mkdir -p .local/teraflow/bin
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o .local/teraflow/bin/ ./src/cmd/kms ./src/cmd/kms-metadata ./src/cmd/test-pki
tar -czf .local/teraflow/source.tar.gz AGENTS.md Makefile README.md go.mod go.sum deploy docs src tests emulator
limactl copy .local/teraflow/source.tar.gz transeuroogs-tfs:/opt/transeuroogs/source.tar.gz
limactl shell --workdir=/tmp transeuroogs-tfs mkdir -p /opt/transeuroogs/kms /opt/transeuroogs/bin
limactl shell --workdir=/tmp transeuroogs-tfs tar -xzf /opt/transeuroogs/source.tar.gz -C /opt/transeuroogs/kms
limactl copy .local/teraflow/bin/kms transeuroogs-tfs:/opt/transeuroogs/bin/kms
limactl copy .local/teraflow/bin/kms-metadata transeuroogs-tfs:/opt/transeuroogs/bin/kms-metadata
limactl copy .local/teraflow/bin/test-pki transeuroogs-tfs:/opt/transeuroogs/bin/test-pki
limactl shell --workdir=/tmp transeuroogs-tfs
```

Run the remaining preparation **inside Linux**. A default case-insensitive macOS
checkout collides on some upstream filenames and must not be used for building
TeraFlow:

```sh
cd /opt/transeuroogs
git clone --branch v7.0.0 --depth 1 https://labs.etsi.org/rep/tfs/controller.git controller
python3 kms/deploy/teraflow/prepare.py controller
cp kms/deploy/teraflow/deploy-lab.py .
cp kms/deploy/teraflow/check-cluster.py .
cp kms/deploy/teraflow/run-acceptance.sh .
mkdir -p kms-image logs
cp bin/kms kms-image/kms
cp kms/deploy/teraflow/start-kms.sh kms-image/
cp kms/deploy/teraflow/kms-lab.Dockerfile kms-image/Dockerfile
sudo docker build --platform=linux/arm64 -t localhost:32000/transeuroogs/kms:lab kms-image
sudo docker push localhost:32000/transeuroogs/kms:lab
python3 deploy-lab.py prerequisites
sudo microk8s kubectl -n crdb rollout status statefulset/cockroachdb --timeout=300s
sudo microk8s kubectl -n kafka rollout status statefulset/kafka --timeout=300s
python3 deploy-lab.py kms
bash kms/deploy/teraflow/build-images.sh
python3 deploy-lab.py controller
python3 deploy-lab.py client
sudo install -m 0644 kms/deploy/teraflow/transeuroogs-webui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now transeuroogs-webui
sudo microk8s kubectl -n tfs get pods
```

`prepare.py` requires the clean pinned checkout and installs the explicit profile
selector. `profile=transeuroogs-allocation-v1` selects our driver; unspecified
profiles retain upstream behavior, and unknown explicit profiles are rejected.
Prepared source must be reviewed before refreshing it. Unsupported link
provisioning and subscriptions remain errors.

## Acceptance and recovery

Inside the VM, after all pods are ready:

```sh
cd /opt/transeuroogs
bash run-acceptance.sh
```

This is a deliberately disruptive **synthetic lab** test. It checks namespace
and mTLS identity isolation, real HTTP NBI onboarding, a lost reply after a real
policy commit, persistent-outbox recovery across controller/client/KMS pod
restarts, matching single-use delivery and delivery with every TFS deployment
scaled to zero. It restores the controller replicas on exit and compares signed
policy-event counts with committed revisions. It consumes four synthetic keys.
It does not constitute independent signature/conformance certification.

Inspect state without consuming keys:

```sh
sudo microk8s kubectl -n tfs exec -i deployment/lab-client -- python - state < check-cluster.py
```

If a test stops with an unresolved outbox, recover the exact pending command
before selecting a different intent:

```sh
sudo microk8s kubectl -n tfs exec -i deployment/lab-client -- python - lost-recover < check-cluster.py
sudo microk8s kubectl -n tfs exec -i deployment/lab-client -- python - resume --nbi < check-cluster.py
```

The KMS state, controller database and its TLS certificates, Kafka data, and
policy outbox have separate persistent volumes. The signing credential and test
PKI live in private `/opt/transeuroogs/lab-state`. KMS private storage remains
0700 with regular 0600 files; an init container copies its projected signing
Secret into private memory rather than weakening the KMS's symlink checks.
Startup seeds 64 synthetic keys only for new state; restarts use zero new keys.

Test certificates expire after 24 hours. The initial synthetic keys expire after
24 hours and allocation freshness limits are 12 hours. This bounded lab will
therefore stop delivering without approved replenishment; restarting must not
reseed or erase consumed-key tombstones. Continuous supply from a synthetic or
IDQ provider is a separate adapter/deployment step. For another test-credential
window, generate fresh lab PKI with `bin/test-pki --out=lab-state/pki`, run
`python3 deploy-lab.py kms`, and restart the KMS, Device and lab-client deployments
together. Keep signing credentials, bootstrap policy and all state volumes.
Renewing certificates does not renew keys or change expiry.

The reusable `Reconciler` supplies one-node policy logic and a durable outbox.
In this lab the acceptance adapter observes KMS metadata over mTLS and sends
writes through TeraFlow NBI/Device. No continuous multi-country policy service,
controller HA, real telemetry adapter, physical-path provisioning, SES/IDQ
interoperability or 021/023 wire profile is claimed. Those remain subsequent
milestones.
