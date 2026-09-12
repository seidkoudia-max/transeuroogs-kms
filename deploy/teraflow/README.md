# TeraFlow v7 laboratory bundle

The local KMS and driver-contract lab runs now with `make sdn-demo`. The full
controller cluster remains pending. On 2026-09-12 the development Mac has arm64,
24 GB RAM and 12 CPUs. Colima 0.10.3, Docker CLI 29.8.0, Kubernetes CLI 1.37.0 and
Helm 4.3.0 were installed; no VM, Docker daemon or Kubernetes cluster was started.
Available storage fell below 7 GiB during work. The upstream guide's example VM
uses 4 CPUs, 8 GB RAM and a 60 GB disk. Provide a larger local/external volume
before downloading controller images or allocating the VM. No user data was
removed to make space.

To keep a synthetic managed KMS running after the acceptance test:

```sh
make build pki
go run ./src/cmd/kms-metadata keygen --private .local/sdn-sign.key.pem --public .local/sdn-sign.pub.pem
.local/bin/kms --config deploy/config/sdn-local.json --synthetic-keys 32
```

Generate the signing credential only once; the tool refuses to overwrite it.
Restart with `--synthetic-keys 0` to recover the existing state. The example has
fixed synthetic node/application UUIDs and a dedicated `controller-sae` test
identity. It is for this isolated lab, not a site certificate/deployment profile.

Use the [official deployment guide](https://tfs.etsi.org/documentation/latest/deployment_guide/)
for Ubuntu 22.04/24.04 and MicroK8s. Start with a dedicated test VM/cluster and
namespace. Colima's default k3s cluster is not a validated replacement for that
guide. Several v7 Dockerfiles fetch `linux-amd64` health probes explicitly;
native arm64 controller operation has not been verified. Use an amd64 Ubuntu
VM with suitable emulation, or explicitly port and test the images for arm64.
Do not assume the installed Mac CLIs prove either deployment works.

## Source and image preparation

```sh
git clone --branch v7.0.0 --depth 1 https://labs.etsi.org/rep/tfs/controller.git /path/to/clean/tfs-v7
python3 deploy/teraflow/prepare.py /path/to/clean/tfs-v7
git -C /path/to/clean/tfs-v7 diff
```

`prepare.py` verifies commit `fb8707871eba26806cac7ac373c70b2bb5bd26fc`, requires
a clean checkout and copies this project's driver, client and reconciler into
the Device source. It changes one import to an explicit profile selector.
Devices with `profile=transeuroogs-allocation-v1` use this driver; unspecified
profiles retain upstream behavior. An unknown explicit profile is rejected.
The preparation step was exercised against the pinned upstream checkout locally.

Build the Device image using the upstream build/deployment procedure from that
prepared checkout. Preserve its provenance and record the resulting digest;
this bundle does not substitute an invented image tag or digest. Upstream build
dependencies and other component images require their own reproducibility review.
Core TFS components include context, device, pathcomp, service, nbi and webui;
the upstream QKD lab adds qkd_app. The TransEuroOGS policy reconciler requires
the Device driver, not the upstream service handler's physical link provisioning.

## Cluster configuration after capacity is available

1. Deploy the isolated upstream lab and verify its own readiness. Bind UI/NBI
   access to the test environment; supply local secrets outside Git. Do not run
   upstream database-reset switches against an existing environment.
2. Create a namespace-scoped `kms-management-mtls` Secret from synthetic lab CA,
   controller certificate and private key files. No certificate/key bytes are
   provided in this repository. Mount it read-only using `device-patch.yaml`.
3. Replace that patch's image placeholder with the verified Device image digest.
   Apply it only to `deviceservice` in the explicitly chosen lab namespace.
4. Register a QKD node with its reachable TLS address/port and the settings in
   `device-settings.example.json`. Match the KMS's URI-SAN and application/node
   UUIDs. Grant the controller only that national node's required associations.
5. Discover `__node__` and `__apps__`, poll `__transeuroogs_state__`, and send a
   complete command as a TFS custom config rule at `/transeuroogs/allocation`.
   Retain `command_id` and `expected_revision` across retries. Integrate
   `Reconciler` into the policy process with one persistent outbox per node.

The YAML file is a **patch template**, not a runnable standalone Deployment.
No live cluster mutation has been performed and no kubeconfig has been changed.
The existing upstream QKD service handler creates physical/virtual links that
this agent does not expose; end-to-end TFS service provisioning needs further
integration and actual device/topology adapters. Never declare unsupported
SetConfig/DeleteConfig/Subscribe calls successful to make that workflow pass.

## Deployment acceptance still to run

- Device-service discovery and policy actuation through TFS NBI/gRPC.
- Namespace isolation and controller/app/peer identity rejection in the cluster.
- Controller restart and lost reply with persisted policy outbox.
- KMS restart and uninterrupted delivery under the last accepted local rule.
- Two-domain partial failure reporting without overwriting another controller's
  revision, plus metadata-authorised route changes while relay sends are pending.
- Real topology/telemetry adapters and agreed 021/023 profile tests as those
  models become accessible; independent 015 conformance assessment.

See [the tested software profile](../../docs/SDN_ALLOCATION.md). Installing
TeraFlow itself does not establish compliance with 015, 021 or 023.
