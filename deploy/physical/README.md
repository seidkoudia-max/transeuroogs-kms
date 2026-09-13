# Physical emulation alongside TeraFlow

This is the **JFK–Windhof–Helmos–HellasQCI** laboratory. The fibre lengths are
25 km and 30 km. EAGLE-1 supplies the simulated middle segment's paired keys
after sequential OGS contacts and offline processing. See
[physical models and limits](../../docs/PHYSICAL_EMULATION.md).

The dedicated Lima/MicroK8s lab hosts one `physical-lab` pod in the new
`transeuroogs-physical` namespace. It runs four independent Go KMS processes and
three synthetic 014 source processes. Each KMS owns its own encrypted journal,
pool, metadata signer and mTLS identity. The emulation uses a shared test CA;
sharing a pod does not implement production host/trust-domain isolation.

The existing TeraFlow Device image supplies the pinned controller clients and
driver. A small derivative adds Linux/amd64 Go binaries, public emulation code
and a precomputed QNETSIM report. It adds no numerical dependencies to the VM.
The numerical simulator and the user's hash-pinned QNETSIM dependency run on
the development host. Scheduled telemetry playback and real runtime key-buffer
observations remain explicitly distinct.

The installer adds a scoped test credential mount to Device, onboards the four
KMSs and their six interfaces, and publishes three links and a reference QKD
service into native Context/WebUI. Six link-create and four application-create
commands pass through NBI/Device and require proof of the exact KMS commit.
Twelve physical adapter reports are verified through fresh Device RPCs.
After delivering eight matching application keys, the pod remains running
with 24 keys at each endpoint. Its observer refreshes the native service and
KMS inventory records every 30 seconds. ServiceService's native provisioning
handler is not implemented by this emulation.

## Build and install

Run the local physical tests/demo first, then cross-compile and package:

```sh
mkdir -p .local/physical/linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o .local/physical/linux/ ./src/cmd/kms ./src/cmd/physical-source \
  ./src/cmd/test-pki ./src/cmd/kms-metadata
python3 deploy/physical/package.py .local/physical/release.tar.gz
```

Copy and safely extract the public archive into a new directory under
`/opt/transeuroogs/` on `transeuroogs-tfs`. Run `deploy/physical/install.py` on
that VM with `--source` pointing to the extracted directory and `--base-image`
set to the **digest of the currently installed TransEuroOGS Device image**.
The installer validates every public source/binary hash before mutation. It
builds and pins the amd64 child manifest so the arm64 Lima host can execute it
through its existing Rosetta configuration.

Only the owned `tfs` lab and the new physical namespace are accepted. A 128 MiB
PVC retains every run's encrypted state and spent permits. Private test
credentials are generated on the VM and installed as Secrets; they never enter
the public package. The physical pod uses an unprivileged UID, read-only image files,
no service-account token and restricted networking. The source APIs remain
loopback-only inside the emulation pod. The controller sees only the four KMS
management/API ports, using distinct pinned identities.

Reinstallation requires `--new-run` and retains previous run directories.
This is an explicit new synthetic experiment, not provider material recovery.
A stopped source cannot replay the same permit in its original run. The pod
does not restart automatically or silently reseed lost source material.

Installation records and controller-template backups are under
`/opt/transeuroogs/physical-state/<run>/`; the latest run is also named in
`/opt/transeuroogs/physical-state/latest.json`. Runtime public evidence is
`/state/<run>/native-acceptance.json` inside the pod; captured 015 data is
`/state/<run>/sdn-node.json`. Neither contains key values. Read current status:

```sh
limactl shell --workdir=/tmp transeuroogs-tfs \
  sudo microk8s kubectl -n transeuroogs-physical get pod physical-lab
```

Test certificates expire after 24 hours. Source/runtime test keys have their
configured finite lifetimes (the disposable source uses one hour). The observer
can therefore report an empty/expired service later; this is not a renewable
SES connection. For further experiments, start an explicit new lab session.

## Acceptance on 2026-09-13

The initial native run passed with four KMS processes, three independently
keyed hops, 12 fresh controller telemetry observations, eight matching
application keys and 24 remaining eligible keys at both JFK and HellasQCI.
The local process acceptance additionally delivered all 32 keys, retained
incident holds across restart, rejected delivery replay and proved buffered
delivery after all three QKD sources stopped. The numerical tests cover
clouds, fibre outage scope, loss/phase/noise, insufficient blocks, expiry,
capacity conservation and no simultaneous OGS illumination.

This is a laboratory integration result, not independent ETSI conformance,
SES validation, an accepted finite-key security proof or operational deployment.
