# Running the relay in Kubernetes

[`deploy/kubernetes/airlox-relay.yaml`](../deploy/kubernetes/airlox-relay.yaml)
runs a relay inside a cluster, for runners and agents that live there too:

- one replica, replaced rather than rolled (`Recreate`), since a relay holds
  its sessions itself;
- the image's own user (UID and GID 65532), a read-only root filesystem, no
  capabilities, no privilege escalation, the runtime's default seccomp
  profile and no service-account token;
- an `emptyDir` at `/data` (4 GiB) for ciphertext in transit. It outlives a
  container restart, which reloads the sessions, but not the pod; use a
  PersistentVolumeClaim to keep sessions across rescheduling;
- startup, readiness and liveness probes on `GET /v1/health`;
- a ClusterIP Service `airlox-relay` on port 8080;
- a NetworkPolicy that admits only pods in the same namespace and allows no
  egress: the relay never makes outbound connections.

```bash
kubectl create namespace airlox
kubectl -n airlox apply -f deploy/kubernetes/airlox-relay.yaml
kubectl -n airlox rollout status deploy/airlox-relay
```

The relay's limits are environment variables (`airlox-server --help` lists
them, e.g. `AIRLOX_MAX_ITEM_BYTES`, `AIRLOX_MAX_SESSION_BYTES`,
`AIRLOX_MAX_TTL`); add them to the container's `env`. The image is
`linux/amd64` only.

## Plain http inside the cluster

Clients refuse `http://` to anything but this machine, so by default a pod
reaching `http://airlox-relay.airlox.svc:8080` is turned away. The owner can
allow it for one host when creating the session; the host is then part of
the signed manifest, and every participant checks it before sending a token:

```bash
airlox session create --relay http://airlox-relay.airlox.svc:8080 \
    --insecure-http-host airlox-relay.airlox.svc --profile host-runner
```

In Python: `Session.create("http://airlox-relay.airlox.svc:8080",
insecure_http_host="airlox-relay.airlox.svc", ...)`.

- Spell the host the same way everywhere: invites carry the relay URL given
  at create, and `airlox-relay`, `airlox-relay.airlox` and
  `airlox-relay.airlox.svc.cluster.local` are different hosts to the check.
  Pick the form every client's DNS resolves (`<service>.<namespace>.svc`
  works from any namespace).
- Messages, files, jobs and results stay end-to-end encrypted. What crosses
  the network in the clear is each participant's bearer token, which lets
  someone on that network act as that participant toward the relay (fetch
  ciphertext, ack, leave) though not read or sign anything, and transfer
  codes, whose sealed invite an eavesdropper could open by trying all 65,536
  word pairs. Use it on a network you
  trust, and prefer TLS (an Ingress or a mesh) for anything that crosses
  clusters.
- Older clients (0.1.2 and before) and older relays reject a manifest with
  `insecure_http_host`.

Machines outside the cluster can still use `kubectl port-forward`: plain
http to `localhost` needs no opt-in, and `airlox runner join --relay
http://localhost:8080` sends a runner's requests there while it keeps the
invite's relay as its identity.

## A runner in the cluster

Hand the runner its invite with a one-time code instead of a file:

```bash
AIRLOX_INVITE="$(cat owner.txt)" airlox session code runner
# 7-guitar-orbit
```

and in the runner's pod:

```bash
airlox runner join --code 7-guitar-orbit --relay http://airlox-relay.airlox.svc:8080 \
    --name runner-01 --sandbox process --accept-network-gap
```

The runner saves the invite the code carried into its cache, so restarts
use `--invite-file` from there; give the cache a volume that survives
restarts.
