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

It needs relay and clients **0.1.3 or later**: older ones reject sessions
that use `--insecure-http-host` and do not report the relay's item limit.
The image is `linux/amd64` only.

```bash
kubectl create namespace airlox
kubectl -n airlox apply -f deploy/kubernetes/airlox-relay.yaml
kubectl -n airlox rollout status deploy/airlox-relay
```

Every pod in the namespace can reach the relay, so give it a namespace of
its own and put only its clients there (or narrow the policy's `from` to
their labels). The relay's limits are environment variables
(`airlox-server --help` lists them, e.g. `AIRLOX_MAX_ITEM_BYTES`,
`AIRLOX_MAX_SESSION_BYTES`, `AIRLOX_MAX_TTL`); add them to the container's
`env`.

## Where the commands run

Invites carry the relay URL the session was created with, so every machine
that uses a session must reach the relay at that URL. Pick one:

- **Everything in the cluster.** Run the owner's commands (`session
  create`, `session code`, `runner approve`) from a pod in the namespace,
  e.g. `kubectl -n airlox exec -it deploy/<your-tools-pod> -- sh`, and
  create the session with the in-cluster URL and `--insecure-http-host`
  (below).
- **Owner outside, over a port-forward.** `kubectl -n airlox port-forward
  svc/airlox-relay 8080` and create the session with `--relay
  http://localhost:8080`; plain http to this machine needs no opt-in. In-
  cluster runners then reach the relay with `runner join --relay
  http://airlox-relay.airlox.svc:8080`. That still needs the session to name
  the host with `--insecure-http-host airlox-relay.airlox.svc`, since the
  runner checks the URL it actually uses against the manifest.
- **TLS.** Put the relay behind an Ingress or a mesh with a certificate
  every client trusts, and use `https://` everywhere; nothing below applies.

## Plain http inside the cluster

Clients refuse `http://` to anything but this machine. The owner can allow
it for one host when creating the session; the host is then part of the
signed manifest, and every participant checks it before sending a token:

```bash
airlox session create --relay http://airlox-relay.airlox.svc:8080 \
    --insecure-http-host airlox-relay.airlox.svc --profile host-runner
```

In Python: `Session.create("http://airlox-relay.airlox.svc:8080",
insecure_http_host="airlox-relay.airlox.svc", ...)`.

- Spell the host the same way everywhere: `airlox-relay`,
  `airlox-relay.airlox` and `airlox-relay.airlox.svc.cluster.local` are
  different hosts to the check. Pick the form every client's DNS resolves
  (`<service>.<namespace>.svc` works from any namespace). `create` notes it
  when `--relay` names a different host.
- Messages, files, jobs and results stay end-to-end encrypted: no one on the
  network can read or forge them. What crosses the network in the clear is
  each participant's bearer token, and anyone who sees one can use it toward
  the relay as that participant:
  - the **owner's** token can close and purge the session, revoke roles, and
    approve or reject runners;
  - a **runner's** token can claim jobs and never answer them;
  - any token can fetch ciphertext, acknowledge items and leave.

  So use plain http only on a network you trust, and prefer to run the
  owner over https or a port-forward even when runners use plain http.
  Pods with `CAP_NET_RAW` (the default for most runtimes) can sniff their
  node's traffic; drop it everywhere in the namespace.
- Transfer codes are refused over plain http to another machine unless you
  pass `--allow-insecure-http`: the code and the invite it carries would
  cross the network in the clear. In a cluster, a Secret (below) is the
  better channel.

## A runner in the cluster

Give the runner its invite through a Secret, mounted as a file:

```bash
AIRLOX_INVITE="$(cat owner.txt)" airlox session invites --json \
  | jq -r .invites.runner > runner.txt
kubectl -n airlox create secret generic airlox-runner-invite --from-file=invite=runner.txt
rm runner.txt
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: airlox-runner}
spec:
  replicas: 1
  selector: {matchLabels: {app.kubernetes.io/name: airlox-runner}}
  template:
    metadata: {labels: {app.kubernetes.io/name: airlox-runner}}
    spec:
      automountServiceAccountToken: false
      enableServiceLinks: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: runner
          image: <an image with airlox and your Python>
          args: [runner, join, --invite-file, /invite/invite, --name, runner-01, --cache-dir, /cache,
                 --sandbox, process, --python, /venv/bin/python, --accept-network-gap]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: invite, mountPath: /invite, readOnly: true}
            - {name: cache, mountPath: /cache}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: invite
          secret: {secretName: airlox-runner-invite, defaultMode: 0400}
        - {name: cache, emptyDir: {}}
        - {name: tmp, emptyDir: {}}
```

If the session was created with another relay URL (the port-forward case
above), add `--relay http://airlox-relay.airlox.svc:8080`.

With `--sandbox process`, jobs run as the runner's own user in the runner's
pod: they can read what the runner can, its invite and its cache included,
and with those decrypt the session and act as the runner. The pod is the
boundary, so:

- run one runner per pod, for one session, and approve runners only from
  senders you would trust with that session;
- keep the cache (`--cache-dir`) on a volume of the pod's own, not one
  shared with anything else;
- give runner pods their own NetworkPolicy that allows egress only to the
  relay (and to what jobs need, if the session allows network);
- or use `--sandbox local` where the nodes allow unprivileged user
  namespaces (it needs a seccomp profile that permits them): jobs then run
  in namespaces with Landlock and cannot read the runner's files.

A one-time code works too (`airlox session code runner`, then `runner join
--code ... --relay http://airlox-relay.airlox.svc:8080
--allow-insecure-http`), at the cost of sending the invite across the
cluster network in the clear.
