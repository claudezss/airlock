# Deploying the relay

The hosted relay runs on one DigitalOcean Droplet (Ubuntu 24.04, 1 GB):
`airlox-server` behind Caddy, which gets and renews the HTTPS certificate.
Sessions live on the Droplet's disk, so restarts and deploys keep them.

```
GitHub Actions ──ssh (deploy key, forced command)──▶ airlox-deploy <sha>
                                                       │ docker pull ghcr.io/claudezss/airlox-server:sha-<sha>
Internet ──HTTPS──▶ Caddy :443 ──▶ airlox-server :8080 ── volume airlox-data
```

## How a deploy happens

Every push to `main` runs `.github/workflows/deploy.yml`:

1. builds the image from `Dockerfile` (a static `airlox-server` with the web UI
   embedded, about 12 MB, running as a non-root user) and pushes
   `ghcr.io/claudezss/airlox-server:sha-<commit>` and `:latest` (linux/amd64
   only; the package is public);
2. connects as `deploy@<droplet>` and runs `airlox-deploy <commit>`, which:
   - refuses a commit that is not on `main`, and skips one that does not
     contain the commit already deployed (so two quick merges can't end with
     the older one live);
   - pulls the image first, then installs `deploy/docker-compose.yml` and
     `deploy/Caddyfile` from that commit;
   - restarts (the relay shuts down cleanly on SIGTERM) and checks
     `/v1/health` through Caddy on the host, with the real certificate, and
     that the new image is the one running;
   - if that fails, restores the previous image and files, and the workflow
     fails.

Releases publish the same image separately, for linux/amd64 and linux/arm64,
as `ghcr.io/claudezss/airlox-server:<version>` (see
[releasing.md](releasing.md)); the Droplet keeps deploying `sha-<commit>` from
`main`, and `:latest` always means the newest `main`, not the newest release.
Anyone can run a release image with `docker run -p 8080:8080 -v airlox-data:/data
ghcr.io/claudezss/airlox-server:<version>`; it listens on port 8080 and keeps
sessions in `/data`.

Pull requests, and manual runs on other branches, only build the image. To
redeploy `main`, run the workflow by hand from the Actions tab. Deploys never
overlap: the workflow serializes them and the script holds a lock.

The `deploy` user's SSH key is restricted to that one command (no shell, no
port forwarding). That command still deploys whatever compose file is on
`main`, as a user in the `docker` group (root-equivalent on the host), so
`main` (protected by the repository rulesets) is what the host trusts. The
registry token the script receives is valid only for the workflow run.

## Setting up a Droplet

On a fresh Ubuntu 24.04 Droplet with your SSH key:

1. Point the domain at it: `A` records for the domain and `www` (which Caddy
   redirects to the domain). Without a domain, `<ip-with-dashes>.sslip.io`
   resolves to the IP and works with Let's Encrypt.
2. Make a deploy key and run the setup script from a checkout:

   ```bash
   ssh-keygen -t ed25519 -N '' -C 'airlox deploy' -f deploy_key
   scp -r deploy root@<ip>:/root/airlox-deploy
   ssh root@<ip> sh /root/airlox-deploy/setup-droplet.sh <domain> "$(cat deploy_key.pub)"
   ```

   This installs Docker, a firewall (22, 80 and 443 only), 1 GB of swap,
   automatic security updates (rebooting at 04:30 UTC when a kernel update
   needs it; sessions survive), `/usr/local/bin/airlox-deploy`, and the
   restricted `deploy` user. Re-run it to change the domain or to install a
   changed `airlox-deploy` (deploys don't update the script itself); leave out
   the key to keep the current one.
3. In the repository's `production` environment (Settings → Environments),
   which only `main` may deploy to, add:

   | Kind | Name | Value |
   |---|---|---|
   | secret | `DEPLOY_HOST` | the Droplet's IP |
   | secret | `DEPLOY_SSH_KEY` | the contents of `deploy_key` |
   | secret | `DEPLOY_KNOWN_HOSTS` | `ssh-keyscan -t ed25519 <ip>` (check the fingerprint) |
   | variable | `AIRLOX_DOMAIN` | the domain |

   Then delete the local `deploy_key`.
4. Push to `main` (or run the workflow by hand) to start the relay.

## Operating it

Everything lives in `/opt/airlox`: `docker-compose.yml`, `caddy/Caddyfile`,
and `.env` with `AIRLOX_DOMAIN` and the deployed `AIRLOX_IMAGE` and
`AIRLOX_SHA`. As root:

```bash
cd /opt/airlox && docker compose logs -f airlox     # relay logs
cd /opt/airlox && docker compose ps                 # status
```

Relay limits (session size, TTLs, rate limits) are the `AIRLOX_*` variables
in `crates/airlox-server/src/config.rs`; set them under `environment:` in
`deploy/docker-compose.yml`.

To use your own domain, add a DNS `A` record for it, re-run
`setup-droplet.sh <domain> ...`, update the `AIRLOX_DOMAIN` variable, and
redeploy.

**Rolling back.** From this release on, a relay skips log records it does
not know, so rolling back to it from a newer build keeps sessions (their
newer features just stop applying). Builds before it purge a session whose
log they cannot read, so rolling back past it, which `airlox-deploy` does by
itself when a new build fails its health check, ends every session that used
re-seeding or revocation. Roll forward with a fix instead where you can.
