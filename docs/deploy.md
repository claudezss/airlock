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
   `ghcr.io/claudezss/airlox-server:sha-<commit>` and `:latest`;
2. connects as `deploy@<droplet>` and runs `airlox-deploy <commit>`. That
   fetches `deploy/docker-compose.yml` and `deploy/Caddyfile` at the same
   commit, pulls the image, restarts, and checks
   `https://$AIRLOX_DOMAIN/v1/health`. If the new version is not healthy it
   puts the previous image back and the workflow fails.

Pull requests only build the image. To redeploy `main`, run the workflow by
hand from the Actions tab. Deploys never run concurrently.

The `deploy` user's SSH key is restricted to that one command (no shell, no
port forwarding), and the registry token it receives is valid only for the
duration of the workflow run.

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
   automatic security updates, `/usr/local/bin/airlox-deploy`, and the
   restricted `deploy` user. It is safe to re-run (for example to change the
   domain).
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

Everything lives in `/opt/airlox` (`docker-compose.yml`, `Caddyfile`, and
`.env` with `AIRLOX_DOMAIN` and the current `AIRLOX_IMAGE`). As root:

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
