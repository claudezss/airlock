#!/bin/sh
# One-time (and re-runnable) setup of an Ubuntu 24.04 Droplet for the relay.
# Run as root from a checkout:
#
#   scp -r deploy root@host:/root/airlox-deploy
#   ssh root@host sh /root/airlox-deploy/setup-droplet.sh <domain> "<deploy public key>"
#
# Installs Docker, a firewall (22, 80, 443 only), swap, automatic security
# updates, the airlox-deploy command, and a `deploy` user whose SSH key can only
# run that command. The first deploy (from GitHub Actions) starts the relay.
set -eu

domain=${1:?usage: setup-droplet.sh <domain> "<deploy public key>"}
pubkey=${2:?usage: setup-droplet.sh <domain> "<deploy public key>"}
here=$(cd "$(dirname "$0")" && pwd)
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -yq ca-certificates curl ufw unattended-upgrades
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

# Security updates install themselves (Ubuntu's default, made explicit).
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
  > /etc/apt/apt.conf.d/20auto-upgrades

# 1 GB of swap so a small Droplet survives memory spikes.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/sh deploy
usermod -aG docker deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
printf 'restrict,command="/usr/local/bin/airlox-deploy" %s\n' "$pubkey" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

install -m 755 -o root -g root "$here/airlox-deploy" /usr/local/bin/airlox-deploy
install -d -m 755 -o deploy -g deploy /opt/airlox
if [ ! -f /opt/airlox/.env ]; then
  echo "AIRLOX_DOMAIN=$domain" > /opt/airlox/.env
else
  grep -v '^AIRLOX_DOMAIN=' /opt/airlox/.env > /opt/airlox/.env.new || true
  echo "AIRLOX_DOMAIN=$domain" >> /opt/airlox/.env.new
  mv /opt/airlox/.env.new /opt/airlox/.env
fi
chown deploy:deploy /opt/airlox/.env

echo "ready: the next deploy starts the relay at https://$domain"
