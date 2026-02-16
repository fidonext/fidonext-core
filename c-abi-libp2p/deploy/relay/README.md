# Relay Container Deployment

This directory contains a production-oriented container entrypoint for running
a FidoNext relay node on a server.

## Quick Start

```bash
cd c-abi-libp2p/deploy/relay
docker compose up --build -d
docker compose logs -f relay
```

The relay listens on `/ip4/0.0.0.0/tcp/41000` by default.

For global deployments run multiple copies of this stack on separate servers
(preferably different countries/providers). Use the resulting relay multiaddrs
as bootstrap entries for terminal clients.

## Publish to Docker Hub

1. Login once:

```bash
docker login
```

2. Build and push image:

```bash
cd c-abi-libp2p/deploy/relay
DOCKERHUB_REPO=<dockerhub-user-or-org>/fidonext-relay IMAGE_TAG=v0.1.0 ./publish_dockerhub.sh
```

3. Validate from any host:

```bash
docker pull <dockerhub-user-or-org>/fidonext-relay:v0.1.0
```

## Deploy From Prebuilt Docker Hub Image (no source code on server)

On each VPS:

```bash
mkdir -p /opt/fidonext-relay && cd /opt/fidonext-relay
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/<your-org>/<your-repo>/<your-branch>/c-abi-libp2p/deploy/relay/docker-compose.hub.yml
```

Create `.env`:

```env
FIDONEXT_RELAY_IMAGE=docker.io/<dockerhub-user-or-org>/fidonext-relay:v0.1.0
LISTEN_ADDR=/ip4/0.0.0.0/tcp/41000
RELAY_PORT_TCP=41000
PROFILE_PATH=/data/relay.profile.json
USE_QUIC=0
BOOTSTRAP_PEERS=
EXTRA_ARGS=
```

Run:

```bash
docker compose up -d
docker compose logs -f relay
```

To update image version, change `FIDONEXT_RELAY_IMAGE` and run:

```bash
docker compose pull && docker compose up -d
```

## Hetzner Cloud: detailed deployment guide

This section describes two options:

- **A. Cloud-init (recommended):** relay auto-installs and starts on first boot.
- **B. Manual setup:** install Docker and run compose manually.

### A) One-shot deployment with cloud-init

1. Open `c-abi-libp2p/deploy/relay/cloud-init.hetzner.relay.yaml`.
2. Replace image in the `.env` part:
   - `FIDONEXT_RELAY_IMAGE=docker.io/<your-user-or-org>/fidonext-relay:<tag>`
3. In Hetzner Cloud Console create server:
   - Image: Ubuntu 22.04 or 24.04
   - Add your SSH key
   - Enable firewall rule: inbound `TCP 41000` from `0.0.0.0/0`
   - Paste full cloud-init YAML into **User data**
4. Wait for server boot (~1-2 minutes), then connect:

```bash
ssh root@<SERVER_PUBLIC_IP>
docker ps
docker logs --tail 80 fidonext-relay
```

5. Get ready bootstrap address:

```bash
fidonext-bootstrap-address
```

The command prints:
`/ip4/<PUBLIC_IP>/tcp/41000/p2p/<RELAY_PEER_ID>`

Use this exact line in clients' `bootstrap_global.txt`.

Notes for cloud-init mode:

- Cloud-init starts relay via `docker run` directly, so it does not depend on
  `docker compose` package availability on the VM image.
- If you change `.env` later, re-apply by running:

```bash
/usr/local/bin/fidonext-relay-up
```

### B) Manual setup on Hetzner VM

1. Create Ubuntu VM in Hetzner Cloud and open inbound `TCP 41000`.
2. SSH into server and install Docker:

```bash
apt-get update
apt-get install -y docker.io docker-compose-plugin curl
systemctl enable --now docker
```

3. Create relay folder:

```bash
mkdir -p /opt/fidonext-relay
cd /opt/fidonext-relay
```

4. Put `docker-compose.hub.yml` as `docker-compose.yml` and create `.env`:

```env
FIDONEXT_RELAY_IMAGE=docker.io/<your-user-or-org>/fidonext-relay:v0.1.0
LISTEN_ADDR=/ip4/0.0.0.0/tcp/41000
RELAY_PORT_TCP=41000
PROFILE_PATH=/data/relay.profile.json
USE_QUIC=0
BOOTSTRAP_PEERS=
EXTRA_ARGS=
```

5. Start relay:

```bash
if docker compose version >/dev/null 2>&1; then
  docker compose up -d
else
  docker-compose up -d
fi
docker logs -f fidonext-relay
```

6. Build bootstrap line:

```bash
PUBLIC_IP="$(curl -4fsS ifconfig.me)"
PEER_ID="$(docker logs fidonext-relay 2>&1 | sed -n 's/^Local PeerId: //p' | tail -n1)"
echo "/ip4/${PUBLIC_IP}/tcp/41000/p2p/${PEER_ID}"
```

Copy the printed value to `bootstrap_global.txt`.

## Environment Variables

- `LISTEN_ADDR` - libp2p listen multiaddr (default: `/ip4/0.0.0.0/tcp/41000`)
- `PROFILE_PATH` - profile path inside container for persistent identity
  (default: `/data/relay.profile.json`)
- `BOOTSTRAP_PEERS` - comma-separated bootstrap multiaddrs
- `USE_QUIC` - set to `1` to enable QUIC
- `SEED_PHRASE` - optional deterministic seed phrase (mutually exclusive with profile)
- `SEED_HEX` - optional deterministic 32-byte hex seed (mutually exclusive with profile)
- `EXTRA_ARGS` - additional args forwarded to relay CLI command

## Notes

- By default, the container uses `--force-hop` so relay mode is enabled
  immediately.
- Identity/profile data is persisted in the `relay-data` volume.
- If both `SEED_*` and `PROFILE_PATH` are provided, `SEED_*` takes precedence.

