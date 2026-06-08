# NetScan

A self-hosted, Dockerized network scanner that discovers devices on your LAN
and maps them in a browser UI.

Built on `nmap` + Flask + SQLite, with a vanilla-JS frontend that renders a
live device table and a force-directed network graph.

## Features

- One-click LAN scan with three profiles:
  - **Quick** — top 100 ports, no OS fingerprinting
  - **Standard** — top 1000 ports, service + OS detection (default)
  - **Deep** — full TCP sweep + OS detection
- Auto-detects your local /24 if no target is provided
- Persists hosts, MACs, vendors, hostnames, OS guesses, and open services to SQLite
- Network map visualization (vis-network) with gateway highlighted
- Scan history with status + result counts
- REST API for automation (`/api/scan`, `/api/hosts`, `/api/scans`, `/api/status`)

## Quick start

```bash
docker compose up -d --build
# open http://<docker-host>:8080
```

The container runs with `network_mode: host` and `NET_ADMIN` / `NET_RAW`
capabilities so that `nmap` can do ARP-level discovery and OS fingerprinting
against your LAN. Port 8080 is exposed directly on the host.

Scan data is stored in `./data/netscan.db` on the host (bind-mounted).

### Configuration

Environment variables (set in `docker-compose.yml`):

| Variable                  | Default              | Purpose                                  |
|---------------------------|----------------------|------------------------------------------|
| `NETSCAN_PORT`            | `8080`               | HTTP listen port                         |
| `NETSCAN_DB`              | `/data/netscan.db`   | SQLite path inside the container         |
| `NETSCAN_DEFAULT_TARGET`  | (auto-detected)      | Default CIDR shown in the UI             |

## API

```bash
# kick off a scan
curl -X POST http://localhost:8080/api/scan \
  -H 'content-type: application/json' \
  -d '{"target":"192.168.1.0/24","profile":"standard"}'

# poll status
curl http://localhost:8080/api/status

# list discovered hosts
curl http://localhost:8080/api/hosts
```

## Security notes

- Only scan networks you own or have explicit permission to scan.
- The container needs `NET_ADMIN` + `NET_RAW` for OS detection and raw ARP probes.
- There is no built-in auth — put it behind a reverse proxy (Caddy, Traefik,
  nginx) with basic auth or SSO if you expose it beyond your LAN.

## Local development

```bash
pip install -r requirements.txt
sudo apt-get install nmap          # nmap binary is required
NETSCAN_DB=./netscan.db python -m app.main
```
