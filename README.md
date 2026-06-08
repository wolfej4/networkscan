# NetScan

A self-hosted, Dockerized network scanner that discovers devices on your LAN,
classifies them, tracks their uptime, and maps the topology.

Built on `nmap` + Flask + SQLite, with a vanilla-JS frontend that renders a
live device table and a force-directed network graph.

## Features

- **Active scanning** with three nmap profiles (quick, standard, deep)
- **Passive discovery**:
  - mDNS / Bonjour browsing (zeroconf)
  - SSDP / UPnP M-SEARCH with friendly-name resolution
  - NetBIOS name lookup via `nmblookup -A`
- **Topology mapping**:
  - `traceroute` from the scanner to every discovered host
  - Optional SNMP v2c LLDP + CDP neighbor walk (set `NETSCAN_SNMP_COMMUNITY`)
- **OUI vendor lookup** from a bundled IEEE OUI database (works offline)
- **Device-type classification** combining OUI, open ports, mDNS, SSDP and
  NetBIOS into categories (router, switch, server, NAS, workstation, phone,
  TV, printer, camera, IoT, etc.) — surfaced as icons in the table and
  colors on the graph
- **Uptime tracking**: background ICMP poller (default every 5 minutes)
  records per-host availability + RTT, shown as 24h sparklines
- **Dark / light theme** toggle (remembered in `localStorage`)
- Scan history, REST API, persistent SQLite storage

## Quick start

```bash
docker compose up -d --build
# open http://<docker-host>:8081
```

`network_mode: host` is required so nmap can do ARP discovery and OS
fingerprinting, and so mDNS/SSDP multicast traffic reaches the container.
Scan data is stored in `./data/netscan.db` on the host.

### Configuration

| Variable                   | Default              | Purpose                                                     |
|----------------------------|----------------------|-------------------------------------------------------------|
| `NETSCAN_PORT`             | `8081`               | HTTP listen port                                            |
| `NETSCAN_DB`               | `/data/netscan.db`   | SQLite path inside the container                            |
| `NETSCAN_DEFAULT_TARGET`   | (auto-detected)      | Default CIDR shown in the UI                                |
| `NETSCAN_UPTIME_INTERVAL`  | `300`                | Uptime ping interval in seconds (`0` disables)              |
| `NETSCAN_SNMP_COMMUNITY`   | (empty)              | SNMP v2c community string for LLDP/CDP discovery            |
| `NETSCAN_OUI_CSV`          | `/app/data/oui.csv`  | Path to IEEE OUI CSV (baked into the image at build time)   |

## API

```bash
# kick off a full scan
curl -X POST http://localhost:8081/api/scan \
  -H 'content-type: application/json' \
  -d '{"target":"192.168.1.0/24","profile":"standard"}'

# re-run passive discovery + topology against already-known hosts
curl -X POST http://localhost:8081/api/discover

# list hosts (includes uptime_24h, device_type, mDNS/SSDP/NetBIOS info)
curl http://localhost:8081/api/hosts

# topology links
curl http://localhost:8081/api/topology

# per-host uptime samples
curl http://localhost:8081/api/hosts/1/uptime?hours=24
```

## Security notes

- Only scan networks you own or have explicit permission to scan.
- The container needs `NET_ADMIN` + `NET_RAW` for OS detection and raw ARP probes.
- There is no built-in auth — put it behind a reverse proxy (Caddy, Traefik,
  nginx) with basic auth or SSO if you expose it beyond your LAN.

## Local development

```bash
pip install -r requirements.txt
sudo apt-get install nmap traceroute snmp samba-common-bin iputils-ping
NETSCAN_DB=./netscan.db python -m app.main
```
