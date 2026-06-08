FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iproute2 \
    iputils-ping \
    traceroute \
    snmp \
    samba-common-bin \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-fetch IEEE OUI database so first-boot vendor lookups work offline.
# Fall back to an empty file if the build host can't reach IEEE.
RUN mkdir -p /app/data && \
    (curl -fsSL --max-time 60 http://standards-oui.ieee.org/oui/oui.csv -o /app/data/oui.csv \
     || echo "Registry,Assignment,Organization Name,Organization Address" > /app/data/oui.csv)

COPY app/ ./app/

ENV PYTHONUNBUFFERED=1 \
    NETSCAN_DB=/data/netscan.db \
    NETSCAN_PORT=8080 \
    NETSCAN_OUI_CSV=/app/data/oui.csv \
    NETSCAN_UPTIME_INTERVAL=300 \
    NETSCAN_SNMP_COMMUNITY=

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "600", "app.main:app"]
