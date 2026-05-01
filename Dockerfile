# Loki-Pi development image.
#
# Built for linux/arm64 by default to match Raspberry Pi Zero 2 W / Pi 5.
# Override at build time for other archs:
#   docker buildx build --platform=linux/arm/v7 -t loki-pi .

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        smbclient \
        freerdp2-x11 \
        python3 \
        python3-pip \
        python3-venv \
        iproute2 \
        net-tools \
        iputils-ping \
        ca-certificates \
        curl \
        unzip \
        git \
        bsdmainutils \
        coreutils \
        bind9-dnsutils \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# --- searchsploit (Exploit-DB CLI) ---
# Tiny offline DB of public exploit modules; we map CVEs found by NSE/Nuclei
# to their Exploit-DB entries for "this is exploitable, here's how" context.
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && /usr/local/bin/searchsploit -h >/dev/null 2>&1 || true

# --- testssl.sh (comprehensive TLS audit) ---
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /opt/testssl/testssl.sh

# --- Nuclei (templated vulnerability scanner from ProjectDiscovery) ---
# Auto-detect arch and pull the matching release tarball. Binary lives at
# /usr/local/bin/nuclei. Templates are downloaded on first run.
ARG NUCLEI_VERSION=3.3.5
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64)         nuclei_arch="linux_amd64" ;; \
        arm64)         nuclei_arch="linux_arm64" ;; \
        armhf|armel)   nuclei_arch="linux_arm" ;; \
        i386)          nuclei_arch="linux_386" ;; \
        *)             echo "Unsupported arch: $arch"; exit 1 ;; \
    esac; \
    url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${nuclei_arch}.zip"; \
    curl -fsSL -o /tmp/nuclei.zip "$url"; \
    unzip -p /tmp/nuclei.zip nuclei > /usr/local/bin/nuclei; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip; \
    /usr/local/bin/nuclei -version

WORKDIR /app

# Install Python deps first so layer cache survives source edits.
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Source comes via volume mount in docker-compose; copy is for standalone builds.
COPY . /app

ENV LOKI_DATA_DIR=/data
ENV LOKI_BIND=0.0.0.0
ENV LOKI_PORT=8000
ENV PYTHONUNBUFFERED=1
RUN mkdir -p /data/logs

EXPOSE 8000

CMD ["python3", "/app/loki.py"]
