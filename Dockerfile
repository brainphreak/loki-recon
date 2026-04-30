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
    && rm -rf /var/lib/apt/lists/*

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
