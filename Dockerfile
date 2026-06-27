# gamekeeper — bundles the capture/Wi-Fi/firewall tools so monitor, honeypot, and
# Wireshark-style capture work without installing anything on the host.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
# let dumpcap run without root inside the container
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
 && apt-get update && apt-get install -y --no-install-recommends \
      nmap tshark tcpdump aircrack-ng iw iproute2 iptables nftables ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# The locally-authenticated LLM CLI. Only the binary is baked in — the credentials are
# mounted at runtime (compose: ~/.claude), never copied into the image.
RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY gamekeeper ./gamekeeper
RUN pip install --no-cache-dir -e .

# inventory / probe log / bans live on a volume, outside the image
ENV GAMEKEEPER_DB=/data/gamekeeper.sqlite
VOLUME /data

ENTRYPOINT ["gamekeeper"]
CMD ["serve", "--host", "0.0.0.0"]
