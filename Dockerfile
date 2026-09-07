ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

USER root

ARG DEBIAN_FRONTEND=noninteractive
ARG ZEEK_REPOSITORY=xUbuntu_24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acct \
        bpfcc-tools \
        ca-certificates \
        curl \
        gnupg \
        inotify-tools \
        iptables \
        iproute2 \
        iputils-ping \
        jq \
        libbpf-tools \
        libcap2-bin \
        lsof \
        netcat-openbsd \
        nftables \
        procps \
        python3 \
        python3-bpfcc \
        strace \
        tcpdump \
        tlog \
        util-linux \
        zstd \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPOSITORY}/Release.key" \
       | gpg --dearmor -o /usr/share/keyrings/security-zeek.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/security-zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPOSITORY}/ /" \
       > /etc/apt/sources.list.d/security-zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*

COPY observer /opt/nsg-observer
COPY examples /opt/nsg-observer/examples

RUN chmod +x /opt/nsg-observer/bin/* /opt/nsg-observer/examples/*.sh \
    && mkdir -p /observation \
    && ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek \
    && printf '\n# NSG observer command logging\n[ -r /opt/nsg-observer/etc/bash-observer.sh ] && . /opt/nsg-observer/etc/bash-observer.sh\n' \
       >> /etc/bash.bashrc

ENV PATH="/opt/zeek/bin:/opt/nsg-observer/bin:${PATH}" \
    OBS_OUTPUT_DIR=/observation \
    OBS_ENABLE_BCC=1 \
    OBS_ENABLE_FILE_EVENTS=1 \
    OBS_ENABLE_NETWORK_TOPOLOGY=1 \
    OBS_ENABLE_PCAP=1 \
    OBS_ENABLE_PROCESS_SNAPSHOTS=1 \
    OBS_ENABLE_SOCKET_SNAPSHOTS=1 \
    OBS_ENABLE_STATE_RECONCILIATION=1 \
    OBS_ENABLE_STATE_GRAPH=1 \
    OBS_ENABLE_TRAJECTORY=1 \
    OBS_ENABLE_STRACE=1 \
    OBS_ENABLE_TTY_RECORDING=1 \
    OBS_ENABLE_ZEEK=1 \
    OBS_PROCESS_INTERVAL=0.10 \
    OBS_SOCKET_INTERVAL=1.0 \
    OBS_NETWORK_INTERVAL=10 \
    OBS_SNAPSHOT_INTERVAL=30 \
    OBS_STATE_INTERVAL=10 \
    OBS_STATE_LEVEL=operational \
    OBS_TRAJECTORY_SENSITIVITY=material \
    OBS_TRAJECTORY_SETTLE_SECONDS=2 \
    OBS_PCAP_FILE_MB=100 \
    OBS_PCAP_FILE_COUNT=10

VOLUME ["/observation"]

ENTRYPOINT ["/opt/nsg-observer/bin/observe-entrypoint"]
CMD ["bash", "-lc", "while true; do sleep 3600; done"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/opt/nsg-observer/bin/observer-healthcheck"]
