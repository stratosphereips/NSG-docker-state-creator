ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

USER root

ARG DEBIAN_FRONTEND=noninteractive
ARG ZEEK_REPOSITORY=xUbuntu_24.04
# Zeek has no repo builds for old bases (e.g. Ubuntu 18.04 bionic) or some
# architectures; the runtime collector is toggleable (OBS_ENABLE_ZEEK) anyway.
# Build with --build-arg INSTALL_ZEEK=0 to skip the Zeek repo + package.
ARG INSTALL_ZEEK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acct \
        bpfcc-tools \
        ca-certificates \
        curl \
        gnupg \
        inotify-tools \
        iproute2 \
        iputils-ping \
        jq \
        libcap2-bin \
        lsof \
        netcat-openbsd \
        procps \
        python3 \
        python3-bpfcc \
        strace \
        tcpdump \
        util-linux \
        zstd \
    && rm -rf /var/lib/apt/lists/*

# tlog (TTY recording) is absent on old bases (e.g. bionic); tolerate and
# continue — the remaining collectors do not depend on it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tlog \
    && rm -rf /var/lib/apt/lists/* \
    || echo "WARNING: tlog not available on this base; TTY recording disabled"

RUN if [ "$INSTALL_ZEEK" = "1" ]; then \
        apt-get update \
        && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPOSITORY}/Release.key" \
           | gpg --dearmor -o /usr/share/keyrings/security-zeek.gpg \
        && echo "deb [signed-by=/usr/share/keyrings/security-zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPOSITORY}/ /" \
           > /etc/apt/sources.list.d/security-zeek.list \
        && apt-get update \
        && apt-get install -y --no-install-recommends zeek \
        && rm -rf /var/lib/apt/lists/*; \
    fi

COPY observer /opt/nsg-observer
COPY examples /opt/nsg-observer/examples

# Side-by-side interpreter for bases whose system python3 is too old for the
# observer scripts (e.g. Ubuntu 18.04 bionic = 3.6; scripts need >= 3.8).
# Build with --build-arg OBS_PYTHON_URL=<python-build-standalone install_only
# tarball> to install it under /opt/observer-python and repoint ONLY the
# observer script shebangs at it — the system python and the workload are
# untouched (see the observer packaging notes in the SCL topology plugin).
ARG OBS_PYTHON_URL=""
RUN if [ -n "$OBS_PYTHON_URL" ]; then \
        curl -fsSL "$OBS_PYTHON_URL" \
        | tar -xz -C /opt \
        && mv /opt/python /opt/observer-python \
        && for f in /opt/nsg-observer/bin/*; do \
            sed -i '1s|^#!/usr/bin/env python3$|#!/opt/observer-python/bin/python3|' "$f"; \
        done \
        && /opt/observer-python/bin/python3 --version; \
    fi

RUN chmod +x /opt/nsg-observer/bin/* /opt/nsg-observer/examples/*.sh \
    && mkdir -p /observation \
    && if [ -x /opt/zeek/bin/zeek ]; then ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek; fi \
    && printf '\n# NSG observer command logging\n[ -r /opt/nsg-observer/etc/bash-observer.sh ] && . /opt/nsg-observer/etc/bash-observer.sh\n' \
       >> /etc/bash.bashrc

ENV PATH="/opt/zeek/bin:/opt/nsg-observer/bin:${PATH}" \
    OBS_OUTPUT_DIR=/observation \
    OBS_ENABLE_BCC=1 \
    OBS_ENABLE_FILE_EVENTS=1 \
    OBS_ENABLE_PCAP=1 \
    OBS_ENABLE_PROCESS_SNAPSHOTS=1 \
    OBS_ENABLE_SOCKET_SNAPSHOTS=1 \
    OBS_ENABLE_STATE_RECONCILIATION=1 \
    OBS_ENABLE_STRACE=1 \
    OBS_ENABLE_TTY_RECORDING=1 \
    OBS_ENABLE_ZEEK=1 \
    OBS_PROCESS_INTERVAL=0.10 \
    OBS_SOCKET_INTERVAL=1.0 \
    OBS_SNAPSHOT_INTERVAL=30 \
    OBS_PCAP_FILE_MB=100 \
    OBS_PCAP_FILE_COUNT=10

VOLUME ["/observation"]

ENTRYPOINT ["/opt/nsg-observer/bin/observe-entrypoint"]
CMD ["bash", "-lc", "while true; do sleep 3600; done"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/opt/nsg-observer/bin/observer-healthcheck"]
