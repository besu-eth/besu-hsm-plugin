# YubiHSM PKCS#11 integration - requires physical USB device or YubiHSM connector.
# Not used in CI. For manual testing only.
ARG BESU_VERSION=26.2.0
FROM hyperledger/besu:${BESU_VERSION}

USER root

# YubiHSM SDK must be downloaded from Yubico:
# https://developers.yubico.com/YubiHSM2/Releases/
# The yubihsm-pkcs11 library path varies by installation method.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unzip && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/besu/plugins

COPY config/pkcs11-yubihsm.cfg /etc/besu/config/pkcs11-yubihsm.cfg
COPY config/pkcs11-hsm-password.test.txt /etc/besu/config/pkcs11-hsm-password.txt
COPY config/besu-dev.toml /etc/besu/config/besu-dev.toml

USER besu

ENTRYPOINT ["/opt/besu/bin/besu"]
