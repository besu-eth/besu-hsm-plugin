ARG BESU_VERSION=26.2.0
FROM hyperledger/besu:${BESU_VERSION}

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        softhsm2 \
        opensc \
        openssl \
        libengine-pkcs11-openssl \
        unzip && \
    rm -rf /var/lib/apt/lists/*

# Create directories for SoftHSM2 token storage and plugin
RUN mkdir -p /var/lib/tokens /opt/besu/plugins /data && \
    chown -R besu:besu /var/lib/tokens /opt/besu/plugins /data

# Copy configuration files
COPY config/softhsm2.conf /etc/softhsm2.conf
COPY config/pkcs11-softhsm.cfg /etc/besu/config/pkcs11-softhsm.cfg
COPY config/pkcs11-hsm-password.txt /etc/besu/config/pkcs11-hsm-password.txt

ENV SOFTHSM2_CONF=/etc/softhsm2.conf

COPY entrypoint-setup.sh /entrypoint-setup.sh
COPY generate-genesis.sh /generate-genesis.sh
COPY entrypoint-besu.sh /entrypoint-besu.sh
RUN chmod +x /entrypoint-setup.sh /generate-genesis.sh /entrypoint-besu.sh

USER besu
