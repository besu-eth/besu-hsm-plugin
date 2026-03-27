ARG BESU_VERSION=26.2.0
FROM hyperledger/besu:${BESU_VERSION}

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        softhsm2 \
        opensc \
        gnutls-bin \
        openssl \
        libengine-pkcs11-openssl \
        unzip && \
    rm -rf /var/lib/apt/lists/*

# Create directories for SoftHSM2 token storage and plugin
RUN mkdir -p /var/lib/tokens /opt/besu/plugins && \
    chown -R besu:besu /var/lib/tokens /opt/besu/plugins

# Copy configuration files
COPY config/softhsm2.conf /etc/softhsm2.conf
COPY config/pkcs11-softhsm.cfg /etc/besu/config/pkcs11-softhsm.cfg
COPY config/pkcs11-hsm-password.test.txt /etc/besu/config/pkcs11-hsm-password.txt

ENV SOFTHSM2_CONF=/etc/softhsm2.conf

COPY entrypoint.sh /entrypoint.sh
COPY entrypoint-keypairgen.sh /entrypoint-keypairgen.sh
RUN chmod +x /entrypoint.sh /entrypoint-keypairgen.sh

USER besu
