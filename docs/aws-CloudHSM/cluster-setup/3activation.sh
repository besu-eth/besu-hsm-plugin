#!/usr/bin/env bash
# Phase 3: Activate the CloudHSM cluster and configure the EC2 client instance.
#
# Three sections — read the headers before running:
#   Section A  (LOCAL)  — copy the CA certificate to the EC2 instance
#   Section B  (EC2)    — install CloudHSM packages and configure the client
#   Section C  (EC2)    — activate the cluster and create HSM users (INTERACTIVE)
#                         See README.md Phase 3c for the interactive commands.

# ── Fill in before running ────────────────────────────────────────────────────
EC2_PUBLIC_IP=x.x.x.x              # public IP of your EC2 instance
SSH_KEY_PATH=~/.ssh/your-key.pem   # path to your SSH private key
HSM_A_PRIVATE_IP=10.x.x.x          # private IP of hsm_a (from AWS Console)
# ─────────────────────────────────────────────────────────────────────────────

# ==============================================================================
# SECTION A — Run from your LOCAL machine
# ==============================================================================

# A.1 Copy the CA certificate (produced in Phase 2) to the EC2 instance
scp -i $SSH_KEY_PATH customerCA.crt ubuntu@$EC2_PUBLIC_IP:/tmp/

# A.2 SSH into the EC2 instance, then continue with Section B
ssh -i $SSH_KEY_PATH ubuntu@$EC2_PUBLIC_IP

# ==============================================================================
# SECTION B — Run on the EC2 instance (automated)
# ==============================================================================

# B.1 Move the CA certificate into the CloudHSM config directory
sudo mv /tmp/customerCA.crt /opt/cloudhsm/etc/customerCA.crt
sudo chmod 644 /opt/cloudhsm/etc/customerCA.crt

# B.2 Install CloudHSM packages
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-cli_latest_u24.04_amd64.deb
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-pkcs11_5.17.1-1_u24.04_amd64.deb
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-jce_latest_u24.04_amd64.deb
sudo apt-get update
sudo apt-get install -y \
  ./cloudhsm-cli_latest_u24.04_amd64.deb \
  ./cloudhsm-pkcs11_5.17.1-1_u24.04_amd64.deb \
  ./cloudhsm-jce_latest_u24.04_amd64.deb \
  opensc

# B.3 Bootstrap the CLI and PKCS#11 against HSM A
# Set HSM_A_PRIVATE_IP to the private IP of hsm_a (from AWS Console).
# The client auto-discovers hsm_b once it becomes active.
sudo /opt/cloudhsm/bin/configure-cli -a $HSM_A_PRIVATE_IP \
  --hsm-ca-cert /opt/cloudhsm/etc/customerCA.crt
sudo /opt/cloudhsm/bin/configure-pkcs11 -a $HSM_A_PRIVATE_IP \
  --hsm-ca-cert /opt/cloudhsm/etc/customerCA.crt \
  --enable-certificate-storage

# B.4 Verify connectivity
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --list-slots

# ==============================================================================
# SECTION C — Run on the EC2 instance (INTERACTIVE)
# See README.md Phase 3c for the full sequence of interactive commands.
# ==============================================================================
/opt/cloudhsm/bin/cloudhsm-cli interactive
