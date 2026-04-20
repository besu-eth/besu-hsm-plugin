#!/usr/bin/env bash
# Phase 2: Initialize the CloudHSM cluster.
# Runs on your LOCAL machine after terraform apply creates the cluster and hsm_a.

# ── Fill in before running ────────────────────────────────────────────────────
CLUSTER_ID=cluster-xxxxxxxx   # from AWS Console or Terraform output
AWS_PROFILE=your-profile
AWS_REGION=eu-west-3
# ─────────────────────────────────────────────────────────────────────────────

# 1. Download the CSR that the HSM generated
AWS_PROFILE=$AWS_PROFILE AWS_REGION=$AWS_REGION \
  aws cloudhsmv2 describe-clusters \
    --filters clusterIds=$CLUSTER_ID \
    --query 'Clusters[0].Certificates.ClusterCsr' \
    --output text > cluster.csr

# 2. Create a self-signed ECDSA CA (suitable for dev/test)

# 2.1 Generate the CA private key
openssl ecparam -name prime256v1 -genkey -noout -out customerCA.key

# 2.2 Create the CA root certificate
openssl req -new -x509 -days 3652 -key customerCA.key -out customerCA.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=CloudHSM-Root-CA"

# 2.3 Sign the HSM's CSR with the CA
# The HSM generates its CSR from the hardware's internal key; we sign it with sha256.
openssl x509 -req -days 3652 \
  -in cluster.csr \
  -CA customerCA.crt \
  -CAkey customerCA.key \
  -CAcreateserial \
  -out cluster.crt \
  -sha256

# 3. Initialize the cluster
AWS_PROFILE=$AWS_PROFILE AWS_REGION=$AWS_REGION \
  aws cloudhsmv2 initialize-cluster \
    --cluster-id $CLUSTER_ID \
    --signed-cert file://cluster.crt \
    --trust-anchor file://customerCA.crt

# Cluster transitions: UNINITIALIZED → INITIALIZE_IN_PROGRESS → INITIALIZED
# Keep customerCA.crt — it is required in Phase 3 (activation).
