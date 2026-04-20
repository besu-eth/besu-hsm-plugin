# CloudHSM Cluster Setup

End-to-end guide for provisioning a production-grade CloudHSM v2 cluster on AWS.
The setup has automated phases (Terraform, shell scripts) and two interactive phases
(cluster activation and key creation) that require direct CLI input and cannot be scripted.

Follow the phases in order.

## Overview

| Phase | Description | Where | How |
|-------|-------------|-------|-----|
| 1 | Create cluster + HSM A | AWS | Terraform |
| 2 | Initialize the cluster | Local machine | [`2init.sh`](./2init.sh) |
| 3 | Activate + configure the EC2 client | Local + EC2 | [`3activation.sh`](./3activation.sh) — partly interactive |
| 4 | Add HSM B + security group | AWS | Terraform |
| 5 | Create key pairs | EC2 | [`5createKey.sh`](./5createKey.sh) — interactive |
| 6 | Verify PKCS#11 access | EC2 | [`6pkcs11.sh`](./6pkcs11.sh) |

## Prerequisites

- AWS CLI configured with credentials and the target region
- Terraform ≥ 1.0
- An EC2 instance (Ubuntu 24.04 LTS) in the same VPC — attach the `hsm_client_sg`
  security group defined in Phase 4
- Local tools: `openssl`, `jq`

## Handling Secrets

Several sensitive artifacts are produced or used during this setup. Store all of them
in a secrets manager (e.g. 1Password, HashiCorp Vault, AWS Secrets Manager) and never
commit them to version control.

| Artifact | Created in | Why it matters |
|----------|------------|----------------|
| `customerCA.key` | Phase 2 | Signs HSM certificates — anyone with this can issue trusted certs for your cluster |
| `customerCA.crt` | Phase 2 | The trust anchor for all CloudHSM clients |
| Admin password | Phase 3c | Full control over the HSM |
| CryptoOfficer password | Phase 3c | Can create and delete HSM users |
| CryptoUser password | Phase 3c | Used by applications to sign transactions and perform ECDH |
| SSH key (`SSH_KEY_PATH`) | Phase 3 | Access to the EC2 client instance |

> `customerCA.key` is especially sensitive — once the cluster is initialized it is no
> longer needed for day-to-day operations. Store it offline or in a hardware-protected
> vault and do not leave it on the machine you used to run `2init.sh`.

---

## Phase 1 — Create the Cluster and First HSM

Create the cluster and a single HSM in the first availability zone. Only `hsm_a` is
provisioned here — `hsm_b` is added after activation (Phase 4) because a second HSM
cannot join an unactivated cluster.

```terraform
resource "aws_cloudhsm_v2_cluster" "cloudhsm_v2_cluster" {
  hsm_type   = "hsm2m.medium"
  mode       = "FIPS"
  subnet_ids = module.vpc.private_subnets
  tags = merge(local.tags, {
    Name = "besu-hsm-cluster"
  })
}

resource "aws_cloudhsm_v2_hsm" "hsm_a" {
  cluster_id        = aws_cloudhsm_v2_cluster.cloudhsm_v2_cluster.cluster_id
  availability_zone = "eu-west-3a"
}
```

Wait for the cluster to reach **UNINITIALIZED** state before continuing.

---

## Phase 2 — Initialize the Cluster

> **Runs on:** your local machine
> **Script:** [`2init.sh`](./2init.sh)

Fill in the variables at the top of the script, then run it:

```bash
bash 2init.sh
```

The script:
1. Downloads the cluster CSR from AWS
2. Creates a self-signed ECDSA CA (suitable for dev/test)
3. Signs the HSM CSR with the CA
4. Calls `aws cloudhsmv2 initialize-cluster`

The cluster transitions: **UNINITIALIZED → INITIALIZE\_IN\_PROGRESS → INITIALIZED**

> Keep `customerCA.crt` — you will copy it to the EC2 instance in Phase 3.

---

## Phase 3 — Activate the Cluster

> **Script:** [`3activation.sh`](./3activation.sh)

This phase has three parts. Read the section headers before running.

### 3a. Copy the CA certificate (local)

Fill in `EC2_PUBLIC_IP`, `SSH_KEY_PATH`, and `HSM_A_PRIVATE_IP` at the top of
`3activation.sh`, then run Section A from your local machine:

```bash
bash 3activation.sh   # copy cert + SSH in (Section A)
```

### 3b. Install and configure the CloudHSM clients (EC2)

On the EC2 instance, run Section B of the script. This installs the CloudHSM CLI,
PKCS#11 library, and JCE provider, then bootstraps each against HSM A. The client
auto-discovers HSM B once it is added in Phase 4.

This installs the CloudHSM CLI, PKCS#11 library, and JCE provider, then bootstraps
each against HSM A. The client auto-discovers HSM B once it is added in Phase 4.

### 3c. Activate the cluster (interactive)

> **Manual step** — the CloudHSM CLI requires an interactive terminal for cluster
> activation. This cannot be scripted.

```bash
/opt/cloudhsm/bin/cloudhsm-cli interactive
```

Inside the interactive shell, run these commands in order:

```
# Activate the cluster — enter the default password when prompted: password
aws-cloudhsm > cluster activate

# Log in as the default admin
aws-cloudhsm > login --username admin --role admin

# Create a Crypto Officer (CO) — manages HSM users
aws-cloudhsm > user create --username CryptoOfficer1 --role admin

# Create a Crypto User (CU) — the application account used for signing and ECDH
aws-cloudhsm > user create --username CryptoUser1 --role crypto-user

aws-cloudhsm > quit
```

---

## Phase 4 — Add HSM B and Configure Networking

With the cluster activated, add the second HSM for high availability and define
the security group that EC2 client instances use to reach the cluster.

```terraform
# Second HSM in a different AZ for HA
resource "aws_cloudhsm_v2_hsm" "hsm_b" {
  cluster_id        = aws_cloudhsm_v2_cluster.cloudhsm_v2_cluster.cluster_id
  availability_zone = "eu-west-3b"
}

# Security group for EC2 client instances
resource "aws_security_group" "hsm_client_sg" {
  name        = "hsm-client-sg"
  description = "Security group for instances running CloudHSM CLI"
  vpc_id      = var.vpc_id
}

# Allow EC2 client → HSM cluster on ports 2223–2225
resource "aws_security_group_rule" "allow_client_to_hsm" {
  type                     = "ingress"
  from_port                = 2223
  to_port                  = 2225
  protocol                 = "tcp"
  security_group_id        = aws_cloudhsm_v2_cluster.cloudhsm_v2_cluster.security_group_id
  source_security_group_id = aws_security_group.hsm_client_sg.id
}

resource "aws_security_group_rule" "allow_hsm_to_client" {
  type                     = "egress"
  from_port                = 2223
  to_port                  = 2225
  protocol                 = "tcp"
  security_group_id        = aws_cloudhsm_v2_cluster.cloudhsm_v2_cluster.security_group_id
  source_security_group_id = aws_security_group.hsm_client_sg.id
}
```

---

## Phase 5 — Create Key Pairs

> **Runs on:** EC2
> **Script:** [`5createKey.sh`](./5createKey.sh) — interactive

Start the CloudHSM CLI interactive shell:

```bash
/opt/cloudhsm/bin/cloudhsm-cli interactive
```

Inside the interactive shell:

```
login --username CryptoUser1 --role crypto-user

key generate-asymmetric-pair ec \
  --curve secp256k1 \
  --private-label validatorPrivate \
  --public-label validatorPublic \
  --public-attributes verify=true id=0x01 \
  --private-attributes sign=true sensitive=true extractable=false derive=true id=0x01
```

Key attribute notes:
- `sensitive=true` — private key value cannot be read in plaintext from the HSM
- `extractable=false` — private key cannot be exported or wrapped
- `derive=true` — enables ECDH key agreement (required for Besu's devp2p handshakes)

---

## Phase 6 — Verify PKCS#11 Access

> **Runs on:** EC2
> **Script:** [`6pkcs11.sh`](./6pkcs11.sh)

Confirm the key pair is visible through the PKCS#11 interface:

Fill in `HSM_USER` and `HSM_PASSWORD` at the top of the script, then run it:

```bash
bash 6pkcs11.sh
```

You should see the key pair from Phase 5 listed as objects on the HSM.

---

## Next Steps

The cluster is initialized, activated, and has at least one key pair. Continue to:

**[Getting Started — Install SDKs and generate validator keys](../1GettingStarted.md)**
