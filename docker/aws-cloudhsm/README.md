# AWS CloudHSM Integration Testing

## Overview

This directory is a placeholder for future AWS CloudHSM integration testing support.

## Prerequisites

- AWS account with CloudHSM cluster provisioned
- CloudHSM client SDK installed
- PKCS#11 library from AWS CloudHSM client (`/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`)
- Network connectivity to CloudHSM cluster ENI

## Setup Steps

1. Provision a CloudHSM cluster in your AWS account
2. Initialize the cluster and create a crypto user (CU)
3. Install the CloudHSM client SDK on the test machine
4. Configure the client to connect to your cluster
5. Generate an EC key pair (secp256k1) on the HSM
6. Create a PKCS#11 config file pointing to the CloudHSM PKCS#11 library
7. Run Besu with the plugin configured to use the CloudHSM

## PKCS#11 Configuration Example

```
name = CloudHSM
library = /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
slot = 1
```

## Notes

- AWS CloudHSM does not support `CKM_ECDSA` with `secp256k1` on all firmware versions. Verify compatibility.
- The CloudHSM PKCS#11 library requires the CloudHSM client daemon to be running.
- Credentials are passed via the PKCS#11 PIN in the format `<CU_username>:<CU_password>`.
