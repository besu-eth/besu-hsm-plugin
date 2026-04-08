/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.plugin.services.securitymodule.hsm;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;

/**
 * Abstraction over different HSM provider backends. Each implementation handles provider
 * initialization, key loading, cryptographic operations, and cleanup for a specific HSM access
 * mechanism. This allows new provider types (e.g., REST-based KMS) to be added without modifying
 * {@link HsmSecurityModule}.
 */
interface HsmProvider {

  /**
   * Signs the given data hash using the HSM-managed private key.
   *
   * @param dataHash the 32-byte hash to sign
   * @return the ECDSA signature with canonical (low-S) form
   */
  Signature sign(Bytes32 dataHash);

  /**
   * Returns the public key loaded from the HSM.
   *
   * @return the public key
   */
  PublicKey getPublicKey();

  /**
   * Performs ECDH key agreement using the HSM-managed private key and the given party's public key.
   *
   * @param partyKey the other party's public key
   * @return the 32-byte shared secret
   */
  Bytes32 calculateECDHKeyAgreement(PublicKey partyKey);

  /**
   * Releases any resources held by this provider (JCA provider registration, classloaders, etc).
   */
  void close();
}
