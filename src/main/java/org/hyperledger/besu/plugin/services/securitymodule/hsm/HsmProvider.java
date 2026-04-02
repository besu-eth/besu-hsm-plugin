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

import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPublicKey;

/**
 * Abstraction over different HSM provider backends. Each implementation handles provider
 * initialization, key loading, and cleanup for a specific HSM access mechanism.
 */
interface HsmProvider {

  /** Returns the JCA {@link Provider} configured for this HSM backend. */
  Provider getProvider();

  /** Returns the private key loaded from the HSM. */
  PrivateKey getPrivateKey();

  /** Returns the EC public key loaded from the HSM. */
  ECPublicKey getEcPublicKey();

  /** Removes the JCA provider from the {@link java.security.Security} registry. */
  void removeProvider();
}
