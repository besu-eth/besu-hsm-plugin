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

/**
 * Which discovery protocol(s) the QBFT test nodes run, pinned on the command line as Besu's {@code
 * --discovery-mode} rather than relying on Besu's default.
 */
enum DiscoveryMode {
  /**
   * DiscV4 and DiscV5 concurrently on a shared UDP socket. Besu degrades this to V4-only when the
   * node key curve cannot sign an ENR, so a secp256r1 node still starts and discovers peers over
   * DiscV4.
   */
  BOTH,
  /** DiscV5 only; requires a secp256k1 node key. */
  V5
}
