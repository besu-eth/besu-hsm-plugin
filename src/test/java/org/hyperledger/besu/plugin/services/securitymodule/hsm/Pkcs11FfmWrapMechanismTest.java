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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Tests the wrap-mechanism selection used by the ECDH recipe. Flag values mirror what real tokens
 * report via {@code C_GetMechanismInfo}: Luna Cloud HSM (FIPS approved configuration) advertises
 * {@code CKM_AES_CBC} as encrypt/decrypt/unwrap only, but its AES Key Wrap as encrypt/decrypt/
 * wrap/unwrap.
 */
class Pkcs11FfmWrapMechanismTest {

  private static final long CKF_ENCRYPT = 0x100L;
  private static final long CKF_DECRYPT = 0x200L;
  private static final long CKF_WRAP = 0x20000L;
  private static final long CKF_UNWRAP = 0x40000L;

  private static final long CBC = Pkcs11Ffm.AES_CBC.id();
  private static final long KW = Pkcs11Ffm.LUNA_AES_KW.id();

  private static final long FULL = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
  private static final long NO_WRAP = CKF_ENCRYPT | CKF_DECRYPT | CKF_UNWRAP;

  private static Optional<Pkcs11Ffm.WrapMechanism> choose(final Map<Long, Long> tokenFlags) {
    return Pkcs11Ffm.chooseWrapMechanism(id -> tokenFlags.getOrDefault(id, -1L));
  }

  @Test
  void prefersAesCbcWhenTokenAdvertisesIt() {
    // SoftHSM2 / Utimaco / non-FIPS Luna: behaviour must not change even if KW is also present.
    assertThat(choose(Map.of(CBC, FULL, KW, FULL))).contains(Pkcs11Ffm.AES_CBC);
  }

  @Test
  void fallsBackToLunaAesKwWhenCbcCannotWrap() {
    // Luna Cloud HSM, FIPS approved configuration: CBC is unwrap-only.
    assertThat(choose(Map.of(CBC, NO_WRAP, KW, FULL))).contains(Pkcs11Ffm.LUNA_AES_KW);
  }

  @Test
  void fallsBackToLunaAesKwWhenCbcUnsupported() {
    assertThat(choose(Map.of(KW, FULL))).contains(Pkcs11Ffm.LUNA_AES_KW);
  }

  @Test
  void skipsMechanismThatCanWrapButNotDecrypt() {
    // The recipe needs C_Decrypt as the oracle half, so wrap-only is not enough.
    assertThat(choose(Map.of(CBC, CKF_WRAP, KW, FULL))).contains(Pkcs11Ffm.LUNA_AES_KW);
  }

  @Test
  void emptyWhenNothingQualifies() {
    assertThat(choose(Map.of(CBC, NO_WRAP, KW, NO_WRAP))).isEmpty();
    assertThat(choose(Map.of())).isEmpty();
  }
}
