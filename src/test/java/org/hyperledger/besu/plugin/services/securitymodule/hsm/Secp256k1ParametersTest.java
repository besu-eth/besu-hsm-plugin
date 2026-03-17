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

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class Secp256k1ParametersTest {

  private static final BigInteger EXPECTED_CURVE_ORDER =
      new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

  @Test
  void curveOrderMatchesKnownValue() {
    assertThat(Secp256k1Parameters.CURVE_ORDER).isEqualTo(EXPECTED_CURVE_ORDER);
  }

  @Test
  void halfCurveOrderIsHalfOfCurveOrder() {
    assertThat(Secp256k1Parameters.HALF_CURVE_ORDER)
        .isEqualTo(Secp256k1Parameters.CURVE_ORDER.shiftRight(1));
  }

  @Test
  void paramSpecIsNotNull() {
    assertThat(Secp256k1Parameters.SECP256K1_PARAM_SPEC).isNotNull();
  }

  @Test
  void paramSpecHasCorrectOrder() {
    assertThat(Secp256k1Parameters.SECP256K1_PARAM_SPEC.getOrder()).isEqualTo(EXPECTED_CURVE_ORDER);
  }

  @Test
  void paramSpecHasCofactorOne() {
    assertThat(Secp256k1Parameters.SECP256K1_PARAM_SPEC.getCofactor()).isEqualTo(1);
  }
}
