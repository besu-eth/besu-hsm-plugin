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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EcCurveParametersTest {

  private static final BigInteger SECP256K1_CURVE_ORDER =
      new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  private static final BigInteger SECP256R1_CURVE_ORDER =
      new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

  @Test
  void secp256k1CurveOrderMatchesKnownValue() {
    final EcCurveParameters params = new EcCurveParameters("secp256k1");
    assertThat(params.getCurveOrder()).isEqualTo(SECP256K1_CURVE_ORDER);
  }

  @Test
  void secp256r1CurveOrderMatchesKnownValue() {
    final EcCurveParameters params = new EcCurveParameters("secp256r1");
    assertThat(params.getCurveOrder()).isEqualTo(SECP256R1_CURVE_ORDER);
  }

  @ParameterizedTest
  @ValueSource(strings = {"secp256k1", "secp256r1"})
  void halfCurveOrderIsCorrect(final String curveName) {
    final EcCurveParameters params = new EcCurveParameters(curveName);
    assertThat(params.getHalfCurveOrder()).isEqualTo(params.getCurveOrder().shiftRight(1));
  }

  @ParameterizedTest
  @ValueSource(strings = {"secp256k1", "secp256r1"})
  void paramSpecIsNotNull(final String curveName) {
    final EcCurveParameters params = new EcCurveParameters(curveName);
    assertThat(params.getParamSpec()).isNotNull();
  }

  @ParameterizedTest
  @ValueSource(strings = {"secp256k1", "secp256r1"})
  void paramSpecHasCorrectOrder(final String curveName) {
    final EcCurveParameters params = new EcCurveParameters(curveName);
    assertThat(params.getParamSpec().getOrder()).isEqualTo(params.getCurveOrder());
  }

  @ParameterizedTest
  @ValueSource(strings = {"secp256k1", "secp256r1"})
  void paramSpecHasCofactorOne(final String curveName) {
    final EcCurveParameters params = new EcCurveParameters(curveName);
    assertThat(params.getParamSpec().getCofactor()).isEqualTo(1);
  }

  @Test
  void unknownCurveThrows() {
    assertThatThrownBy(() -> new EcCurveParameters("invalid"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unsupported EC curve");
  }
}
