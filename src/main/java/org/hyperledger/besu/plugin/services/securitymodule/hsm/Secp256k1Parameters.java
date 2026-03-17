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

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

final class Secp256k1Parameters {

  static final ECParameterSpec SECP256K1_PARAM_SPEC;
  static final BigInteger CURVE_ORDER;
  static final BigInteger HALF_CURVE_ORDER;

  static {
    final X9ECParameters params = SECNamedCurves.getByName("secp256k1");
    final ECDomainParameters ecParams =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

    SECP256K1_PARAM_SPEC =
        new ECNamedCurveSpec(
            "secp256k1", ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

    CURVE_ORDER = params.getN();
    HALF_CURVE_ORDER = CURVE_ORDER.shiftRight(1);
  }

  private Secp256k1Parameters() {}
}
