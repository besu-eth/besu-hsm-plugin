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
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

final class EcCurveParameters {

  private final String curveName;
  private final ECParameterSpec paramSpec;
  private final BigInteger curveOrder;
  private final BigInteger halfCurveOrder;

  EcCurveParameters(final String curveName) {
    final X9ECParameters params = ECNamedCurveTable.getByName(curveName);
    if (params == null) {
      throw new IllegalArgumentException(
          "Unsupported EC curve: " + curveName + ". Supported values: secp256k1, secp256r1");
    }
    this.curveName = curveName;
    final ECDomainParameters ecParams =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    this.paramSpec =
        new ECNamedCurveSpec(
            curveName, ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
    this.curveOrder = params.getN();
    // Ethereum requires "low-S" signatures (EIP-2): S must be in the lower half of the curve order
    this.halfCurveOrder = curveOrder.shiftRight(1);
  }

  String getCurveName() {
    return curveName;
  }

  ECParameterSpec getParamSpec() {
    return paramSpec;
  }

  BigInteger getCurveOrder() {
    return curveOrder;
  }

  BigInteger getHalfCurveOrder() {
    return halfCurveOrder;
  }
}
