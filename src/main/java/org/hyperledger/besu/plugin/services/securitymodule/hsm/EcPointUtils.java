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
import java.security.spec.ECPoint;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;

/** Shared EC-point and BigInteger encoding helpers used by both HSM provider implementations. */
final class EcPointUtils {

  private EcPointUtils() {}

  /**
   * Validates that {@code point} is a non-null, non-infinity affine point on the configured curve.
   * Used at every HSM boundary so a malicious or misconfigured peer cannot smuggle an off-curve
   * point through to the underlying ECDH primitive.
   *
   * @param point the candidate EC point
   * @param curveParams the configured curve
   * @throws SecurityModuleException if {@code point} is null, the point at infinity, or off-curve
   */
  static void validatePointOnCurve(final ECPoint point, final EcCurveParameters curveParams) {
    if (point == null || point.equals(ECPoint.POINT_INFINITY)) {
      throw new SecurityModuleException("EC point is not on the configured curve");
    }
    try {
      final var bcPoint =
          curveParams.getBCCurve().createPoint(point.getAffineX(), point.getAffineY());
      if (!bcPoint.isValid()) {
        throw new SecurityModuleException("EC point is not on the configured curve");
      }
    } catch (final IllegalArgumentException e) {
      throw new SecurityModuleException("EC point is not on the configured curve", e);
    }
  }

  /**
   * Converts a non-negative {@link BigInteger} to a 32-byte big-endian representation,
   * right-aligning and zero-padding if the value is shorter than 32 bytes.
   *
   * <p>{@link BigInteger#toByteArray()} uses two's complement encoding, which may produce a leading
   * {@code 0x00} sign byte for values with the high bit set, resulting in 33 bytes; {@link
   * Bytes#trimLeadingZeros()} drops that, and {@link Bytes32#leftPad(Bytes)} pads shorter values to
   * exactly 32 bytes (and rejects values that don't fit).
   *
   * @param value a non-negative {@link BigInteger}, typically an EC point coordinate
   * @return a {@link Bytes32} containing the big-endian 32-byte representation of {@code value}
   */
  static Bytes32 toBytes32(final BigInteger value) {
    return Bytes32.leftPad(Bytes.wrap(value.toByteArray()).trimLeadingZeros());
  }
}
