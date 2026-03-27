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

import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Secp256k1Parameters.CURVE_ORDER;
import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Secp256k1Parameters.HALF_CURVE_ORDER;
import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Secp256k1Parameters.SECP256K1_PARAM_SPEC;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;

final class SignatureUtil {

  private SignatureUtil() {}

  static Signature extractRAndS(final byte[] signatureBytes, final boolean isP1363) {
    if (isP1363) {
      return extractRAndSFromP1363(signatureBytes);
    }
    return extractRAndSFromDER(signatureBytes);
  }

  private static Signature extractRAndSFromP1363(final byte[] signatureBytes) {
    if (signatureBytes.length != 64) {
      throw new SecurityModuleException(
          "Invalid P1363 signature length: expected 64, got " + signatureBytes.length);
    }
    final BigInteger r = new BigInteger(1, signatureBytes, 0, 32);
    final BigInteger s = new BigInteger(1, signatureBytes, 32, 32);
    return canonicalize(r, s);
  }

  private static Signature extractRAndSFromDER(final byte[] der) {
    try (final ASN1InputStream asn1InputStream = new ASN1InputStream(der)) {
      if (!(asn1InputStream.readObject() instanceof final DLSequence seq)) {
        throw new SecurityModuleException("DER signature is not a valid ASN.1 SEQUENCE");
      }
      if (seq.size() != 2) {
        throw new SecurityModuleException("DER signature must contain exactly 2 integers");
      }
      if (!(seq.getObjectAt(0) instanceof final ASN1Integer rInt)
          || !(seq.getObjectAt(1) instanceof final ASN1Integer sInt)) {
        throw new SecurityModuleException("DER signature SEQUENCE elements must be INTEGERs");
      }
      final BigInteger r = rInt.getValue();
      final BigInteger s = sInt.getValue();
      if (r.signum() <= 0 || s.signum() <= 0) {
        throw new SecurityModuleException("Invalid DER signature: R or S is non-positive");
      }
      if (asn1InputStream.readObject() != null) {
        throw new SecurityModuleException("Trailing data found after DER signature SEQUENCE");
      }
      return canonicalize(r, s);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error parsing DER-encoded signature", e);
    }
  }

  private static Signature canonicalize(final BigInteger r, final BigInteger s) {
    if (r.signum() <= 0 || r.compareTo(CURVE_ORDER) >= 0) {
      throw new SecurityModuleException("Invalid signature: R is out of range");
    }

    final BigInteger canonicalS = s.compareTo(HALF_CURVE_ORDER) > 0 ? CURVE_ORDER.subtract(s) : s;

    if (canonicalS.signum() <= 0 || canonicalS.compareTo(CURVE_ORDER) >= 0) {
      throw new SecurityModuleException(
          "Invalid signature: S is out of range after canonicalization");
    }

    return new SignatureImpl(r, canonicalS);
  }

  static byte[] toDer(final BigInteger r, final BigInteger s) {
    try {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1Integer(r));
      v.add(new ASN1Integer(s));
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      final ASN1OutputStream asnOs = ASN1OutputStream.create(baos);
      asnOs.writeObject(new DERSequence(v));
      asnOs.close();
      return baos.toByteArray();
    } catch (final Exception e) {
      throw new SecurityModuleException("Error encoding signature to DER", e);
    }
  }

  static java.security.PublicKey ecPointToJcePublicKey(
      final ECPoint ecPoint, final Provider provider) {
    try {
      return KeyFactory.getInstance("EC", provider)
          .generatePublic(new ECPublicKeySpec(ecPoint, SECP256K1_PARAM_SPEC));
    } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new SecurityModuleException("Error converting ECPoint to PublicKey", e);
    }
  }

  static final class SignatureImpl implements Signature {
    private final BigInteger r;
    private final BigInteger s;

    SignatureImpl(final BigInteger r, final BigInteger s) {
      this.r = r;
      this.s = s;
    }

    @Override
    public BigInteger getR() {
      return r;
    }

    @Override
    public BigInteger getS() {
      return s;
    }
  }
}
