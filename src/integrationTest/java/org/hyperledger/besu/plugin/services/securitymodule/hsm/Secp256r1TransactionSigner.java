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
import java.util.Arrays;
import java.util.List;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPSignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

/**
 * Signs an Ethereum legacy transaction (EIP-155) using Besu's {@link SECP256R1} algorithm. Used by
 * the secp256r1 QBFT integration test, where web3j's secp256k1-only {@code TransactionEncoder} is
 * unusable. Algorithm copied from Besu's acceptance-tests-dsl {@code SignUtil}; the dsl module is
 * not on this project's classpath, so the few lines we need are inlined here.
 */
final class Secp256r1TransactionSigner {

  private static final int CHAIN_ID_INC = 35;
  private static final SECP256R1 ALGORITHM = new SECP256R1();

  private Secp256r1TransactionSigner() {}

  static byte[] sign(
      final RawTransaction transaction, final BigInteger privateKey, final long chainId) {
    final byte[] encoded = TransactionEncoder.encode(transaction, chainId);
    final byte[] hash = Hash.sha3(encoded);

    final KeyPair keyPair = keyPair(privateKey);
    final SECPSignature signature = ALGORITHM.sign(Bytes32.wrap(hash), keyPair);

    final Sign.SignatureData signatureData =
        new Sign.SignatureData(
            calculateV(signature, BigInteger.valueOf(chainId)),
            signature.getR().toByteArray(),
            signature.getS().toByteArray());

    final List<RlpType> values = TransactionEncoder.asRlpValues(transaction, signatureData);
    return RlpEncoder.encode(new RlpList(values));
  }

  static String addressFromPrivateKey(final BigInteger privateKey) {
    final byte[] publicKeyBytes = keyPair(privateKey).getPublicKey().getEncoded();
    final byte[] addressBytes = Arrays.copyOfRange(Hash.sha3(publicKeyBytes), 12, 32);
    return "0x" + Numeric.toHexStringNoPrefix(addressBytes);
  }

  private static KeyPair keyPair(final BigInteger privateKey) {
    final SECPPrivateKey priv = ALGORITHM.createPrivateKey(privateKey);
    return ALGORITHM.createKeyPair(priv);
  }

  private static byte[] calculateV(final SECPSignature signature, final BigInteger chainId) {
    BigInteger v = BigInteger.valueOf(signature.getRecId() & 0xFF);
    v = v.add(chainId.multiply(BigInteger.TWO));
    v = v.add(BigInteger.valueOf(CHAIN_ID_INC));
    return v.toByteArray();
  }
}
