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

import static org.hyperledger.besu.plugin.services.securitymodule.hsm.HsmPlugin.SECURITY_MODULE_NAME;

import java.nio.file.Path;
import picocli.CommandLine.Option;

public class Pkcs11CliOptions {
  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-config-path",
      description = "Path to the PKCS11 configuration file",
      paramLabel = "<path>")
  private Path pkcs11ConfigPath;

  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-password-path",
      description = "Path to the file that contains password or PIN to access PKCS11 token",
      paramLabel = "<path>")
  private Path pkcs11PasswordPath;

  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-key-alias",
      description = "Alias or label of the private key that is stored in the HSM",
      paramLabel = "<label>")
  private String privateKeyAlias;

  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-ec-curve",
      description = "Elliptic curve name: ${COMPLETION-CANDIDATES} (default: ${DEFAULT-VALUE})",
      paramLabel = "<curve>")
  private EcCurve ecCurve = EcCurve.SECP256K1;

  enum EcCurve {
    SECP256K1("secp256k1"),
    SECP256R1("secp256r1");

    private final String curveName;

    EcCurve(final String curveName) {
      this.curveName = curveName;
    }

    @Override
    public String toString() {
      return curveName;
    }
  }

  public Path getPkcs11ConfigPath() {
    return pkcs11ConfigPath;
  }

  public Path getPkcs11PasswordPath() {
    return pkcs11PasswordPath;
  }

  public String getPrivateKeyAlias() {
    return privateKeyAlias;
  }

  public String getEcCurve() {
    return ecCurve.curveName;
  }
}
