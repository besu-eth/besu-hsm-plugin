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

import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Validations.requireNonBlank;
import static org.hyperledger.besu.plugin.services.securitymodule.hsm.Validations.requireNonNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HSM provider that uses Java's SunPKCS11 provider to access a PKCS#11 token. Requires a PKCS#11
 * configuration file and a password file for token authentication.
 */
class Pkcs11Provider extends JcaHsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11Provider.class);

  private final Provider provider;

  /**
   * Bundles all artifacts produced during PKCS#11 provider + key initialization so they can be
   * passed to the delegating constructor that calls {@code super()}.
   */
  private record InitResult(Provider provider, PrivateKey privateKey, ECPublicKey ecPublicKey) {}

  /**
   * Creates a {@link Pkcs11Provider} after validating the relevant CLI options.
   *
   * @param cliOptions the parsed CLI options
   * @param curveParams the EC curve parameters
   * @return a new {@link Pkcs11Provider} instance
   * @throws SecurityModuleException if required options are missing or initialization fails
   */
  static Pkcs11Provider create(
      final HsmCliOptions cliOptions, final EcCurveParameters curveParams) {
    requireNonNull(
        cliOptions.getPkcs11ConfigPath(), "PKCS#11 configuration file path is not provided");
    requireNonNull(
        cliOptions.getPkcs11PasswordPath(), "PKCS#11 password file path is not provided");
    requireNonBlank(cliOptions.getPrivateKeyAlias(), "Private key alias is not provided");
    return new Pkcs11Provider(
        cliOptions.getPkcs11ConfigPath(),
        cliOptions.getPkcs11PasswordPath(),
        cliOptions.getPrivateKeyAlias(),
        curveParams);
  }

  private Pkcs11Provider(
      final Path configPath,
      final Path passwordPath,
      final String keyAlias,
      final EcCurveParameters curveParams) {
    this(init(configPath, passwordPath, keyAlias), curveParams);
  }

  private Pkcs11Provider(final InitResult result, final EcCurveParameters curveParams) {
    super(result.provider(), result.privateKey(), result.ecPublicKey(), curveParams);
    this.provider = result.provider();
  }

  private static InitResult init(
      final Path configPath, final Path passwordPath, final String keyAlias) {
    final Provider provider =
        initializeProvider(requireNonNull(configPath, "configPath must not be null"));
    final KeyStore keyStore =
        loadKeyStore(provider, requireNonNull(passwordPath, "passwordPath must not be null"));
    final PrivateKey privateKey =
        loadPrivateKey(keyStore, requireNonNull(keyAlias, "keyAlias must not be null"));
    final ECPublicKey ecPublicKey = loadPublicKey(keyStore, keyAlias);
    return new InitResult(provider, privateKey, ecPublicKey);
  }

  private static Provider initializeProvider(final Path configPath) {
    LOG.info("Initializing PKCS#11 provider ...");
    try {
      final Provider sunPKCS11 = Security.getProvider("SunPKCS11");
      if (sunPKCS11 == null) {
        throw new SecurityModuleException("SunPKCS11 provider not found");
      }
      final Provider configured = sunPKCS11.configure(configPath.toString());
      if (configured == null) {
        throw new SecurityModuleException("Unable to configure SunPKCS11 provider");
      }
      Security.addProvider(configured);
      return configured;
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error loading SunPKCS11 provider with configuration: " + configPath, e);
    }
  }

  private static KeyStore loadKeyStore(final Provider provider, final Path passwordPath) {
    LOG.info("Loading PKCS#11 keystore ...");
    final byte[] passwordBytes;
    try {
      passwordBytes = Files.readAllBytes(passwordPath);
    } catch (final IOException e) {
      throw new SecurityModuleException("Error reading password file: " + passwordPath, e);
    }

    final char[] password = new String(passwordBytes, StandardCharsets.UTF_8).trim().toCharArray();
    Arrays.fill(passwordBytes, (byte) 0);

    try {
      final KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
      keyStore.load(null, password);
      return keyStore;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading PKCS#11 keystore", e);
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  private static PrivateKey loadPrivateKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading private key for alias: {} ...", alias);
    try {
      if (keyStore.getKey(alias, new char[0]) instanceof PrivateKey key) {
        return key;
      }

      throw new SecurityModuleException(
          "Key loaded for alias is not a PrivateKey. Alias: " + alias);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading private key for alias: " + alias, e);
    }
  }

  private static ECPublicKey loadPublicKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading public key for alias: {} ...", alias);
    try {
      final Certificate certificate = keyStore.getCertificate(alias);
      if (certificate == null) {
        throw new SecurityModuleException("Certificate not found for alias: " + alias);
      }

      if (certificate.getPublicKey() instanceof ECPublicKey publicKey) {
        return publicKey;
      }

      throw new SecurityModuleException(
          "Public key loaded is not an ECPublicKey for alias: " + alias);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading public key for alias: " + alias, e);
    }
  }

  @Override
  public void close() {
    Security.removeProvider(provider.getName());
  }
}
