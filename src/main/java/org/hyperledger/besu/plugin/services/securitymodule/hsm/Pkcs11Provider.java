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

import java.io.IOException;
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
class Pkcs11Provider implements HsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11Provider.class);

  private final Provider provider;
  private final PrivateKey privateKey;
  private final ECPublicKey ecPublicKey;

  /**
   * Creates a new PKCS#11 provider, initializing the SunPKCS11 provider and loading keys.
   *
   * @param configPath path to the PKCS#11 configuration file
   * @param passwordPath path to the file containing the token PIN/password
   * @param keyAlias alias of the key pair stored on the PKCS#11 token
   * @throws SecurityModuleException if any parameter is null/blank or initialization fails
   */
  Pkcs11Provider(final Path configPath, final Path passwordPath, final String keyAlias) {
    if (configPath == null) {
      throw new SecurityModuleException("PKCS#11 configuration file path must not be null");
    }
    if (passwordPath == null) {
      throw new SecurityModuleException("PKCS#11 password file path must not be null");
    }
    if (keyAlias == null || keyAlias.isBlank()) {
      throw new SecurityModuleException("PKCS#11 key alias must not be null or empty");
    }
    this.provider = initializeProvider(configPath);
    final KeyStore keyStore = loadKeyStore(passwordPath);
    this.privateKey = loadPrivateKey(keyStore, keyAlias);
    this.ecPublicKey = loadPublicKey(keyStore, keyAlias);
  }

  private Provider initializeProvider(final Path configPath) {
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

  private KeyStore loadKeyStore(final Path passwordPath) {
    LOG.info("Loading PKCS#11 keystore ...");
    final byte[] passwordBytes;
    try {
      passwordBytes = Files.readAllBytes(passwordPath);
    } catch (final IOException e) {
      throw new SecurityModuleException("Error reading password file: " + passwordPath, e);
    }

    final char[] password =
        new String(passwordBytes, java.nio.charset.StandardCharsets.UTF_8).trim().toCharArray();
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

  private PrivateKey loadPrivateKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading private key for alias: {} ...", alias);
    try {
      final java.security.Key key = keyStore.getKey(alias, new char[0]);
      if (!(key instanceof PrivateKey)) {
        throw new SecurityModuleException(
            "Key loaded for alias is not a PrivateKey. Alias: " + alias);
      }
      return (PrivateKey) key;
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading private key for alias: " + alias, e);
    }
  }

  private ECPublicKey loadPublicKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading public key for alias: {} ...", alias);
    try {
      final Certificate certificate = keyStore.getCertificate(alias);
      if (certificate == null) {
        throw new SecurityModuleException("Certificate not found for alias: " + alias);
      }
      final java.security.PublicKey publicKey = certificate.getPublicKey();
      if (!(publicKey instanceof ECPublicKey)) {
        throw new SecurityModuleException(
            "Public key loaded is not an ECPublicKey for alias: " + alias);
      }
      return (ECPublicKey) publicKey;
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading public key for alias: " + alias, e);
    }
  }

  @Override
  public void removeProvider() {
    Security.removeProvider(provider.getName());
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  @Override
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  @Override
  public ECPublicKey getEcPublicKey() {
    return ecPublicKey;
  }
}
