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

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HSM provider that uses the AWS CloudHSM JCE provider. The CloudHSM JCE jar is auto-loaded from
 * {@code /opt/cloudhsm/java} if not already on the classpath.
 */
class CloudHsmJceProvider implements HsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(CloudHsmJceProvider.class);
  private static final String CLOUDHSM_PROVIDER_CLASS =
      "com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider";
  private static final String CLOUDHSM_KEYSTORE_TYPE = "CloudHSM";
  private static final Path CLOUDHSM_JAR_DIR = Path.of("/opt/cloudhsm/java");
  private static final String CLOUDHSM_JAR_GLOB = "cloudhsm-jce-*.jar";

  private final Provider provider;
  private final PrivateKey privateKey;
  private final ECPublicKey ecPublicKey;

  /**
   * Creates a new CloudHSM JCE provider, initializing the provider and loading keys from the HSM.
   *
   * @param privateKeyAlias alias of the private key stored in CloudHSM
   * @param publicKeyAlias alias of the public key stored in CloudHSM
   * @throws SecurityModuleException if aliases are blank or key loading fails
   */
  CloudHsmJceProvider(final String privateKeyAlias, final String publicKeyAlias) {
    if (privateKeyAlias == null || privateKeyAlias.isBlank()) {
      throw new SecurityModuleException("Private key alias must not be null or empty");
    }
    if (publicKeyAlias == null || publicKeyAlias.isBlank()) {
      throw new SecurityModuleException("Public key alias must not be null or empty");
    }
    this.provider = initializeProvider();
    final KeyStore keyStore = loadKeyStore();
    this.privateKey = loadPrivateKey(keyStore, privateKeyAlias);
    this.ecPublicKey = loadPublicKey(keyStore, publicKeyAlias);
  }

  private Provider initializeProvider() {
    LOG.info("Initializing CloudHSM JCE provider ...");
    try {
      final Class<?> clazz = loadCloudHsmProviderClass();
      final Provider cloudHsmProvider = (Provider) clazz.getDeclaredConstructor().newInstance();
      if (Security.getProvider(cloudHsmProvider.getName()) == null) {
        Security.addProvider(cloudHsmProvider);
      }
      LOG.info(
          "CloudHSM JCE provider registered: {} v{}",
          cloudHsmProvider.getName(),
          cloudHsmProvider.getVersionStr());
      return cloudHsmProvider;
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error initializing CloudHSM JCE provider", e);
    }
  }

  private Class<?> loadCloudHsmProviderClass() {
    // First, try loading from the existing classpath (e.g., jar in Besu plugins/ directory)
    try {
      return Class.forName(CLOUDHSM_PROVIDER_CLASS);
    } catch (final ClassNotFoundException e) {
      LOG.debug(
          "CloudHSM JCE provider not found on classpath, attempting auto-load from {}",
          CLOUDHSM_JAR_DIR);
    }

    // Auto-load from default CloudHSM installation path
    final List<Path> foundJars = findCloudHsmJars();
    if (foundJars.isEmpty()) {
      throw new SecurityModuleException(
          "CloudHSM JCE provider jar not found on classpath or in "
              + CLOUDHSM_JAR_DIR
              + ". Install the CloudHSM JCE provider package"
              + " or copy the jar to Besu's plugins/ directory.");
    }

    try {
      final URL[] jarUrls =
          foundJars.stream()
              .map(
                  p -> {
                    try {
                      return p.toUri().toURL();
                    } catch (final Exception e) {
                      throw new SecurityModuleException(
                          "Error converting jar path to URL: " + p, e);
                    }
                  })
              .toArray(URL[]::new);

      final URLClassLoader cloudHsmClassLoader =
          new URLClassLoader(jarUrls, Thread.currentThread().getContextClassLoader());
      LOG.info("Auto-loaded CloudHSM JCE jar from {}", foundJars.getFirst());
      return cloudHsmClassLoader.loadClass(CLOUDHSM_PROVIDER_CLASS);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final ClassNotFoundException e) {
      throw new SecurityModuleException(
          "CloudHSM JCE provider class not found in jars at " + CLOUDHSM_JAR_DIR, e);
    }
  }

  private static List<Path> findCloudHsmJars() {
    final List<Path> jars = new ArrayList<>();
    if (!Files.isDirectory(CLOUDHSM_JAR_DIR)) {
      return jars;
    }
    try (final DirectoryStream<Path> stream =
        Files.newDirectoryStream(CLOUDHSM_JAR_DIR, CLOUDHSM_JAR_GLOB)) {
      for (final Path jar : stream) {
        jars.add(jar);
      }
    } catch (final Exception e) {
      LOG.warn("Error scanning for CloudHSM JCE jars in {}: {}", CLOUDHSM_JAR_DIR, e.getMessage());
    }
    return jars;
  }

  private KeyStore loadKeyStore() {
    LOG.info("Loading CloudHSM keystore ...");
    try {
      final KeyStore keyStore = KeyStore.getInstance(CLOUDHSM_KEYSTORE_TYPE);
      keyStore.load(null, null);
      return keyStore;
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error loading CloudHSM keystore."
              + " Ensure HSM_USER and HSM_PASSWORD are set as environment variables"
              + " or system properties.",
          e);
    }
  }

  private PrivateKey loadPrivateKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading private key for alias: {} ...", alias);
    try {
      final java.security.Key key = keyStore.getKey(alias, null);
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
      final java.security.Key key = keyStore.getKey(alias, null);
      if (!(key instanceof ECPublicKey)) {
        throw new SecurityModuleException(
            "Key loaded for alias is not an ECPublicKey. Alias: " + alias);
      }
      return (ECPublicKey) key;
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
