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
import java.util.Comparator;
import java.util.List;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HSM provider that uses the AWS CloudHSM JCE provider. The CloudHSM JCE jar is loaded from the
 * standard installation path {@code /opt/cloudhsm/java}.
 */
class CloudHsmJceProvider implements HsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(CloudHsmJceProvider.class);
  private static final String CLOUDHSM_PROVIDER_CLASS =
      "com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider";
  private static final String CLOUDHSM_KEYSTORE_TYPE_FIELD = "CLOUDHSM_KEYSTORE_TYPE";
  private static final Path CLOUDHSM_JAR_DIR = Path.of("/opt/cloudhsm/java");
  private static final String CLOUDHSM_JAR_GLOB = "cloudhsm-*.jar";

  private final Provider provider;
  private final boolean ownsProvider;
  private final String keystoreType;
  private final PrivateKey privateKey;
  private final ECPublicKey ecPublicKey;
  private URLClassLoader cloudHsmClassLoader;

  private record ProviderInit(Provider provider, boolean ownsProvider, String keystoreType) {}

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
    final ProviderInit init = initializeProvider();
    this.provider = init.provider();
    this.ownsProvider = init.ownsProvider();
    this.keystoreType = init.keystoreType();
    final KeyStore keyStore = loadKeyStore();
    this.privateKey = loadPrivateKey(keyStore, privateKeyAlias);
    this.ecPublicKey = loadPublicKey(keyStore, publicKeyAlias);
  }

  private ProviderInit initializeProvider() {
    LOG.info("Initializing CloudHSM JCE provider ...");
    try {
      final Class<?> clazz = loadCloudHsmProviderClass();
      final String keystoreType = (String) clazz.getField(CLOUDHSM_KEYSTORE_TYPE_FIELD).get(null);
      final Provider newProvider = (Provider) clazz.getDeclaredConstructor().newInstance();
      final Provider existingProvider = Security.getProvider(newProvider.getName());
      if (existingProvider != null) {
        LOG.info(
            "Reusing already registered CloudHSM JCE provider: {} v{}",
            existingProvider.getName(),
            existingProvider.getVersionStr());
        return new ProviderInit(existingProvider, false, keystoreType);
      }
      Security.addProvider(newProvider);
      LOG.info(
          "CloudHSM JCE provider registered: {} v{}",
          newProvider.getName(),
          newProvider.getVersionStr());
      return new ProviderInit(newProvider, true, keystoreType);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error initializing CloudHSM JCE provider", e);
    }
  }

  private Class<?> loadCloudHsmProviderClass() {
    final Path jar = findCloudHsmJar();
    try {
      final URL jarUrl = jar.toUri().toURL();
      this.cloudHsmClassLoader =
          new URLClassLoader(new URL[] {jarUrl}, Thread.currentThread().getContextClassLoader());
      LOG.info("Loaded CloudHSM JCE jar: {}", jar);
      return cloudHsmClassLoader.loadClass(CLOUDHSM_PROVIDER_CLASS);
    } catch (final ClassNotFoundException e) {
      throw new SecurityModuleException("CloudHSM JCE provider class not found in jar: " + jar, e);
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading CloudHSM JCE jar: " + jar, e);
    }
  }

  private static Path findCloudHsmJar() {
    if (!Files.isDirectory(CLOUDHSM_JAR_DIR)) {
      throw new SecurityModuleException(
          "CloudHSM JCE jar directory not found: "
              + CLOUDHSM_JAR_DIR
              + ". Install the CloudHSM JCE provider package:"
              + " https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html");
    }
    final List<Path> jars = new ArrayList<>();
    try (final DirectoryStream<Path> stream =
        Files.newDirectoryStream(CLOUDHSM_JAR_DIR, CLOUDHSM_JAR_GLOB)) {
      for (final Path jar : stream) {
        jars.add(jar);
      }
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error scanning for CloudHSM JCE jars in " + CLOUDHSM_JAR_DIR, e);
    }
    if (jars.isEmpty()) {
      throw new SecurityModuleException(
          "No CloudHSM JCE jars matching '"
              + CLOUDHSM_JAR_GLOB
              + "' found in "
              + CLOUDHSM_JAR_DIR
              + ". Install the CloudHSM JCE provider package:"
              + " https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html");
    }
    jars.sort(Comparator.comparing(Path::getFileName).reversed());
    if (jars.size() > 1) {
      LOG.warn(
          "Multiple CloudHSM JCE jars found in {}: {}. Using: {}",
          CLOUDHSM_JAR_DIR,
          jars,
          jars.getFirst());
    }
    return jars.getFirst();
  }

  private KeyStore loadKeyStore() {
    LOG.info("Loading CloudHSM keystore ...");
    try {
      final KeyStore keyStore = KeyStore.getInstance(keystoreType);
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
    if (ownsProvider) {
      Security.removeProvider(provider.getName());
    }
    if (cloudHsmClassLoader != null) {
      try {
        cloudHsmClassLoader.close();
      } catch (final IOException e) {
        LOG.warn("Error closing CloudHSM classloader: {}", e.getMessage());
      }
    }
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
