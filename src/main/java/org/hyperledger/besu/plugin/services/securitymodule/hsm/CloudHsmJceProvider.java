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
 * HSM provider that uses the AWS CloudHSM JCE provider. The CloudHSM JCE jar is loaded from a
 * configurable path that defaults to {@code /opt/cloudhsm/java}.
 */
class CloudHsmJceProvider extends JcaHsmProvider {
  private static final Logger LOG = LoggerFactory.getLogger(CloudHsmJceProvider.class);
  private static final String CLOUDHSM_PROVIDER_CLASS =
      "com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider";

  // Value of CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE as documented in the AWS CloudHSM JCE
  // javadoc (v5.17.1). Hardcoded to avoid reflection on the dynamically loaded class.
  private static final String CLOUDHSM_KEYSTORE_TYPE = "CloudHSM";
  private static final String CLOUDHSM_JAR_GLOB = "cloudhsm-*.jar";

  private final URLClassLoader cloudHsmClassLoader;

  /**
   * Bundles the results of JCE provider initialization: the resolved {@link Provider} and the
   * classloader used to load the provider jar.
   */
  private record ProviderInit(Provider provider, URLClassLoader classLoader) {}

  /**
   * Bundles all artifacts produced during full provider + key initialization so they can be passed
   * to the delegating constructor that calls {@code super()}.
   */
  private record InitResult(
      Provider provider,
      PrivateKey privateKey,
      ECPublicKey ecPublicKey,
      URLClassLoader classLoader) {}

  /**
   * Creates a {@link CloudHsmJceProvider} after validating the relevant CLI options.
   *
   * @param cliOptions the parsed CLI options
   * @param curveParams the EC curve parameters
   * @return a new {@link CloudHsmJceProvider} instance
   * @throws SecurityModuleException if required options are missing or initialization fails
   */
  static CloudHsmJceProvider create(
      final HsmCliOptions cliOptions, final EcCurveParameters curveParams) {
    requireNonBlank(cliOptions.getPrivateKeyAlias(), "Private key alias is not provided");
    requireNonBlank(
        cliOptions.getPublicKeyAlias(),
        "Public key alias is required for cloudhsm-jce provider type");
    return new CloudHsmJceProvider(
        cliOptions.getCloudHsmJarPath(),
        cliOptions.getPrivateKeyAlias(),
        cliOptions.getPublicKeyAlias(),
        curveParams);
  }

  private CloudHsmJceProvider(
      final Path jarPath,
      final String privateKeyAlias,
      final String publicKeyAlias,
      final EcCurveParameters curveParams) {
    this(init(jarPath, privateKeyAlias, publicKeyAlias), curveParams);
  }

  private CloudHsmJceProvider(final InitResult result, final EcCurveParameters curveParams) {
    super(result.provider(), result.privateKey(), result.ecPublicKey(), curveParams);
    this.cloudHsmClassLoader = result.classLoader();
  }

  private static InitResult init(
      final Path jarPath, final String privateKeyAlias, final String publicKeyAlias) {
    final ProviderInit providerInit =
        initializeProvider(requireNonNull(jarPath, "jarPath must not be null"));
    final KeyStore keyStore = loadKeyStore();
    final PrivateKey privateKey =
        loadPrivateKey(
            keyStore, requireNonNull(privateKeyAlias, "privateKeyAlias must not be null"));
    final ECPublicKey ecPublicKey =
        loadPublicKey(keyStore, requireNonNull(publicKeyAlias, "publicKeyAlias must not be null"));
    return new InitResult(
        providerInit.provider(), privateKey, ecPublicKey, providerInit.classLoader());
  }

  private static ProviderInit initializeProvider(final Path jarPath) {
    LOG.info("Initializing CloudHSM JCE provider ...");
    try {
      final Path jar = findCloudHsmJar(jarPath);
      final URL jarUrl = jar.toUri().toURL();
      final URLClassLoader classLoader =
          new URLClassLoader(new URL[] {jarUrl}, Thread.currentThread().getContextClassLoader());
      LOG.info("Loaded CloudHSM JCE jar: {}", jar);
      final Class<?> clazz = classLoader.loadClass(CLOUDHSM_PROVIDER_CLASS);
      // addProvider is a no-op if a provider with the same name is already registered.
      // In the Besu plugin context, this plugin is the sole registrant of the CloudHSM provider.
      final Provider newProvider = (Provider) clazz.getDeclaredConstructor().newInstance();
      Security.addProvider(newProvider);
      LOG.info(
          "CloudHSM JCE provider registered: {} v{}",
          newProvider.getName(),
          newProvider.getVersionStr());
      return new ProviderInit(newProvider, classLoader);
    } catch (final SecurityModuleException e) {
      throw e;
    } catch (final Exception e) {
      throw new SecurityModuleException("Error initializing CloudHSM JCE provider", e);
    }
  }

  private static Path findCloudHsmJar(final Path jarPath) {
    if (Files.isRegularFile(jarPath)) {
      LOG.info("Using specified CloudHSM JCE jar: {}", jarPath);
      return jarPath;
    }
    if (!Files.isDirectory(jarPath)) {
      throw new SecurityModuleException(
          "CloudHSM JCE jar path not found: "
              + jarPath
              + ". Install the CloudHSM JCE provider package:"
              + " https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html");
    }
    final List<Path> jars = new ArrayList<>();
    try (final DirectoryStream<Path> stream =
        Files.newDirectoryStream(jarPath, CLOUDHSM_JAR_GLOB)) {
      for (final Path jar : stream) {
        jars.add(jar);
      }
    } catch (final Exception e) {
      throw new SecurityModuleException("Error scanning for CloudHSM JCE jars in " + jarPath, e);
    }
    if (jars.isEmpty()) {
      throw new SecurityModuleException(
          "No CloudHSM JCE jars matching '"
              + CLOUDHSM_JAR_GLOB
              + "' found in "
              + jarPath
              + ". Install the CloudHSM JCE provider package:"
              + " https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html");
    }
    jars.sort(Comparator.comparing(Path::getFileName).reversed());
    if (jars.size() > 1) {
      LOG.warn(
          "Multiple CloudHSM JCE jars found in {}: {}. Using: {}", jarPath, jars, jars.getFirst());
    }
    return jars.getFirst();
  }

  private static KeyStore loadKeyStore() {
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

  private static PrivateKey loadPrivateKey(final KeyStore keyStore, final String alias) {
    LOG.info("Loading private key for alias: {} ...", alias);
    try {
      if (keyStore.getKey(alias, null) instanceof PrivateKey key) {
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
      if (keyStore.getKey(alias, null) instanceof ECPublicKey publicKey) {
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
    super.close();
    if (cloudHsmClassLoader != null) {
      try {
        cloudHsmClassLoader.close();
      } catch (final IOException e) {
        LOG.warn("Error closing CloudHSM classloader: {}", e.getMessage());
      }
    }
  }
}
