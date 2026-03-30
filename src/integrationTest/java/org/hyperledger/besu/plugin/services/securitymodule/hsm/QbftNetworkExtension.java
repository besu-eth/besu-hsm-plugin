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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/**
 * JUnit 5 extension that provisions a 4-node QBFT network with HSM-backed signing using SoftHSM2.
 * Use with {@code @RegisterExtension} as a static field, parameterized by EC curve name.
 *
 * <p>Three-phase setup:
 *
 * <ol>
 *   <li>Generate EC key pairs on each node's SoftHSM2 token
 *   <li>Generate QBFT genesis with validator addresses
 *   <li>Start 4 Besu nodes with QBFT consensus using HSM-backed signing
 * </ol>
 */
class QbftNetworkExtension implements BeforeAllCallback, AfterAllCallback {

  private static final int NODE_COUNT = 4;
  private static final String IMAGE_NAME = "besu-hsm-test";
  private static final Path DOCKER_DIR =
      Path.of(System.getProperty("user.dir"), "docker", "softhsm2");
  private static final Path DIST_DIR =
      Path.of(System.getProperty("user.dir"), "build", "distributions");
  private static final String INSTALL_PLUGIN_CMD =
      "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/";
  static final int RPC_PORT = 8545;
  private static final int P2P_PORT = 30303;

  private final String ecCurve;
  private final boolean discV5Enabled;
  private final Path distZip;

  private ImageFromDockerfile image;
  private Path tempDir;
  private Network network;
  private Path sharedDataDir;
  private List<Path> tokenDirs;
  private List<String> publicKeys;
  private List<GenericContainer<?>> besuContainers;
  private List<ToStringConsumer> nodeLogConsumers;

  QbftNetworkExtension(final String ecCurve) {
    this(ecCurve, false);
  }

  QbftNetworkExtension(final String ecCurve, final boolean discV5Enabled) {
    this.ecCurve = ecCurve;
    this.discV5Enabled = discV5Enabled;
    this.distZip = findDistZip();
  }

  @Override
  public void beforeAll(final ExtensionContext context) throws Exception {
    tempDir = Files.createTempDirectory("qbft-hsm-" + ecCurve);
    image =
        new ImageFromDockerfile(IMAGE_NAME, false).withDockerfile(DOCKER_DIR.resolve("Dockerfile"));
    network = Network.newNetwork();
    sharedDataDir = Files.createDirectory(tempDir.resolve("data"));
    tokenDirs = new ArrayList<>();
    publicKeys = new ArrayList<>();

    // Phase 1: Generate keys on each node's SoftHSM2
    for (int i = 0; i < NODE_COUNT; i++) {
      final Path tokenDir = Files.createDirectory(tempDir.resolve("tokens-" + i));
      tokenDirs.add(tokenDir);
      generateNodeKey(i, tokenDir);
    }

    // Read public keys for enode URL construction
    for (int i = 0; i < NODE_COUNT; i++) {
      final Path pubkeyFile = sharedDataDir.resolve("node-" + i).resolve("pubkey.hex");
      assertThat(pubkeyFile).exists();
      final String pubkey = Files.readString(pubkeyFile).trim();
      assertThat(pubkey).hasSize(128);
      publicKeys.add(pubkey);
    }

    // Phase 2: Generate QBFT genesis
    generateGenesis();
    assertThat(sharedDataDir.resolve("genesis.json")).exists();

    // Phase 3: Start QBFT network
    besuContainers = new ArrayList<>();
    nodeLogConsumers = new ArrayList<>();
    startBootnode();
    final String bootnodeUrl = discV5Enabled ? getBootnodeEnrUrl() : getBootnodeEnodeUrl();
    for (int i = 1; i < NODE_COUNT; i++) {
      startValidatorNode(i, bootnodeUrl);
    }
  }

  @Override
  public void afterAll(final ExtensionContext context) {
    // Always dump Besu logs for debugging — integration tests are slow, logs are valuable
    if (nodeLogConsumers != null) {
      for (int i = 0; i < nodeLogConsumers.size(); i++) {
        System.err.println(
            "=== Besu node-" + i + " logs (" + ecCurve + ", discV5=" + discV5Enabled + ") ===");
        System.err.println(nodeLogConsumers.get(i).toUtf8String());
        System.err.println("=== End node-" + i + " logs ===");
      }
    }
    if (besuContainers != null) {
      besuContainers.forEach(GenericContainer::stop);
    }
    if (network != null) {
      network.close();
    }
    // Docker containers create files as root inside bind-mounted temp dirs.
    // Fix permissions then delete the temp directory.
    if (image != null && tempDir != null) {
      try (GenericContainer<?> cleanup =
          new GenericContainer<>(image)
              .withFileSystemBind(tempDir.toString(), "/cleanup")
              .withCreateContainerCmdModifier(
                  cmd -> {
                    cmd.withEntrypoint("/bin/sh", "-c");
                    cmd.withCmd("chmod -R 777 /cleanup");
                  })
              .withStartupCheckStrategy(
                  new OneShotStartupCheckStrategy().withTimeout(Duration.ofSeconds(30)))) {
        cleanup.start();
      } catch (final Exception e) {
        // Best-effort permission fix
      }
      deleteDirectory(tempDir);
    }
  }

  private static void deleteDirectory(final Path dir) {
    try (var paths = Files.walk(dir)) {
      paths.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
    } catch (final IOException e) {
      // Best-effort cleanup
    }
  }

  String getEcCurve() {
    return ecCurve;
  }

  ImageFromDockerfile getImage() {
    return image;
  }

  Path getDistZip() {
    return distZip;
  }

  GenericContainer<?> getContainer(final int index) {
    return besuContainers.get(index);
  }

  List<GenericContainer<?>> getContainers() {
    return Collections.unmodifiableList(besuContainers);
  }

  int getNodeCount() {
    return NODE_COUNT;
  }

  String getNodeLogs(final int index) {
    if (nodeLogConsumers != null && index < nodeLogConsumers.size()) {
      return nodeLogConsumers.get(index).toUtf8String();
    }
    return "";
  }

  private void generateNodeKey(final int nodeIndex, final Path tokenDir) {
    final ToStringConsumer logConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(image)
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withFileSystemBind(tokenDir.toString(), "/var/lib/tokens")
            .withEnv("EC_CURVE", ecCurve)
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/entrypoint-setup.sh");
                  cmd.withCmd(String.valueOf(nodeIndex));
                })
            .withStartupCheckStrategy(
                new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))
            .withLogConsumer(logConsumer)) {
      container.start();
    }

    assertThat(logConsumer.toUtf8String()).contains("Setup complete");
  }

  private void generateGenesis() {
    final ToStringConsumer logConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(image)
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withEnv("EC_CURVE", ecCurve)
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/generate-genesis.sh");
                  cmd.withCmd(String.valueOf(NODE_COUNT));
                })
            .withStartupCheckStrategy(
                new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))
            .withLogConsumer(logConsumer)) {
      container.start();
    }

    assertThat(logConsumer.toUtf8String()).contains("Genesis generation complete");
  }

  private void startBootnode() {
    startNode(0, null);
  }

  private String getBootnodeEnodeUrl() {
    final ContainerState bootnode = besuContainers.get(0);
    final String bootnodeIp =
        besuContainers
            .get(0)
            .getContainerInfo()
            .getNetworkSettings()
            .getNetworks()
            .values()
            .iterator()
            .next()
            .getIpAddress();
    return "enode://" + publicKeys.get(0) + "@" + bootnodeIp + ":" + P2P_PORT;
  }

  private String getBootnodeEnrUrl() {
    try {
      final GenericContainer<?> bootnode = besuContainers.get(0);
      final int port = bootnode.getMappedPort(RPC_PORT);
      final String body =
          "{\"jsonrpc\":\"2.0\",\"method\":\"admin_nodeInfo\",\"params\":[],\"id\":1}";
      final HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create("http://localhost:" + port))
              .header("Content-Type", "application/json")
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .timeout(Duration.ofSeconds(10))
              .build();
      final String response =
          HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
      final JsonNode json = new ObjectMapper().readTree(response);
      assertThat(json.has("result"))
          .withFailMessage("admin_nodeInfo RPC error: %s", response)
          .isTrue();
      final String enr = json.get("result").get("enr").asText();
      assertThat(enr).startsWith("enr:");
      return enr;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to get ENR from bootnode via admin_nodeInfo", e);
    }
  }

  private void startValidatorNode(final int nodeIndex, final String bootnodeUrl) {
    startNode(nodeIndex, bootnodeUrl);
  }

  private void startNode(final int nodeIndex, final String bootnodeUrl) {
    final ToStringConsumer logConsumer = new ToStringConsumer();

    final GenericContainer<?> container =
        new GenericContainer<>(image)
            .withNetwork(network)
            .withNetworkAliases("besu-node-" + nodeIndex)
            .withExposedPorts(RPC_PORT, P2P_PORT)
            .withFileSystemBind(tokenDirs.get(nodeIndex).toString(), "/var/lib/tokens")
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withCopyFileToContainer(MountableFile.forHostPath(distZip), "/tmp/besu-hsm-plugin.zip")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/bin/sh", "-c");
                  cmd.withCmd(besuCommand(bootnodeUrl));
                })
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Ethereum main loop is up.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    container.start();
    besuContainers.add(container);
    nodeLogConsumers.add(logConsumer);
  }

  private String besuCommand(final String bootnodeUrl) {
    final StringBuilder cmd = new StringBuilder();
    cmd.append(INSTALL_PLUGIN_CMD);
    if (discV5Enabled) {
      // Resolve container's own Docker network IP at runtime for --p2p-host
      // so that ENR records contain the correct routable IP address
      // grep for IPv4 pattern to avoid picking up an IPv6 address
      cmd.append(
          " && export MY_IP=$(grep -oE '\\b[0-9]{1,3}(\\.[0-9]{1,3}){3}\\b' /etc/hosts"
              + " | grep -v '^127\\.' | head -1)");
    }
    cmd.append(" && /entrypoint-besu.sh");
    cmd.append(" --genesis-file=/data/genesis.json");
    cmd.append(" --security-module=pkcs11-hsm");
    cmd.append(" --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg");
    cmd.append(" --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt");
    cmd.append(" --plugin-pkcs11-hsm-key-alias=testkey");
    cmd.append(" --plugin-pkcs11-hsm-ec-curve=").append(ecCurve);
    cmd.append(" --rpc-http-enabled");
    cmd.append(" --rpc-http-api=ETH,NET,QBFT,ADMIN");
    cmd.append(" --rpc-http-host=0.0.0.0");
    cmd.append(" --host-allowlist=*");
    if (discV5Enabled) {
      cmd.append(" --p2p-host=$MY_IP");
    }
    cmd.append(" --p2p-port=").append(P2P_PORT);
    cmd.append(" --min-gas-price=0");
    cmd.append(" --profile=ENTERPRISE");
    if (discV5Enabled) {
      cmd.append(" --Xv5-discovery-enabled=true");
    }
    if (bootnodeUrl != null) {
      cmd.append(" --bootnodes=").append(bootnodeUrl);
    }
    return cmd.toString();
  }

  private static Path findDistZip() {
    try (var stream = Files.newDirectoryStream(DIST_DIR, "besu-hsm-plugin*.zip")) {
      for (final Path path : stream) {
        return path;
      }
    } catch (final IOException e) {
      // Fall through
    }
    throw new IllegalStateException(
        "Plugin distribution zip not found in " + DIST_DIR + ". Run ./gradlew distZip first.");
  }
}
