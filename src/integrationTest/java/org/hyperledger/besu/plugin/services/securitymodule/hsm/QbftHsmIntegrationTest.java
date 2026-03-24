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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Integration test that runs a 4-node QBFT network where each validator uses the PKCS#11 HSM
 * security module (SoftHSM2) for block signing.
 *
 * <p>Three-phase setup:
 *
 * <ol>
 *   <li>Generate EC key pairs on each node's SoftHSM2 token
 *   <li>Generate QBFT genesis with validator addresses using {@code besu operator
 *       generate-blockchain-config}
 *   <li>Start 4 Besu nodes with QBFT consensus using HSM-backed signing
 * </ol>
 *
 * <p>Requires a Besu version that includes the besu-native-ec static OpenSSL fix
 * (https://github.com/besu-eth/besu/pull/10096).
 */
@Testcontainers
class QbftHsmIntegrationTest {

  private static final int NODE_COUNT = 4;
  private static final String BESU_QBFT_HSM_IMAGE_NAME = "besu-qbft-hsm-test";
  private static final Path DOCKER_DIR =
      Path.of(System.getProperty("user.dir"), "docker", "qbft-softhsm2");
  private static final Path DIST_ZIP =
      Path.of(System.getProperty("user.dir"), "build", "distributions", "besu-hsm-plugin.zip");
  private static final String INSTALL_PLUGIN_CMD =
      "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/";
  private static final int RPC_PORT = 8545;
  private static final int P2P_PORT = 30303;

  private static ImageFromDockerfile qbftImage;
  private static Network network;
  private static Path sharedDataDir;
  private static List<Path> tokenDirs;
  private static List<String> publicKeys;
  private static List<GenericContainer<?>> besuContainers;
  private static List<ToStringConsumer> logConsumers;

  @BeforeAll
  static void setup() throws Exception {
    qbftImage =
        new ImageFromDockerfile(BESU_QBFT_HSM_IMAGE_NAME, false)
            .withDockerfile(DOCKER_DIR.resolve("Dockerfile"));

    network = Network.newNetwork();
    sharedDataDir = Files.createTempDirectory("qbft-hsm-data");
    tokenDirs = new ArrayList<>();
    publicKeys = new ArrayList<>();

    // Phase 1: Generate keys on each node's SoftHSM2
    for (int i = 0; i < NODE_COUNT; i++) {
      final Path tokenDir = Files.createTempDirectory("qbft-hsm-tokens-" + i);
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
    // Node-0 starts first as bootnode (no --bootnodes needed).
    // Nodes 1-3 start with --bootnodes pointing to node-0's IP.
    besuContainers = new ArrayList<>();
    logConsumers = new ArrayList<>();
    startBootnode();
    final String bootnodeEnodeUrl = getBootnodeEnodeUrl();
    for (int i = 1; i < NODE_COUNT; i++) {
      startValidatorNode(i, bootnodeEnodeUrl);
    }
  }

  private static void generateNodeKey(final int nodeIndex, final Path tokenDir) {
    final ToStringConsumer logConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(qbftImage)
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withFileSystemBind(tokenDir.toString(), "/var/lib/tokens")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withUser("root");
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

  private static void generateGenesis() {
    final ToStringConsumer logConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(qbftImage)
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withUser("root");
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

  /** Starts node-0 as the bootnode (no --bootnodes flag). */
  private static void startBootnode() {
    final ToStringConsumer logConsumer = new ToStringConsumer();
    logConsumers.add(logConsumer);

    final GenericContainer<?> container =
        new GenericContainer<>(qbftImage)
            .withNetwork(network)
            .withNetworkAliases("besu-node-0")
            .withExposedPorts(RPC_PORT, P2P_PORT)
            .withFileSystemBind(tokenDirs.get(0).toString(), "/var/lib/tokens")
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withCopyFileToContainer(
                MountableFile.forHostPath(DIST_ZIP), "/tmp/besu-hsm-plugin.zip")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/bin/sh", "-c");
                  cmd.withCmd(besuCommand(null));
                })
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Ethereum main loop is up.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    container.start();
    besuContainers.add(container);
  }

  /**
   * Returns the enode URL for node-0 using its container IP address. QBFT/Ethereum requires IP
   * addresses in enode URLs, not hostnames.
   */
  private static String getBootnodeEnodeUrl() {
    final ContainerState bootnode = besuContainers.get(0);
    final String bootnodeIp =
        bootnode
            .getContainerInfo()
            .getNetworkSettings()
            .getNetworks()
            .values()
            .iterator()
            .next()
            .getIpAddress();
    return "enode://" + publicKeys.get(0) + "@" + bootnodeIp + ":" + P2P_PORT;
  }

  /** Starts a validator node with --bootnodes pointing to the bootnode. */
  private static void startValidatorNode(final int nodeIndex, final String bootnodeEnodeUrl) {
    final ToStringConsumer logConsumer = new ToStringConsumer();
    logConsumers.add(logConsumer);

    final GenericContainer<?> container =
        new GenericContainer<>(qbftImage)
            .withNetwork(network)
            .withNetworkAliases("besu-node-" + nodeIndex)
            .withExposedPorts(RPC_PORT, P2P_PORT)
            .withFileSystemBind(tokenDirs.get(nodeIndex).toString(), "/var/lib/tokens")
            .withFileSystemBind(sharedDataDir.toString(), "/data")
            .withCopyFileToContainer(
                MountableFile.forHostPath(DIST_ZIP), "/tmp/besu-hsm-plugin.zip")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/bin/sh", "-c");
                  cmd.withCmd(besuCommand(bootnodeEnodeUrl));
                })
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Ethereum main loop is up.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    container.start();
    besuContainers.add(container);
  }

  private static String besuCommand(final String bootnodeEnodeUrl) {
    final StringBuilder cmd = new StringBuilder();
    cmd.append(INSTALL_PLUGIN_CMD);
    cmd.append(" && /entrypoint-besu.sh");
    cmd.append(" --genesis-file=/data/genesis.json");
    cmd.append(" --security-module=pkcs11-hsm");
    cmd.append(" --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg");
    cmd.append(" --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt");
    cmd.append(" --plugin-pkcs11-hsm-key-alias=testkey");
    cmd.append(" --rpc-http-enabled");
    cmd.append(" --rpc-http-api=ETH,NET,QBFT");
    cmd.append(" --rpc-http-host=0.0.0.0");
    cmd.append(" --host-allowlist=*");
    cmd.append(" --p2p-port=").append(P2P_PORT);
    cmd.append(" --min-gas-price=0");
    cmd.append(" --profile=ENTERPRISE");
    if (bootnodeEnodeUrl != null) {
      cmd.append(" --bootnodes=").append(bootnodeEnodeUrl);
    }
    return cmd.toString();
  }

  @Test
  void qbftNetworkProducesBlocks() throws Exception {
    // Poll for block production — QBFT may need time to complete its first round
    long blockNumber = 0;
    for (int attempt = 0; attempt < 30; attempt++) {
      Thread.sleep(2_000);
      final String response = jsonRpcCall(besuContainers.get(0), "eth_blockNumber", "[]");
      assertThat(response).contains("result");

      final String blockHex = response.replaceAll(".*\"result\":\"(0x[0-9a-fA-F]+)\".*", "$1");
      blockNumber = Long.parseLong(blockHex.substring(2), 16);
      if (blockNumber > 0) {
        break;
      }
    }
    assertThat(blockNumber).isGreaterThan(0);
  }

  @Test
  void allValidatorsAreRecognized() throws Exception {
    final String response =
        jsonRpcCall(besuContainers.get(0), "qbft_getValidatorsByBlockNumber", "[\"latest\"]");
    assertThat(response).contains("result");

    // Extract the result array and count validator addresses
    final String resultArray =
        response.replaceAll(".*\"result\":\\[([^\\]]*)\\].*", "$1").toLowerCase();
    final String[] addresses = resultArray.split(",");
    assertThat(addresses).hasSize(NODE_COUNT);
  }

  @Test
  void prefundedAccountHasBalance() throws Exception {
    final String response =
        jsonRpcCall(
            besuContainers.get(0),
            "eth_getBalance",
            "[\"0xfe3b557e8fb62b89f4916b721be55ceb828dbd73\", \"latest\"]");
    assertThat(response).contains("result");
    assertThat(response).contains("0xad78ebc5ac6200000");
  }

  @AfterAll
  static void teardown() {
    if (besuContainers != null) {
      besuContainers.forEach(GenericContainer::stop);
    }
    if (network != null) {
      network.close();
    }
  }

  private static String jsonRpcCall(
      final GenericContainer<?> container, final String method, final String params)
      throws IOException, InterruptedException {
    final int port = container.getMappedPort(RPC_PORT);
    final String body =
        String.format(
            "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":1}", method, params);

    final HttpClient client = HttpClient.newHttpClient();
    final HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create("http://localhost:" + port))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .timeout(Duration.ofSeconds(10))
            .build();

    return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
  }
}
