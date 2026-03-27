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
import static org.awaitility.Awaitility.await;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.math.BigInteger;
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
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;

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
  private static final String BESU_QBFT_HSM_IMAGE_NAME = "besu-hsm-test";
  private static final Path DOCKER_DIR =
      Path.of(System.getProperty("user.dir"), "docker", "softhsm2");
  private static final Path DIST_DIR =
      Path.of(System.getProperty("user.dir"), "build", "distributions");
  private static final String INSTALL_PLUGIN_CMD =
      "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/";
  private static final int RPC_PORT = 8545;
  private static final int P2P_PORT = 30303;
  private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @TempDir private static Path tempDir;

  private static final Path DIST_ZIP = findDistZip();

  private static ImageFromDockerfile qbftImage;
  private static Network network;
  private static Path sharedDataDir;
  private static List<Path> tokenDirs;
  private static List<String> publicKeys;
  private static List<GenericContainer<?>> besuContainers;

  @BeforeAll
  static void setup() throws Exception {
    qbftImage =
        new ImageFromDockerfile(BESU_QBFT_HSM_IMAGE_NAME, false)
            .withDockerfile(DOCKER_DIR.resolve("Dockerfile"));

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
    // Node-0 starts first as bootnode (no --bootnodes needed).
    // Nodes 1-3 start with --bootnodes pointing to node-0's IP.
    besuContainers = new ArrayList<>();
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
  void besuHelpShowsPluginCliOptions() {
    final ToStringConsumer toStringConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(qbftImage)
            .withCopyFileToContainer(
                MountableFile.forHostPath(DIST_ZIP), "/tmp/besu-hsm-plugin.zip")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/bin/sh", "-c");
                  cmd.withCmd(INSTALL_PLUGIN_CMD + " && /opt/besu/bin/besu --help");
                })
            .withStartupCheckStrategy(
                new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(1)))
            .withLogConsumer(toStringConsumer)) {
      container.start();

      final String logs = toStringConsumer.toUtf8String();
      assertThat(logs).contains("--plugin-pkcs11-hsm-config-path");
      assertThat(logs).contains("--plugin-pkcs11-hsm-password-path");
      assertThat(logs).contains("--plugin-pkcs11-hsm-key-alias");
    }
  }

  @Test
  void qbftNetworkProducesBlocks() {
    await()
        .atMost(Duration.ofSeconds(60))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final long blockNumber = getBlockNumber(besuContainers.get(0));
              assertThat(blockNumber).isGreaterThan(0);
            });
  }

  @Test
  void allNodesReachSameBlock() {
    // Wait for all nodes to produce blocks and agree on the same block height
    await()
        .atMost(Duration.ofSeconds(60))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final long expected = getBlockNumber(besuContainers.get(0));
              assertThat(expected).isGreaterThan(0);
              for (int i = 1; i < besuContainers.size(); i++) {
                assertThat(getBlockNumber(besuContainers.get(i))).isEqualTo(expected);
              }
            });
  }

  @Test
  void allValidatorsAreRecognized() throws Exception {
    final JsonNode result =
        rpcResult(besuContainers.get(0), "qbft_getValidatorsByBlockNumber", "[\"latest\"]");
    assertThat(result.isArray()).isTrue();
    assertThat(result.size()).isEqualTo(NODE_COUNT);
  }

  @Test
  void prefundedAccountHasBalance() throws Exception {
    final JsonNode result =
        rpcResult(
            besuContainers.get(0),
            "eth_getBalance",
            "[\"0xfe3b557e8fb62b89f4916b721be55ceb828dbd73\", \"latest\"]");
    assertThat(new BigInteger(result.asText().substring(2), 16).signum()).isGreaterThan(0);
  }

  @Test
  void valueTransferProducesNonEmptyBlock() throws Exception {
    // Sign and send a value transfer from the prefunded dev account (0xfe3b...).
    // Private key is the well-known Besu dev/test key.
    final Credentials sender =
        Credentials.create("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");

    final JsonNode nonceResult =
        rpcResult(
            besuContainers.get(0),
            "eth_getTransactionCount",
            "[\"" + sender.getAddress() + "\", \"latest\"]");
    final long nonce = Long.decode(nonceResult.asText());

    final RawTransaction rawTx =
        RawTransaction.createEtherTransaction(
            BigInteger.valueOf(nonce),
            BigInteger.valueOf(1_000_000_000L),
            BigInteger.valueOf(21_000),
            "0x627306090abaB3A6e1400e9345bC60c78a8BEf57",
            BigInteger.valueOf(1_000_000_000_000_000_000L));

    final byte[] signedBytes = TransactionEncoder.signMessage(rawTx, 1337, sender);
    final String signedTxHex = Numeric.toHexString(signedBytes);

    final String txHash =
        rpcResult(besuContainers.get(0), "eth_sendRawTransaction", "[\"" + signedTxHex + "\"]")
            .asText();
    assertThat(txHash).startsWith("0x");

    // Wait for the transaction to be mined and verify the block contains it
    await()
        .atMost(Duration.ofSeconds(30))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final JsonNode receipt =
                  rpcResult(
                      besuContainers.get(0), "eth_getTransactionReceipt", "[\"" + txHash + "\"]");
              assertThat(receipt.isNull()).isFalse();
              assertThat(receipt.get("status").asText()).isEqualTo("0x1");

              // Verify the block that mined this tx is non-empty
              final String blockNumber = receipt.get("blockNumber").asText();
              final JsonNode block =
                  rpcResult(
                      besuContainers.get(0),
                      "eth_getBlockByNumber",
                      "[\"" + blockNumber + "\", false]");
              assertThat(block.get("transactions").size()).isGreaterThan(0);
            });
  }

  @AfterAll
  static void teardown() {
    if (besuContainers != null) {
      besuContainers.forEach(GenericContainer::stop);
    }
    if (network != null) {
      network.close();
    }
    // Docker containers create files as root inside bind-mounted temp dirs.
    // Fix permissions so JUnit @TempDir cleanup can delete them.
    if (qbftImage != null && tempDir != null) {
      try (GenericContainer<?> cleanup =
          new GenericContainer<>(qbftImage)
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
        // Best-effort cleanup; don't fail the test suite
      }
    }
  }

  private static long getBlockNumber(final GenericContainer<?> container)
      throws IOException, InterruptedException {
    return Long.decode(rpcResult(container, "eth_blockNumber", "[]").asText());
  }

  private static JsonNode rpcResult(
      final GenericContainer<?> container, final String method, final String params)
      throws IOException, InterruptedException {
    final int port = container.getMappedPort(RPC_PORT);
    final String body =
        String.format(
            "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":1}", method, params);

    final HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create("http://localhost:" + port))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .timeout(Duration.ofSeconds(10))
            .build();

    final String response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString()).body();
    final JsonNode json = MAPPER.readTree(response);
    assertThat(json.has("result"))
        .withFailMessage("RPC error for %s: %s", method, response)
        .isTrue();
    return json.get("result");
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
