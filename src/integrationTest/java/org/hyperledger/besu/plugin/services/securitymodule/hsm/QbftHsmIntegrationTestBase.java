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
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.utility.MountableFile;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;

/**
 * Base class for QBFT HSM integration tests. Subclasses provide a {@link QbftNetworkExtension} via
 * {@code @RegisterExtension} that manages the 4-node QBFT network lifecycle.
 */
abstract class QbftHsmIntegrationTestBase {

  private static final String INSTALL_PLUGIN_CMD =
      "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/";
  private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** Subclasses return their {@link QbftNetworkExtension} instance. */
  abstract QbftNetworkExtension network();

  @Test
  void besuHelpShowsPluginCliOptions() {
    final ToStringConsumer toStringConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(network().getImage())
            .withCopyFileToContainer(
                MountableFile.forHostPath(network().getDistZip()), "/tmp/besu-hsm-plugin.zip")
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
      assertThat(logs).contains("--plugin-hsm-config-path");
      assertThat(logs).contains("--plugin-hsm-password-path");
      assertThat(logs).contains("--plugin-hsm-key-alias");
      assertThat(logs).contains("--plugin-hsm-ec-curve");
    }
  }

  @Test
  void qbftNetworkProducesBlocks() {
    await()
        .atMost(Duration.ofSeconds(60))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final long blockNumber = getBlockNumber(network().getContainer(0));
              assertThat(blockNumber).isGreaterThan(0);
            });
  }

  @Test
  void allNodesReachSameBlock() {
    await()
        .atMost(Duration.ofSeconds(60))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final long expected = getBlockNumber(network().getContainer(0));
              assertThat(expected).isGreaterThan(0);
              for (int i = 1; i < network().getContainers().size(); i++) {
                assertThat(getBlockNumber(network().getContainer(i))).isEqualTo(expected);
              }
            });
  }

  @Test
  void allValidatorsAreRecognized() throws Exception {
    final JsonNode result =
        rpcResult(network().getContainer(0), "qbft_getValidatorsByBlockNumber", "[\"latest\"]");
    assertThat(result.isArray()).isTrue();
    assertThat(result.size()).isEqualTo(network().getNodeCount());
  }

  @Test
  void prefundedAccountHasBalance() throws Exception {
    final JsonNode result =
        rpcResult(
            network().getContainer(0),
            "eth_getBalance",
            "[\"0xfe3b557e8fb62b89f4916b721be55ceb828dbd73\", \"latest\"]");
    assertThat(new BigInteger(result.asText().substring(2), 16).signum()).isGreaterThan(0);
  }

  @Test
  void valueTransferProducesNonEmptyBlock() throws Exception {
    final Credentials sender =
        Credentials.create("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");

    final JsonNode nonceResult =
        rpcResult(
            network().getContainer(0),
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
        rpcResult(network().getContainer(0), "eth_sendRawTransaction", "[\"" + signedTxHex + "\"]")
            .asText();
    assertThat(txHash).startsWith("0x");

    await()
        .atMost(Duration.ofSeconds(30))
        .pollInterval(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              final JsonNode receipt =
                  rpcResult(
                      network().getContainer(0),
                      "eth_getTransactionReceipt",
                      "[\"" + txHash + "\"]");
              assertThat(receipt.isNull()).isFalse();
              assertThat(receipt.get("status").asText()).isEqualTo("0x1");

              final String blockNumber = receipt.get("blockNumber").asText();
              final JsonNode block =
                  rpcResult(
                      network().getContainer(0),
                      "eth_getBlockByNumber",
                      "[\"" + blockNumber + "\", false]");
              assertThat(block.get("transactions").size()).isGreaterThan(0);
            });
  }

  private static long getBlockNumber(final GenericContainer<?> container)
      throws IOException, InterruptedException {
    return Long.decode(rpcResult(container, "eth_blockNumber", "[]").asText());
  }

  static JsonNode rpcResult(
      final GenericContainer<?> container, final String method, final String params)
      throws IOException, InterruptedException {
    final int port = container.getMappedPort(QbftNetworkExtension.RPC_PORT);
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
}
