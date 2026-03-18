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

import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
class BesuContainerIntegrationTest {

  private static final String BESU_HSM_IMAGE_NAME = "besu-hsm-test";
  private static final String BESU_VERSION = "26.2.0";
  private static final Path DOCKER_DIR =
      Path.of(System.getProperty("user.dir"), "docker", "softhsm");
  private static final Path DIST_ZIP =
      Path.of(System.getProperty("user.dir"), "build", "distributions", "besu-hsm-plugin.zip");

  private static final String INSTALL_PLUGIN_CMD =
      "unzip -o -j /tmp/besu-hsm-plugin.zip -d /opt/besu/plugins/";

  private static ImageFromDockerfile besuHsmImage;

  @BeforeAll
  static void buildImage() {
    besuHsmImage =
        new ImageFromDockerfile(BESU_HSM_IMAGE_NAME, false)
            .withBuildArg("BESU_VERSION", BESU_VERSION)
            .withDockerfile(DOCKER_DIR.resolve("Dockerfile"));
  }

  @Test
  void besuHelpShowsPluginCliOptions() {
    final ToStringConsumer toStringConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(besuHsmImage)
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
  void besuStartsWithPkcs11SecurityModule() {
    final ToStringConsumer toStringConsumer = new ToStringConsumer();

    try (GenericContainer<?> container =
        new GenericContainer<>(besuHsmImage)
            .withCopyFileToContainer(
                MountableFile.forHostPath(DIST_ZIP), "/tmp/besu-hsm-plugin.zip")
            .withCreateContainerCmdModifier(
                cmd -> {
                  cmd.withEntrypoint("/bin/sh", "-c");
                  cmd.withCmd(
                      INSTALL_PLUGIN_CMD
                          + " && /entrypoint.sh"
                          + " --network=dev"
                          + " --discovery-enabled=false"
                          + " --security-module=pkcs11-hsm"
                          + " --plugin-pkcs11-hsm-config-path=/etc/besu/config/pkcs11-softhsm.cfg"
                          + " --plugin-pkcs11-hsm-password-path=/etc/besu/config/pkcs11-hsm-password.txt"
                          + " --plugin-pkcs11-hsm-key-alias=testkey");
                })
            .withLogConsumer(toStringConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Ethereum main loop is up.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(3)))) {
      container.start();

      final String logs = toStringConsumer.toUtf8String();
      assertThat(logs).contains("Registering PKCS#11 HSM plugin");
      assertThat(logs).doesNotContain("SecurityModuleException");
    }
  }
}
