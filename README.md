# Besu HSM Plugin
 [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/besu-eth/besu-hsm-plugin/blob/main/LICENSE)
 [![Discord](https://img.shields.io/discord/905194001349627914?logo=Hyperledger&style=plastic)](https://discord.com/invite/hyperledger)

A [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) based Hardware Security Module (HSM) plugin for [Hyperledger Besu](https://github.com/besu-eth/besu). This plugin enables Besu validators to delegate cryptographic signing operations to an HSM via the standard PKCS#11 interface, keeping private keys secure in dedicated hardware rather than in software.

## Architecture

![Besu HSM Plugin Architecture](docs/besu-hsm-plugin-architecture.png)

The plugin sits between the Besu client (validator) and HSM providers using the PKCS#11 interface. It supports:

- **Cloud HSM providers** — Connect to remote HSMs via vendor-specific PKCS#11 libraries (e.g. AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM)
- **Local HSMs** — Connect to on-premise HSM hardware via PKCS#11 libraries
- **Configuration** — Provider selection and authentication (secret/API key) are specified through plugin configuration

## Useful Links

* [Besu User Documentation](https://besu.hyperledger.org)
* [Besu HSM Plugin Issues]
* [Besu Wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/)
* [How to Contribute to Besu](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22156850/How+to+Contribute)
* [Besu Maintainers](https://github.com/besu-eth/besu/blob/main/MAINTAINERS.md)

## Issues

Besu HSM Plugin issues are tracked [in the github issues tab][Besu HSM Plugin Issues].

If you have any questions, queries or comments, [Besu channel on Discord] is the place to find us.

## Besu HSM Plugin Developers

* [Contributing Guidelines]
* [Coding Conventions](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154259/Coding+Conventions)

### Development

Instructions for how to get started with developing on the Besu HSM Plugin codebase. Please also read the
[wiki](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154251/Pull+Requests) for more details on how to submit a pull request (PR).

### Prerequisites

* [Java 21+](https://adoptium.net/)
* [Gradle](https://gradle.org/) (or use the included Gradle wrapper)

### Building

```bash
./gradlew build
```

### Running Tests

```bash
./gradlew test
```

[Besu HSM Plugin Issues]: https://github.com/besu-eth/besu-hsm-plugin/issues
[Besu channel on Discord]: https://discord.com/invite/hyperledger
[Contributing Guidelines]: CONTRIBUTING.md
