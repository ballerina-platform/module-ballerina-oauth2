# Change Log
This file contains all the notable changes done to the Ballerina OAuth2 package through the releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0-alpha6] - 2021-04-02

### Changed
- Remove usages of `checkpanic` for type narrowing

### Security
- [Update log messages for a security concern](https://github.com/ballerina-platform/ballerina-standard-library/issues/1203)

## [1.1.0-alpha5] - 2021-03-19

### Added
- [Add OAuth2 client auth support for introspection request](https://github.com/ballerina-platform/ballerina-standard-library/issues/935)
- [Add cert file and mTLS support for JDK11 client](https://github.com/ballerina-platform/ballerina-standard-library/issues/936)

### Changed
- Refactor error messages and debug logs
- Update error types and log API
- Update for Time API changes
- Generate OAuth2 token while the provider is initialized
- Update for Cache API changes
- Update for refresh token grant config
