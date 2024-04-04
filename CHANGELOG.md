# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] (2024-04-04)

### Changed

- **Dependencies**: update to golang.org/x/net v0.23.0
- **Documentation**: fix bad link in changelog

## [0.1.1] (2024-04-03)

### Added

- **Tests**: augment test suite

### Changed

- **Performance**: As a side effect of a bug fix, CORS middleware now incur
  slightly more heap allocations than they used to when they handle requests
  that are not CORS-preflight requests.
- **Performance**: various micro-optimizations
- **Documentation**: simplify examples
- **Documentation**: various improvements

### Fixed

- **Bug**: A handler wrapped in a CORS middleware could compromise middleware's
  concurrency safety by mutating some internal package-level slices that are
  meant to be effectively constant.

## [0.1.0] (2024-03-23)

[0.1.2]: https://github.com/jub0bs/cors/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jub0bs/cors/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jub0bs/cors/releases/tag/v0.1.0
