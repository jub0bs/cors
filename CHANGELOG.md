# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] (2025-06-14)

This release drops support for [Private-Network Access][pna].

Private-Network Access was never fully implemented by browsers and has been put
[on (indefinite) hold][pna-on-hold] in favor of
[a new permission-based mechanism named "Local-Network Access"][lna].

### Changed

- **API** (breaking change): Valid values for the `Reason` field of struct type
  `cfgerrors.IncompatibleOriginPatternError` now exclude `"pna"` and are
  limited to `"credentialed"` and `"psl"`.

### Removed

- **API** (breaking changes): Drop fields `PrivateNetworkAccess` and
  `PrivateNetworkAccessInNoCORSModeOnly` from struct type `ExtraConfig`.
- **API** (breaking change): Drop type
  `cfgerrors.IncompatiblePrivateNetworkAccessModesError`.

## [0.6.0] (2025-06-10)

- **Behavior**: minor changes to how middleware tolerate optional whitespace
  in the Access-Control-Request-Headers header.
- **Performance**: minor improvements
- **Dependencies**: update to golang.org/x/net v0.41.0

## [0.5.9] (2025-04-26)

### Changed

- **Performance**: minor improvements
- **Dependencies**: update to golang.org/x/net v0.39.0
- **Tests**: minor improvements
- **Documentation**: minor improvements

## [0.5.8] (2025-04-03)

### Changed

- **Dependencies**: update to golang.org/x/net v0.38.0

## [0.5.7] (2025-03-13)

### Changed

- **Performance**: minor improvements
- **Dependencies**: update to golang.org/x/net v0.37.0

## [0.5.6] (2025-02-18)

### Changed

- **Performance**: Middleware initialization now requires less heap allocation.
- **Performance**: Middleware's Config method now requires less heap allocation.
- **Tests**: minor improvements
- **Documentation**: minor improvements

## [0.5.5] (2025-02-13)

### Changed

- **Performance**: Middleware initialization now requires less heap allocation.
- **Performance**: Middleware's Config method now requires less heap allocation.
- **Dependencies**: update to golang.org/x/net v0.35.0
- **Tests**: various improvements
- **Documentation**: minor improvements

## [0.5.4] (2025-02-04)

### Changed

- **Performance**: Middleware initialization now requires less heap allocation.
- **Performance**: Middleware's Config method now requires less heap allocation.

## [0.5.3] (2025-01-24)

### Changed

- **Performance**: Middleware initialization now requires less heap allocation.
- **Documentation**: minor fixes and improvements

## [0.5.2] (2025-01-15)

### Changed

- **Performance**: minor improvements
- **Dependencies**: update to golang.org/x/net v0.34.0
- **Documentation**: Emphasize the library's distinguishing features in the
  README.
- **Documentation**: minor improvements

## [0.5.1] (2025-01-13)

### Changed

- **Performance**: minor improvements
- **Tests**: various improvements
- **Documentation**: various improvements

## [0.5.0] (2025-01-05)

### Added

- **API**: Export concrete error types from a new `cfgerrors` package,
  thereby enabling programmatic handling of CORS-configuration errors.

### Changed
- **Behavior**: Error messages have been simplified.
- **Behavior**: Safelisted response-header names are now silently ignored.
- **Behavior**: Method names are now normalized (per the Fetch standard).
- **Behavior**: Discrete origin patterns in addition to * are now permitted.
- **Behavior**: Discrete methods in addition to * are now permitted.
- **Behavior**: Discrete request-header names in addition to * are now
  permitted.
- **Behavior**: Discrete response-header names in addition to * are now
  permitted.
- **Behavior**: The conjunct use of wildcard subdomains and wildcard ports
  in an origin pattern is now permitted.
- **Behavior**: `*Middleware`'s `Config` method now outputs header names in
  lower case rather than in their canonical form.
- **Tests**: various improvements
- **Documentation**: various improvements

### Removed

- **API**: Drop `SetPkgName` method from error types.
  Although this is (strictly speaking) a breaking change,
  it is unlikely to affect many (if any at all) users of this library.

## [0.4.0] (2024-12-19)

### Changed

- **Dependencies**: Go 1.23 (or above) is now required.
- **Dependencies**: update to golang.org/x/net v0.33.0
- **Tests**: various improvements
- **Documentation**: various improvements

## [0.3.1] (2024-09-05)

### Changed

- **Tests**: various improvements
- **Documentation**: various improvements

## [0.3.0] (2024-08-28)

### Fixed

- **Bug**: Due to a lack of synchronization, invocations of a middleware
  concurrent with calls to that middleware's SetDebug method could previously
  trigger data races.
- **Tests**: Benchmarks now set the debug mode of the middleware under test
  only when intended.

### Changed

- **Behavior**: Middleware now handle multiple Access-Control-Request-Headers
  field lines.
- **Behavior**: Middleware now tolerate a small amount of whitespace around the
  elements of Access-Control-Request-Headers field values; moreover, middleware
  now tolerate tolerate a modest number of empty elements in
  Access-Control-Request-Headers field values.
- **Behavior**: Non-HTTP(S) schemes (e.g. "connector") are now supported.
- **Performance**: various improvements of middleware invocations
- **Dependencies**: update to golang.org/x/net v0.28.0
- **Documentation**: various improvements

## [0.2.0] (2024-05-08)

### Added

- **API**: add a `Reconfigure` method on `*Middleware`
- **API**: add a `Config` method on `*Middleware`
- **Performance**: minor improvements
- **Documentation**: add a section about reasons for favoring rs/cors
  over jub0bs/cors

### Changed

- **API**: The zero value of `Middleware` is now ready to use,
  but is a mere "passthrough" middleware,
  i.e. a middleware that simply delegates to the handler(s) it wraps.
- **Dependencies**: update to golang.org/x/net v0.25.0
- **Documentation**: various improvements

## [0.1.3] (2024-05-02)

### Fixed

- **Vulnerability**: Some CORS middleware (more specifically those created by
  specifying two or more origin patterns whose hosts share a proper suffix)
  incorrectly allowed some untrusted origins, thereby opening the door to
  cross-origin attacks from the untrusted origins in question.
  For example, specifying origin patterns `https://foo.com` and
  `https://bar.com` (in that order) would yield a middleware that would
  incorrectly allow untrusted origin `https://barfoo.com`.
  See https://github.com/jub0bs/cors/security/advisories/GHSA-vhxv-fg4m-p2w8.

### Changed

- **Performance**: reduce heap allocations at initialization
- **Dependencies**: update to golang.org/x/net v0.24.0
- **Documentation**: clarify examples
- **Tests**: improve failure messages

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

[0.7.0]: https://github.com/jub0bs/cors/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jub0bs/cors/compare/v0.5.9...v0.6.0
[0.5.9]: https://github.com/jub0bs/cors/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/jub0bs/cors/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/jub0bs/cors/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/jub0bs/cors/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/jub0bs/cors/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/jub0bs/cors/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/jub0bs/cors/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/jub0bs/cors/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/jub0bs/cors/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/jub0bs/cors/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jub0bs/cors/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/jub0bs/cors/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jub0bs/cors/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jub0bs/cors/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/jub0bs/cors/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/jub0bs/cors/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jub0bs/cors/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jub0bs/cors/releases/tag/v0.1.0

[lna]: https://developer.chrome.com/blog/local-network-access
[pna-on-hold]: https://developer.chrome.com/blog/pna-on-hold
[pna]: https://wicg.github.io/private-network-access/
