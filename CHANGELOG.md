# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.0] - 2026-09-06

### Added

- Test coverage for documented-but-untested `Jwt::decode()` validation paths:
  - A token header missing the `alg` field entirely throws
    `InvalidTokenException`.
  - A token header whose `alg` field is not a string throws
    `InvalidTokenException`.
  - A token whose payload segment decodes to a JSON scalar (not an
    object/array) throws `InvalidTokenException`.
  - A non-numeric `exp` claim throws `InvalidTokenException` instead of
    being silently ignored.
  - A non-numeric `nbf` claim throws `InvalidTokenException` instead of
    being silently ignored.
  - `Jwt::encode()` with a malformed PEM key for RS256 throws
    `InvalidTokenException` rather than a raw OpenSSL warning/error.

No behavioral changes were needed — all new edge-case tests passed against
the existing implementation.
