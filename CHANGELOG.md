# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.0] - 2026-09-06

### Added

- `Jwt::decode()` gained optional `issuer` and `audience` parameters for validating the
  registered `iss` and `aud` claims, matching the existing `exp`/`nbf` validation style: opt in
  by passing a value, and the claim must be present and match or a new `InvalidClaimException`
  is thrown. `audience` accepts a single string or an array of acceptable values, matching
  against a token `aud` that is itself a string or an array (RFC 7519 §4.1.3). Both parameters
  default to `null` (no check), so existing calls are unaffected.
- New `InvalidClaimException` (extends the common `JwtException` base) for this failure mode,
  distinct from `InvalidTokenException` (structural malformation) and `ExpiredTokenException`
  (time-based claims).

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
