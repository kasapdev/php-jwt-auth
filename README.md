# php-jwt-auth

[![CI](https://github.com/kasapdev/php-jwt-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/kasapdev/php-jwt-auth/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![PHP](https://img.shields.io/badge/PHP-8.1%2B-777BB4?logo=php&logoColor=white)

A zero-dependency PHP library for encoding and decoding JSON Web Tokens (JWT). Supports **HS256**
(HMAC-SHA256) and **RS256** (RSA-SHA256), validates `exp`/`nbf` claims, and uses `hash_equals()`
for constant-time signature comparison.

## Installation

Once published to Packagist:

```bash
composer require kasapdev/php-jwt-auth
```

Or just require the files directly:

```php
require_once 'src/JwtException.php';
require_once 'src/InvalidTokenException.php';
require_once 'src/InvalidSignatureException.php';
require_once 'src/ExpiredTokenException.php';
require_once 'src/Base64Url.php';
require_once 'src/Jwt.php';
```

## Usage

### HS256 (shared secret)

```php
use Kasapdev\JwtAuth\Jwt;
use Kasapdev\JwtAuth\ExpiredTokenException;
use Kasapdev\JwtAuth\InvalidSignatureException;
use Kasapdev\JwtAuth\InvalidTokenException;

$secret = 'a-long-random-shared-secret';

$token = Jwt::encode([
    'sub' => 'user-42',
    'role' => 'admin',
    'iat' => time(),
    'exp' => time() + 3600, // expires in one hour
], $secret);

try {
    $payload = Jwt::decode($token, $secret);
    echo $payload['sub']; // "user-42"
} catch (ExpiredTokenException $e) {
    // exp is in the past, or nbf is in the future
} catch (InvalidSignatureException $e) {
    // token is well-formed but the signature doesn't match
} catch (InvalidTokenException $e) {
    // malformed token: wrong segment count, bad base64, bad JSON, bad/disallowed alg
}
```

### RS256 (RSA key pair)

```php
use Kasapdev\JwtAuth\Jwt;

// $privateKeyPem / $publicKeyPem are PEM strings, e.g. loaded from files.
$token = Jwt::encode(['sub' => 'user-42'], $privateKeyPem, 'RS256');

$payload = Jwt::decode($token, $publicKeyPem, ['RS256']);
```

### Custom header fields

```php
$token = Jwt::encode(['sub' => '1'], $secret, 'HS256', ['kid' => 'key-2024-01']);
```

`typ` defaults to `"JWT"` and `alg` is always forced to match the `$algo` argument, regardless of
what's passed in `$header` — a caller cannot smuggle a different algorithm into the header than
the one actually used to sign the token.

## API

### `Jwt`

- `Jwt::encode(array $payload, string $secret, string $algo = 'HS256', array $header = []): string`
- `Jwt::decode(string $token, string $secret, array $allowedAlgos = ['HS256']): array`

For RS256, `$secret` in `encode()` is a PEM-encoded RSA **private** key, and in `decode()` a
PEM-encoded RSA **public** key.

### `Base64Url`

- `Base64Url::encode(string $data): string`
- `Base64Url::decode(string $data): string` — throws `InvalidTokenException` on invalid input

### Exceptions

All extend the common `JwtException` base, so you can catch broadly or specifically:

- `InvalidTokenException` — malformed token (wrong segment count, invalid base64url, invalid
  JSON, missing/disallowed `alg`, or an invalid signing/verification key)
- `InvalidSignatureException` — the token is well-formed but its signature does not verify
- `ExpiredTokenException` — the signature is valid but `exp` is in the past or `nbf` is in the
  future

## Security notes

- Signature comparison for HS256 uses `hash_equals()`, which is constant-time and resistant to
  timing attacks.
- `decode()` always verifies the signature **before** trusting the payload's claims.
- The `alg` used to sign a token is never taken on faith from the token's own header without your
  explicit consent: pass the algorithms you're willing to accept via `$allowedAlgos`, and anything
  else is rejected with `InvalidTokenException` (this closes the classic "alg confusion" /
  "alg: none" class of JWT vulnerabilities).

## Testing

```bash
php tests/run.php
```

The suite covers HS256 and RS256 round trips, tampered signatures, wrong secrets/keys, expired
and not-yet-valid tokens, and a range of malformed-token inputs. If the environment's OpenSSL
configuration can't generate an RSA key pair (some minimal PHP installs need `OPENSSL_CONF`
pointed at a valid `openssl.cnf` before `openssl_pkey_new()` will work), the RS256 tests are
skipped with a `[SKIP]` line rather than failing — HS256 coverage runs unconditionally either way.

## License

MIT
