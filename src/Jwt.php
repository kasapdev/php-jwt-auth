<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Encode and decode JSON Web Tokens. Supports HS256 (HMAC-SHA256, via
 * hash_hmac + hash_equals for constant-time comparison) and RS256
 * (RSA-SHA256, via openssl_sign/openssl_verify).
 */
final class Jwt
{
    private const SUPPORTED_ALGOS = ['HS256', 'RS256'];

    /**
     * Encode a payload into a signed JWT.
     *
     * @param string $secret For HS256, the shared HMAC secret. For RS256, a PEM-encoded RSA private key.
     * @param array<string,mixed> $header Extra header fields to merge in (e.g. ['kid' => '...']).
     *
     * @throws InvalidTokenException on an unsupported algorithm or signing failure.
     */
    public static function encode(array $payload, string $secret, string $algo = 'HS256', array $header = []): string
    {
        self::assertSupportedAlgo($algo);

        $header = array_merge($header, ['typ' => $header['typ'] ?? 'JWT', 'alg' => $algo]);

        $headerEncoded = Base64Url::encode(self::jsonEncode($header));
        $payloadEncoded = Base64Url::encode(self::jsonEncode($payload));

        $signingInput = $headerEncoded . '.' . $payloadEncoded;
        $signature = self::sign($signingInput, $secret, $algo);

        return $signingInput . '.' . Base64Url::encode($signature);
    }

    /**
     * Decode and verify a JWT, returning its payload as an array.
     *
     * @param string|string[] $secret For HS256, the shared HMAC secret. For RS256, a PEM-encoded RSA public key.
     *     Also accepts an array of candidate secrets/keys to support key rotation: each candidate is tried in
     *     order (constant-time per attempt) until one verifies the signature, so tokens signed under an older
     *     secret keep decoding as long as that secret is still included in the array.
     * @param string[] $allowedAlgos Algorithms this call will accept; the token's own "alg" header must be in this list.
     * @param string|null $issuer If given, the token's "iss" claim must be present and equal to this value.
     * @param string|string[]|null $audience If given, the token's "aud" claim (a single string or an array of
     *     strings per RFC 7519 §4.1.3) must be present and contain at least one value from this list.
     *
     * @throws InvalidTokenException     if the token is malformed or uses a disallowed/unsupported algorithm.
     * @throws InvalidSignatureException if the signature does not verify against $secret, or (when $secret is an
     *     array) against any of the candidate secrets/keys.
     * @throws ExpiredTokenException     if "exp" is in the past or "nbf" is in the future.
     * @throws InvalidClaimException     if "iss" or "aud" is required but missing, or does not match.
     */
    public static function decode(
        string $token,
        string|array $secret,
        array $allowedAlgos = ['HS256'],
        ?string $issuer = null,
        string|array|null $audience = null
    ): array {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('A JWT must have exactly three dot-separated segments.');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        $header = self::jsonDecode(Base64Url::decode($headerEncoded));
        $payload = self::jsonDecode(Base64Url::decode($payloadEncoded));
        $signature = Base64Url::decode($signatureEncoded);

        if (!is_array($header) || !isset($header['alg']) || !is_string($header['alg'])) {
            throw new InvalidTokenException('Token header is missing a valid "alg" field.');
        }

        if (!is_array($payload)) {
            throw new InvalidTokenException('Token payload is not a JSON object.');
        }

        $algo = $header['alg'];
        if (!in_array($algo, $allowedAlgos, true)) {
            throw new InvalidTokenException(sprintf('Algorithm "%s" is not in the allowed list.', $algo));
        }

        $signingInput = $headerEncoded . '.' . $payloadEncoded;
        self::verifyAnyKey($signingInput, $signature, $secret, $algo);

        $now = time();

        if (array_key_exists('exp', $payload)) {
            if (!is_numeric($payload['exp'])) {
                throw new InvalidTokenException('Token "exp" claim must be numeric.');
            }
            if ($now >= (int) $payload['exp']) {
                throw new ExpiredTokenException('Token has expired.');
            }
        }

        if (array_key_exists('nbf', $payload)) {
            if (!is_numeric($payload['nbf'])) {
                throw new InvalidTokenException('Token "nbf" claim must be numeric.');
            }
            if ($now < (int) $payload['nbf']) {
                throw new ExpiredTokenException('Token is not valid yet ("nbf" is in the future).');
            }
        }

        if ($issuer !== null) {
            self::checkIssuer($payload, $issuer);
        }

        if ($audience !== null) {
            self::checkAudience($payload, $audience);
        }

        /** @var array<string,mixed> $payload */
        return $payload;
    }

    /**
     * @param array<string,mixed> $payload
     */
    private static function checkIssuer(array $payload, string $issuer): void
    {
        if (!array_key_exists('iss', $payload)) {
            throw new InvalidClaimException('Token has no "iss" claim, but an issuer was required.');
        }

        if (!is_string($payload['iss'])) {
            throw new InvalidTokenException('Token "iss" claim must be a string.');
        }

        if ($payload['iss'] !== $issuer) {
            throw new InvalidClaimException(sprintf('Token issuer "%s" does not match the expected issuer.', $payload['iss']));
        }
    }

    /**
     * @param array<string,mixed> $payload
     * @param string|string[] $audience
     */
    private static function checkAudience(array $payload, string|array $audience): void
    {
        if (!array_key_exists('aud', $payload)) {
            throw new InvalidClaimException('Token has no "aud" claim, but an audience was required.');
        }

        $tokenAudiences = is_string($payload['aud']) ? [$payload['aud']] : $payload['aud'];
        if (!is_array($tokenAudiences) || array_filter($tokenAudiences, 'is_string') !== $tokenAudiences) {
            throw new InvalidTokenException('Token "aud" claim must be a string or an array of strings.');
        }

        $expected = is_array($audience) ? $audience : [$audience];
        if (!array_intersect($expected, $tokenAudiences)) {
            throw new InvalidClaimException('Token audience does not match any expected audience.');
        }
    }

    private static function sign(string $data, string $secret, string $algo): string
    {
        return match ($algo) {
            'HS256' => hash_hmac('sha256', $data, $secret, true),
            'RS256' => self::signRs256($data, $secret),
            default => throw new InvalidTokenException("Unsupported algorithm: {$algo}"),
        };
    }

    /**
     * Verify a signature against one key, or (for key rotation) an array of candidate keys, trying each in
     * order until one verifies. Every attempt goes through the same constant-time comparison as a single-key
     * verify; a candidate that doesn't match simply raises InvalidSignatureException, which is caught here so
     * the next candidate can be tried.
     *
     * @param string|string[] $keys
     */
    private static function verifyAnyKey(string $data, string $signature, string|array $keys, string $algo): void
    {
        $candidates = is_array($keys) ? $keys : [$keys];

        if ($candidates === []) {
            throw new InvalidSignatureException('No candidate keys were provided for signature verification.');
        }

        foreach ($candidates as $candidate) {
            try {
                self::verify($data, $signature, $candidate, $algo);

                return;
            } catch (InvalidSignatureException) {
                // Try the next candidate key.
            }
        }

        throw new InvalidSignatureException('Signature did not verify against any candidate key.');
    }

    private static function verify(string $data, string $signature, string $secret, string $algo): void
    {
        match ($algo) {
            'HS256' => self::verifyHs256($data, $signature, $secret),
            'RS256' => self::verifyRs256($data, $signature, $secret),
            default => throw new InvalidTokenException("Unsupported algorithm: {$algo}"),
        };
    }

    private static function verifyHs256(string $data, string $signature, string $secret): void
    {
        $expected = hash_hmac('sha256', $data, $secret, true);

        if (!hash_equals($expected, $signature)) {
            throw new InvalidSignatureException('HS256 signature verification failed.');
        }
    }

    private static function signRs256(string $data, string $privateKeyPem): string
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new InvalidTokenException('Invalid RS256 private key: ' . self::lastOpensslError());
        }

        $signature = '';
        $ok = openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!$ok) {
            throw new InvalidTokenException('Failed to sign token with RS256: ' . self::lastOpensslError());
        }

        return $signature;
    }

    private static function verifyRs256(string $data, string $signature, string $publicKeyPem): void
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new InvalidTokenException('Invalid RS256 public key: ' . self::lastOpensslError());
        }

        $result = openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);

        if ($result === 1) {
            return;
        }

        if ($result === 0) {
            throw new InvalidSignatureException('RS256 signature verification failed.');
        }

        throw new InvalidTokenException('RS256 signature verification error: ' . self::lastOpensslError());
    }

    private static function lastOpensslError(): string
    {
        $message = openssl_error_string();

        return $message !== false ? $message : 'unknown OpenSSL error';
    }

    private static function assertSupportedAlgo(string $algo): void
    {
        if (!in_array($algo, self::SUPPORTED_ALGOS, true)) {
            throw new InvalidTokenException("Unsupported algorithm: {$algo}");
        }
    }

    /**
     * @param array<string,mixed> $data
     */
    private static function jsonEncode(array $data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new InvalidTokenException('Failed to JSON-encode JWT segment: ' . json_last_error_msg());
        }

        return $json;
    }

    private static function jsonDecode(string $json): mixed
    {
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidTokenException('Invalid JSON in JWT segment: ' . json_last_error_msg());
        }

        return $data;
    }
}
