<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Base64url encoding as defined by RFC 4648 §5: standard base64 with `+`/`/`
 * swapped for `-`/`_`, and trailing `=` padding stripped (and restored on
 * decode).
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @throws InvalidTokenException if the input is not valid base64url.
     */
    public static function decode(string $data): string
    {
        if ($data === '') {
            return '';
        }

        $padded = $data;
        $remainder = strlen($padded) % 4;
        if ($remainder !== 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        if ($decoded === false) {
            throw new InvalidTokenException('Invalid base64url-encoded segment.');
        }

        return $decoded;
    }
}
