<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Thrown for structurally malformed tokens: wrong segment count, invalid
 * base64url, invalid JSON, a missing/disallowed "alg" header, or key errors.
 */
final class InvalidTokenException extends JwtException
{
}
