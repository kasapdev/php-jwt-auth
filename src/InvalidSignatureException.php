<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Thrown when a token is well-formed but its signature does not verify
 * against the given secret/public key.
 */
final class InvalidSignatureException extends JwtException
{
}
