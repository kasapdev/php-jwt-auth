<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Thrown when a token's signature is valid but its "exp" claim is in the
 * past, or its "nbf" claim is in the future.
 */
final class ExpiredTokenException extends JwtException
{
}
