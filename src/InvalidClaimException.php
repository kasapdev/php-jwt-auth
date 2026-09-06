<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

/**
 * Thrown when a token is structurally valid and its signature verifies, but
 * a registered claim does not satisfy a requirement the caller opted into —
 * e.g. "iss" is not the expected issuer, or "aud" does not contain the
 * expected audience.
 */
final class InvalidClaimException extends JwtException
{
}
