<?php

declare(strict_types=1);

namespace Kasapdev\JwtAuth;

use RuntimeException;

/**
 * Common base class for every exception thrown by this library, so callers
 * can catch JwtException broadly or one of the specific subclasses.
 */
abstract class JwtException extends RuntimeException
{
}
