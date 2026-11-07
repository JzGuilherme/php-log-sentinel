<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Exceptions;

use RuntimeException;

/**
 * Exception thrown when AI diagnostic generation or payload validation fails.
 */
final class DiagnosticException extends RuntimeException
{
    public static function fromHttpError(int $statusCode, string $body): self
    {
        return new self(
            sprintf('AI Diagnostic Provider failed with HTTP %d: %s', $statusCode, mb_substr($body, 0, 400)),
            $statusCode
        );
    }

    public static function fromInvalidSchema(string $reason): self
    {
        return new self(sprintf('AI Diagnostic response violated structured schema: %s', $reason), 422);
    }
}
