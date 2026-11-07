<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\DTO;

use Throwable;

/**
 * Represents a raw, un-sanitized error or exception event captured from the application runtime.
 */
final readonly class RawLogEventDTO
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public string $serviceName,
        public string $environment,
        public string $exceptionClass,
        public string $message,
        public string $filePath,
        public int $lineNumber,
        public string $stackTrace,
        public array $context = []
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function fromThrowable(
        Throwable $exception,
        string $serviceName = 'php-app',
        string $environment = 'production',
        array $context = []
    ): self {
        return new self(
            serviceName: $serviceName,
            environment: $environment,
            exceptionClass: $exception::class,
            message: $exception->getMessage(),
            filePath: $exception->getFile(),
            lineNumber: $exception->getLine(),
            stackTrace: $exception->getTraceAsString(),
            context: $context
        );
    }
}
