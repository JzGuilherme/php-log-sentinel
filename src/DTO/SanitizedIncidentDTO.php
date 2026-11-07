<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\DTO;

use JsonSerializable;

/**
 * Immutable DTO guaranteed to contain ONLY LGPD/GDPR-scrubbed error telemetry
 * and a canonical SHA-256 deduplication fingerprint.
 */
final readonly class SanitizedIncidentDTO implements JsonSerializable
{
    /**
     * @param array<string, mixed> $sanitizedContext
     */
    public function __construct(
        public string $serviceName,
        public string $environment,
        public string $fingerprint,
        public string $exceptionClass,
        public string $filePath,
        public int $lineNumber,
        public string $sanitizedMessage,
        public string $sanitizedStackTrace,
        public array $sanitizedContext,
        public int $redactedPiiCount
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'service_name'          => $this->serviceName,
            'environment'           => $this->environment,
            'fingerprint'           => $this->fingerprint,
            'exception_class'       => $this->exceptionClass,
            'file_path'             => $this->filePath,
            'line_number'           => $this->lineNumber,
            'sanitized_message'     => $this->sanitizedMessage,
            'sanitized_stack_trace' => $this->sanitizedStackTrace,
            'sanitized_context'     => $this->sanitizedContext,
            'redacted_pii_count'    => $this->redactedPiiCount,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
