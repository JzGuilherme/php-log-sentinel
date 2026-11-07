<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Contracts;

/**
 * Contract for LGPD/GDPR Personally Identifiable Information (PII) scrubbing engines.
 */
interface PiiScrubberInterface
{
    /**
     * Masks all PII patterns (CPF, CNPJ, Credit Cards, Emails, JWTs, API Keys, Passwords)
     * in a raw text string and returns the sanitized string along with the count of masked tokens.
     *
     * @return array{sanitized: string, redacted_count: int}
     */
    public function scrubText(string $rawText): array;

    /**
     * Recursively scrubs an associative array (e.g., request payload or log context),
     * redacting both sensitive keys and inline PII values.
     *
     * @param array<string, mixed> $context
     * @return array{sanitized: array<string, mixed>, redacted_count: int}
     */
    public function scrubContext(array $context): array;
}
