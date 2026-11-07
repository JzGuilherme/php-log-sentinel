<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Security;

use JzGuilherme\LogSentinel\Contracts\PiiScrubberInterface;
use JzGuilherme\LogSentinel\DTO\RawLogEventDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;

/**
 * Computes a canonical SHA-256 deduplication fingerprint for application errors
 * and builds an LGPD-sanitized incident DTO ready for persistence and AI analysis.
 */
final class ErrorFingerprinter
{
    public function __construct(
        private readonly PiiScrubberInterface $scrubber = new LgpdPiiScrubber()
    ) {
    }

    /**
     * Sanitizes a RawLogEventDTO and generates its deterministic SHA-256 fingerprint.
     */
    public function sanitizeAndFingerprint(RawLogEventDTO $rawEvent): SanitizedIncidentDTO
    {
        $messageResult = $this->scrubber->scrubText($rawEvent->message);
        $traceResult = $this->scrubber->scrubText($rawEvent->stackTrace);
        $contextResult = $this->scrubber->scrubContext($rawEvent->context);

        $totalRedacted = $messageResult['redacted_count']
            + $traceResult['redacted_count']
            + $contextResult['redacted_count'];

        $normalizedPath = $this->normalizeFilePath($rawEvent->filePath);
        $fingerprint = $this->computeHash(
            $rawEvent->serviceName,
            $rawEvent->exceptionClass,
            $normalizedPath,
            $rawEvent->lineNumber
        );

        return new SanitizedIncidentDTO(
            serviceName: trim($rawEvent->serviceName),
            environment: trim($rawEvent->environment),
            fingerprint: $fingerprint,
            exceptionClass: trim($rawEvent->exceptionClass),
            filePath: $normalizedPath,
            lineNumber: $rawEvent->lineNumber,
            sanitizedMessage: $messageResult['sanitized'],
            sanitizedStackTrace: $traceResult['sanitized'],
            sanitizedContext: $contextResult['sanitized'],
            redactedPiiCount: $totalRedacted
        );
    }

    /**
     * Computes a 64-character SHA-256 hash from the structural location of the exception,
     * ensuring dynamic user IDs or timestamps in the message never break deduplication.
     */
    public function computeHash(
        string $serviceName,
        string $exceptionClass,
        string $filePath,
        int $lineNumber
    ): string {
        $canonicalSignature = implode('|', [
            strtolower(trim($serviceName)),
            strtolower(trim($exceptionClass)),
            $this->normalizeFilePath($filePath),
            (string) $lineNumber,
        ]);

        return hash('sha256', $canonicalSignature);
    }

    private function normalizeFilePath(string $path): string
    {
        $unixPath = str_replace('\\', '/', trim($path));
        // Strip deployment-specific release prefixes like /var/www/releases/20261107/
        $cleaned = (string) preg_replace('#^/.+?/(?:app|src|vendor|bin)/#i', '$0', $unixPath);

        return ltrim($cleaned, '/');
    }
}
