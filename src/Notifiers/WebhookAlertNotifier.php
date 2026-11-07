<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Notifiers;

use JzGuilherme\LogSentinel\Contracts\AlertNotifierInterface;
use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;
use RuntimeException;

/**
 * Dispatches structured incident cards to Slack, Discord, or Microsoft Teams webhooks.
 * Guarantees that only LGPD-scrubbed data and AI root-cause fixes are transmitted.
 */
final class WebhookAlertNotifier implements AlertNotifierInterface
{
    public function __construct(
        private readonly string $webhookUrl = '',
        private readonly int $timeoutSeconds = 10
    ) {
    }

    public function notify(SanitizedIncidentDTO $incident, AiRootCauseDTO $diagnosis, int $occurrences = 1): bool
    {
        $payload = $this->buildWebhookPayload($incident, $diagnosis, $occurrences);

        if (trim($this->webhookUrl) === '') {
            // Dry-run mode when external webhook is not configured
            return true;
        }

        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $ch = curl_init($this->webhookUrl);
        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL for WebhookAlertNotifier.');
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS     => $json,
            CURLOPT_TIMEOUT        => $this->timeoutSeconds,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $response !== false && $httpCode >= 200 && $httpCode < 300;
    }

    /**
     * @return array<string, mixed>
     */
    public function buildWebhookPayload(SanitizedIncidentDTO $incident, AiRootCauseDTO $diagnosis, int $occurrences = 1): array
    {
        return [
            'username'    => 'PHP Log Sentinel (LGPD Safe)',
            'fingerprint' => $incident->fingerprint,
            'severity'    => strtoupper($diagnosis->severity),
            'category'    => $diagnosis->category,
            'occurrences' => $occurrences,
            'pii_masked'  => $incident->redactedPiiCount,
            'text'        => sprintf(
                "🚨 *[%s] %s* in `%s` (%s:%d)\n*Occurrences:* %d | *LGPD PII Tokens Masked:* %d\n*Root Cause:* %s\n```php\n%s\n```",
                strtoupper($diagnosis->severity),
                $incident->exceptionClass,
                $incident->serviceName,
                $incident->filePath,
                $incident->lineNumber,
                $occurrences,
                $incident->redactedPiiCount,
                $diagnosis->rootCauseSummary,
                $diagnosis->suggestedFixCode
            ),
        ];
    }
}
