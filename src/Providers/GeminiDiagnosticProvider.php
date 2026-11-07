<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Providers;

use JzGuilherme\LogSentinel\Contracts\AiDiagnosticProviderInterface;
use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;
use JzGuilherme\LogSentinel\Exceptions\DiagnosticException;

/**
 * Google Gemini 2.5 Flash Diagnostic Provider.
 * Receives strictly LGPD-sanitized incident telemetry and returns a structured JSON
 * root-cause analysis, severity classification, and actionable PHP code patch.
 */
final class GeminiDiagnosticProvider implements AiDiagnosticProviderInterface
{
    private const ENDPOINT_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';

    public function __construct(
        private readonly string $apiKey,
        private readonly int $timeoutSeconds = 30
    ) {
        if (trim($this->apiKey) === '') {
            throw new DiagnosticException('GEMINI_API_KEY cannot be empty.', 401);
        }
    }

    /**
     * @inheritDoc
     */
    public function analyzeIncident(SanitizedIncidentDTO $incident): AiRootCauseDTO
    {
        $payload = $this->buildRequestPayload($incident);
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $ch = curl_init(self::ENDPOINT_URL);
        if ($ch === false) {
            throw new DiagnosticException('Failed to initialize cURL session for Gemini Diagnostic API.', 500);
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'x-goog-api-key: ' . $this->apiKey,
            ],
            CURLOPT_POSTFIELDS     => $jsonPayload,
            CURLOPT_TIMEOUT        => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => 10,
        ]);

        $rawResponse = curl_exec($ch);
        $curlErrno = curl_errno($ch);
        $curlError = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($rawResponse === false || $curlErrno !== 0) {
            throw new DiagnosticException(sprintf('cURL error (%d): %s', $curlErrno, $curlError), 503);
        }

        $responseString = (string) $rawResponse;
        if ($httpCode < 200 || $httpCode >= 300) {
            throw DiagnosticException::fromHttpError($httpCode, $responseString);
        }

        /** @var array<string, mixed>|null $decoded */
        $decoded = json_decode($responseString, true);
        if (!is_array($decoded)) {
            throw DiagnosticException::fromInvalidSchema('Top-level Gemini response is not valid JSON.');
        }

        $candidateText = $decoded['candidates'][0]['content']['parts'][0]['text'] ?? null;
        if (!is_string($candidateText) || trim($candidateText) === '') {
            throw DiagnosticException::fromInvalidSchema('Missing candidate JSON text in Gemini response.');
        }

        /** @var array<string, mixed>|null $structured */
        $structured = json_decode($candidateText, true);
        if (!is_array($structured)) {
            throw DiagnosticException::fromInvalidSchema('Candidate payload is not a valid JSON object.');
        }

        $required = ['severity', 'category', 'root_cause_summary', 'suggested_fix_code', 'prevention_checklist'];
        foreach ($required as $key) {
            if (!array_key_exists($key, $structured)) {
                throw DiagnosticException::fromInvalidSchema(sprintf('Missing required key "%s".', $key));
            }
        }

        $severity = strtolower(trim((string) $structured['severity']));
        if (!in_array($severity, ['critical', 'high', 'medium', 'low'], true)) {
            $severity = 'high';
        }

        $checklist = [];
        if (is_array($structured['prevention_checklist'])) {
            foreach ($structured['prevention_checklist'] as $item) {
                if (is_string($item) && trim($item) !== '') {
                    $checklist[] = trim($item);
                }
            }
        }

        $usage = is_array($decoded['usageMetadata'] ?? null) ? $decoded['usageMetadata'] : [];

        return new AiRootCauseDTO(
            severity: $severity,
            category: trim((string) $structured['category']),
            rootCauseSummary: trim((string) $structured['root_cause_summary']),
            suggestedFixCode: trim((string) $structured['suggested_fix_code']),
            preventionChecklist: $checklist,
            promptTokens: (int) ($usage['promptTokenCount'] ?? 0),
            completionTokens: (int) ($usage['candidatesTokenCount'] ?? 0)
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function buildRequestPayload(SanitizedIncidentDTO $incident): array
    {
        $contextJson = json_encode($incident->sanitizedContext, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $prompt = implode("\n", [
            'Act as a Principal PHP 8.2+ Site Reliability Engineer (SRE) and Application Security Architect.',
            'Analyze the following LGPD-sanitized production exception and provide a precise root-cause diagnosis and PHP code hotfix.',
            '',
            '--- SANITIZED INCIDENT TELEMETRY ---',
            sprintf('Service: %s (%s)', $incident->serviceName, $incident->environment),
            sprintf('Exception Class: %s', $incident->exceptionClass),
            sprintf('Location: %s:%d', $incident->filePath, $incident->lineNumber),
            sprintf('Sanitized Message: %s', $incident->sanitizedMessage),
            sprintf('Sanitized Context: %s', $contextJson),
            sprintf("Sanitized Stack Trace:\n%s", $incident->sanitizedStackTrace),
        ]);

        return [
            'contents' => [
                [
                    'role'  => 'user',
                    'parts' => [
                        ['text' => $prompt],
                    ],
                ],
            ],
            'generationConfig' => [
                'temperature'      => 0.1,
                'responseMimeType' => 'application/json',
                'responseSchema'   => [
                    'type'       => 'OBJECT',
                    'required'   => [
                        'severity',
                        'category',
                        'root_cause_summary',
                        'suggested_fix_code',
                        'prevention_checklist',
                    ],
                    'properties' => [
                        'severity' => [
                            'type'        => 'STRING',
                            'enum'        => ['critical', 'high', 'medium', 'low'],
                            'description' => 'Incident operational severity level.',
                        ],
                        'category' => [
                            'type'        => 'STRING',
                            'description' => 'Short classification slug (e.g. pdo_deadlock, null_reference, gateway_timeout).',
                        ],
                        'root_cause_summary' => [
                            'type'        => 'STRING',
                            'description' => 'Concise technical explanation of why the exception occurred.',
                        ],
                        'suggested_fix_code' => [
                            'type'        => 'STRING',
                            'description' => 'Production-ready PHP 8.2+ code snippet fixing the vulnerability or bug.',
                        ],
                        'prevention_checklist' => [
                            'type'  => 'ARRAY',
                            'items' => ['type' => 'STRING'],
                        ],
                    ],
                ],
            ],
        ];
    }
}
