<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Tests\Unit;

use JzGuilherme\LogSentinel\Contracts\AiDiagnosticProviderInterface;
use JzGuilherme\LogSentinel\Contracts\AlertNotifierInterface;
use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\RawLogEventDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;
use JzGuilherme\LogSentinel\Notifiers\WebhookAlertNotifier;
use JzGuilherme\LogSentinel\Security\ErrorFingerprinter;
use JzGuilherme\LogSentinel\Security\LgpdPiiScrubber;
use JzGuilherme\LogSentinel\Services\IncidentTriageService;
use PHPUnit\Framework\TestCase;

final class ErrorFingerprinterAndTriageTest extends TestCase
{
    public function testGeneratesIdenticalSha256FingerprintForSameErrorLocationAcrossDifferentUsers(): void
    {
        $fingerprinter = new ErrorFingerprinter(new LgpdPiiScrubber());

        $eventUserA = new RawLogEventDTO(
            serviceName: 'checkout-api',
            environment: 'production',
            exceptionClass: 'RuntimeException',
            message: 'Timeout charging CPF 111.222.333-44',
            filePath: '/var/www/src/Services/PaymentGateway.php',
            lineNumber: 88,
            stackTrace: '#0 /var/www/src/Services/PaymentGateway.php(88)'
        );

        $eventUserB = new RawLogEventDTO(
            serviceName: 'checkout-api',
            environment: 'production',
            exceptionClass: 'RuntimeException',
            message: 'Timeout charging CPF 555.666.777-88',
            filePath: 'C:\\var\\www\\src\\Services\\PaymentGateway.php',
            lineNumber: 88,
            stackTrace: '#0 /var/www/src/Services/PaymentGateway.php(88)'
        );

        $sanitizedA = $fingerprinter->sanitizeAndFingerprint($eventUserA);
        $sanitizedB = $fingerprinter->sanitizeAndFingerprint($eventUserB);

        self::assertSame(64, strlen($sanitizedA->fingerprint));
        self::assertSame($sanitizedA->fingerprint, $sanitizedB->fingerprint);
        self::assertSame('Timeout charging CPF [REDACTED_CPF]', $sanitizedA->sanitizedMessage);
        self::assertSame('Timeout charging CPF [REDACTED_CPF]', $sanitizedB->sanitizedMessage);
    }

    public function testIncidentTriageServiceOrchestratesScrubbingAiDiagnosisAndNotification(): void
    {
        $mockAi = new class () implements AiDiagnosticProviderInterface {
            public function analyzeIncident(SanitizedIncidentDTO $incident): AiRootCauseDTO
            {
                return new AiRootCauseDTO(
                    severity: 'critical',
                    category: 'pdo_deadlock',
                    rootCauseSummary: 'Concurrent transaction lock contention on orders table.',
                    suggestedFixCode: '$pdo->exec("SET SESSION innodb_lock_wait_timeout = 5;");',
                    preventionChecklist: ['Use SELECT ... FOR UPDATE SKIP LOCKED', 'Keep transactions short'],
                    promptTokens: 290,
                    completionTokens: 165
                );
            }
        };

        $notifier = new WebhookAlertNotifier('');
        $service = new IncidentTriageService(
            fingerprinter: new ErrorFingerprinter(new LgpdPiiScrubber()),
            aiProvider: $mockAi,
            notifier: $notifier,
            pdo: null
        );

        $rawEvent = new RawLogEventDTO(
            serviceName: 'order-worker',
            environment: 'production',
            exceptionClass: 'PDOException',
            message: 'Deadlock found for email client@store.com',
            filePath: '/var/www/src/Queue/OrderWorker.php',
            lineNumber: 54,
            stackTrace: '#0 OrderWorker.php(54)'
        );

        $result = $service->triageDirectly($rawEvent);

        self::assertSame('Deadlock found for email [REDACTED_EMAIL]', $result['incident']->sanitizedMessage);
        self::assertSame('critical', $result['diagnosis']->severity);
        self::assertSame('pdo_deadlock', $result['diagnosis']->category);
        self::assertSame(290, $result['diagnosis']->promptTokens);

        $webhookPayload = $notifier->buildWebhookPayload($result['incident'], $result['diagnosis'], 42);
        self::assertSame('CRITICAL', $webhookPayload['severity']);
        self::assertSame(42, $webhookPayload['occurrences']);
        self::assertStringNotContainsString('client@store.com', (string) $webhookPayload['text']);
    }
}
