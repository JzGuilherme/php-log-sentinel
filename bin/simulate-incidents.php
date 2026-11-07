#!/usr/bin/env php
<?php

declare(strict_types=1);

use JzGuilherme\LogSentinel\DTO\RawLogEventDTO;
use JzGuilherme\LogSentinel\Security\ErrorFingerprinter;
use JzGuilherme\LogSentinel\Security\LgpdPiiScrubber;

$autoloadPath = dirname(__DIR__) . '/vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

$scrubber = new LgpdPiiScrubber();
$fingerprinter = new ErrorFingerprinter($scrubber);

$rawEvent = new RawLogEventDTO(
    serviceName: 'checkout-payment-service',
    environment: 'production',
    exceptionClass: 'PDOException',
    message: 'SQLSTATE[23000]: Duplicate entry for user Joao (CPF: 123.456.789-01, Email: joao.silva@cliente.com.br, Card: 4532 0151 1283 0366)',
    filePath: '/var/www/releases/20261107/src/Repositories/OrderRepository.php',
    lineNumber: 142,
    stackTrace: "#0 /var/www/src/Repositories/OrderRepository.php(142): PDOStatement->execute()\n#1 Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    context: [
        'customer_cpf' => '123.456.789-01',
        'password'     => 'SuperSecretPassword!2026',
        'card_number'  => '4532015112830366',
        'order_total'  => 499.90,
    ]
);

$sanitized = $fingerprinter->sanitizeAndFingerprint($rawEvent);

echo "=== [PHP LOG SENTINEL - LGPD ANONYMIZATION DEMO] ===\n";
echo "Fingerprint SHA-256 : " . $sanitized->fingerprint . "\n";
echo "Normalized Location : " . $sanitized->filePath . ':' . $sanitized->lineNumber . "\n";
echo "PII Tokens Masked   : " . $sanitized->redactedPiiCount . "\n";
echo "Sanitized Message   : " . $sanitized->sanitizedMessage . "\n";
echo "Sanitized Context   : " . json_encode($sanitized->sanitizedContext, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
