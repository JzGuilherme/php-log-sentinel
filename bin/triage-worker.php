#!/usr/bin/env php
<?php

declare(strict_types=1);

use Dotenv\Dotenv;
use JzGuilherme\LogSentinel\Notifiers\WebhookAlertNotifier;
use JzGuilherme\LogSentinel\Providers\GeminiDiagnosticProvider;
use JzGuilherme\LogSentinel\Security\ErrorFingerprinter;
use JzGuilherme\LogSentinel\Security\LgpdPiiScrubber;
use JzGuilherme\LogSentinel\Services\IncidentTriageService;

$autoloadPath = dirname(__DIR__) . '/vendor/autoload.php';
if (!file_exists($autoloadPath)) {
    fwrite(STDERR, "Error: Run 'composer install' first.\n");
    exit(1);
}

require_once $autoloadPath;

$rootDir = dirname(__DIR__);
if (class_exists(Dotenv::class) && file_exists($rootDir . '/.env')) {
    Dotenv::createImmutable($rootDir)->safeLoad();
}

/** @var Closure(array<string, mixed>=): PDO $dbFactory */
$dbFactory = require $rootDir . '/config/database.php';
$pdo = $dbFactory();

$apiKey = (string) ($_ENV['GEMINI_API_KEY'] ?? getenv('GEMINI_API_KEY') ?: '');
$webhookUrl = (string) ($_ENV['ALERT_WEBHOOK_URL'] ?? getenv('ALERT_WEBHOOK_URL') ?: '');
$sleepSeconds = (int) ($_ENV['WORKER_SLEEP_SECONDS'] ?? getenv('WORKER_SLEEP_SECONDS') ?: 3);

$service = new IncidentTriageService(
    fingerprinter: new ErrorFingerprinter(new LgpdPiiScrubber()),
    aiProvider: new GeminiDiagnosticProvider($apiKey),
    notifier: new WebhookAlertNotifier($webhookUrl),
    pdo: $pdo
);

echo "[php-log-sentinel] Starting background triage worker...\n";

while (true) {
    $processed = $service->processNextPendingIncident();
    if (!$processed) {
        sleep(max(1, $sleepSeconds));
    }
}
